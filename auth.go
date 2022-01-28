package auth

import (
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/alexedwards/scs/boltstore"
	"github.com/alexedwards/scs/v2"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

const (
	// Buckets for boltDB
	userInfoBucketName = "Users"
	// Available roles for users
	RoleAdmin = "admin"
	RoleUser  = "user"
	// Names of cookies used
	cookieUser     = "user"
	cookieFlash    = "flash"
	cookieRedirect = "redirect"
)

var (
	errUserDoesNotExist = errors.New("User does not exist")
)

// State holds all required info to get authentication working in the app
type State struct {
	sm *scs.SessionManager
	DB
	Cfg Config
}

// DB wraps a bolt.DB struct, so I can test and interact with the db from programs using the lib, while vendoring bolt in both places
type DB struct {
	authdb *bolt.DB
	path   string
}

// User is what is stored inside the context
type User struct {
	Name string
	Role string
}

type Config struct {
	CookieSecure bool
	DbPath       string
	LoginPath    string
	SignupPath   string
	// Session lifetime in hours
	SessionLifetimeHours int
}

func init() {
	gob.Register(User{})
}

// GetName is a helper function that sets the user blank if User is nil
// This allows use in Templates and the like
func (u *User) GetName() string {
	if u != nil {
		return u.Name
	}
	return ""
}

func validRole(role string) bool {
	switch role {
	case RoleAdmin, RoleUser:
		return true
	default:
		return false
	}
}

func (state *State) CloseDB() {

	err := state.DB.authdb.Close()
	if err != nil {
		log.Fatalln("Error closing auth.db in CloseDB()", err)
	}

}

// NewAuthState creates a new AuthState using the BoltDB backend, storing the boltDB connection and cookie info
func NewAuthState(cfg Config) *State {
	var db *bolt.DB
	return NewAuthStateWithDB(&DB{authdb: db, path: cfg.DbPath}, cfg)
}

// NewAuthStateWithDB takes an instance of a boltDB, and returns an AuthState using the BoltDB backend
func NewAuthStateWithDB(db *DB, cfg Config) *State {
	if cfg.DbPath == "" {
		log.Fatalln(errors.New("NewAuthStateWithDB: path is blank"))
	}

	if cfg.LoginPath == "" {
		cfg.LoginPath = "/login"
	}

	if cfg.SignupPath == "" {
		cfg.SignupPath = "/signup"
	}

	if cfg.SessionLifetimeHours == 0 {
		cfg.SessionLifetimeHours = 24
	}

	var err error
	db.authdb, err = bolt.Open(db.path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalln("Error opening auth.DB in getDB()", err)
		return nil
	}

	db.dbInit()

	// scs
	sessionManager := scs.New()
	sessionManager.Lifetime = time.Duration(cfg.SessionLifetimeHours) * time.Hour
	sessionManager.Store = boltstore.New(db.authdb)
	sessionManager.Cookie.Secure = cfg.CookieSecure

	state := &State{
		sm:  sessionManager,
		DB:  *db,
		Cfg: cfg,
	}

	return state
}

// Wrapping scs middleware
func (s *State) LoadAndSave(next http.Handler) http.Handler {
	return s.sm.LoadAndSave(next)
}

// HashPassword generates a bcrypt hash of the password using work factor 14.
func HashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
}

// CheckPasswordHash securely compares a bcrypt hashed password with its possible
// plaintext equivalent.  Returns nil on success, or an error on failure.
func CheckPasswordHash(hash, password []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}

// SetFlash sets a flash message inside a cookie, which, combined with the UserEnvMiddle
//   middleware, pushes the message into context and then template
func (state *State) SetFlash(msg string, r *http.Request) {
	state.sm.Put(r.Context(), cookieFlash, msg)
}

// Login generates a random session ID, throws that into the DB,
//   then sets that session ID into the cookie
func (state *State) Login(username string, r *http.Request) {
	user := state.DB.getUserInfo(username)
	err := state.sm.RenewToken(r.Context())
	if err != nil {
		log.Println("error renewing token:", err)
		return
	}
	state.sm.Put(r.Context(), cookieUser, user)
}

// GetRedirect returns the URL from the redirect cookie
func (state *State) GetRedirect(r *http.Request) string {
	redirURL := state.sm.PopString(r.Context(), cookieRedirect)
	return redirURL
}

// IsLoggedIn simply tries to fetch a session ID from the request
//   If more user info is required, use GetUser()
func (state *State) IsLoggedIn(r *http.Request) bool {
	return state.sm.Exists(r.Context(), cookieUser)
}

// GetUserState returns a *User given a session ID cookie inside the request
func (state *State) GetUser(r *http.Request) *User {

	user, ok := state.sm.Get(r.Context(), cookieUser).(User)
	if !ok {
		//log.Println("Invalid session ID given")
		return nil
	}

	return &user
}

// GetFlash retrieves flash message
func (state *State) GetFlash(r *http.Request) string {
	message := state.sm.PopString(r.Context(), cookieFlash)
	return message
}

// IsAdmin checks if the given user is an admin
func (u *User) IsAdmin() bool {
	if u != nil {
		if u.Role == RoleAdmin {
			return true
		}
	}

	return false
}

// IsValid checks if the given User is valid
func (u *User) IsValid() bool {
	return u != nil
}

// Auth authenticates a given username and password
func (db *DB) Auth(username, password string) bool {

	// Grab given user's password from Bolt
	err := db.authdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName)).Bucket([]byte(username))
		if b == nil {
			return errUserDoesNotExist
		}
		v := b.Get([]byte("password"))

		err := CheckPasswordHash(v, []byte(password))
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		// Incorrect password, malformed hash, etc.
		// Should not be a fatal error
		//log.Println("error verifying password for user ", username, err)
		return false
	}
	// TODO: Should look into fleshing this out
	return true
}

// DoesUserExist checks if user actually exists in the DB
func (db *DB) DoesUserExist(username string) bool {

	err := db.authdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName)).Bucket([]byte(username))
		if b == nil {
			return errUserDoesNotExist
		}
		return nil
	})
	if err == nil {
		return true
	}
	if err != nil && err != errUserDoesNotExist {
		log.Fatalln("Boltdb error in DoesUserExist():", err)
	}
	return false
}

// GetUserInfo gets a *User from the DB
func (db *DB) getUserInfo(username string) *User {
	var u User

	err := db.authdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName)).Bucket([]byte(username))
		if b == nil {
			return errUserDoesNotExist
		}
		v := b.Get([]byte("role"))
		u.Role = string(v)
		u.Name = username

		return nil
	})
	if err != nil {
		log.Fatalln("Boltdb error in getUserInfo():", err)
	}
	return &u

}

// LogoutHandler clears the "user" cookie, logging the user out
func (state *State) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	state.sm.Remove(r.Context(), cookieUser)
	http.Redirect(w, r, r.Referer(), http.StatusFound)
}

// NewUser creates a new user with a given plaintext username and password
func (db *DB) NewUser(username, password string) error {
	return db.newUser(username, password, RoleUser)
}

// NewAdmin creates a new admin with a given plaintext username and password
func (db *DB) NewAdmin(username, password string) error {
	return db.newUser(username, password, RoleAdmin)
}

// newUser is a dedicated function to create new users, taking plaintext username, password, and role
//  Hashing done in this function, no need to do it before
func (db *DB) newUser(username, password, role string) error {

	// Check that the given role is valid before even opening the DB
	if !validRole(role) {
		return errors.New("NewUser role is invalid: " + role)
	}

	// Same for hasing; Hash password now so if it fails we catch it before touching Bolt
	hash, err := HashPassword([]byte(password))
	if err != nil {
		// couldn't hash password for some reason
		log.Println("Error hasing password:", err)
		return err
	}

	//var vb []byte
	adderr := db.authdb.Batch(func(tx *bolt.Tx) error {
		masteruserbucket := tx.Bucket([]byte(userInfoBucketName))

		// Check if no users exist. If so, make this one an admin
		if masteruserbucket.Stats().KeyN == 0 {
			role = RoleAdmin
		}

		userbucket := masteruserbucket.Bucket([]byte(username))
		// userbucket should be nil if user doesn't exist
		if userbucket != nil {
			return errors.New("User already exists")
		}

		userbucket, err = tx.Bucket([]byte(userInfoBucketName)).CreateBucket([]byte(username))
		if err != nil {
			return err
		}

		err = userbucket.Put([]byte("password"), hash)
		if err != nil {
			return err
		}

		err = userbucket.Put([]byte("role"), []byte(role))
		if err != nil {
			return err
		}

		return nil
	})

	if adderr != nil {
		return adderr
	}

	return nil
}

// Userlist lists all users in the DB
func (db *DB) Userlist() ([]string, error) {

	var userList []string
	err := db.authdb.View(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte(userInfoBucketName))
		err := userbucket.ForEach(func(key, value []byte) error {
			//fmt.Printf("A %s is %s.\n", key, value)
			user := string(key)
			userList = append(userList, user)
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	return userList, err
}

// DeleteUser deletes a given user from the DB
func (db *DB) DeleteUser(username string) error {

	err := db.authdb.Update(func(tx *bolt.Tx) error {
		//log.Println(username + " has been deleted")
		return tx.Bucket([]byte(userInfoBucketName)).DeleteBucket([]byte(username))
	})
	if err != nil {
		return err
	}
	return err
}

// UpdatePass updates a given user's password to the given hash
// Password hashing must be done by the caller
func (db *DB) UpdatePass(username string, hash []byte) error {

	// Update password only if user exists
	err := db.authdb.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte(userInfoBucketName)).Bucket([]byte(username))
		// userbucket should be nil if user doesn't exist
		if userbucket == nil {
			return errUserDoesNotExist
		}

		err := userbucket.Put([]byte("password"), hash)
		if err != nil {
			return err
		}
		//log.Println("User " + username + " has changed their password.")
		return nil
	})
	return err
}

// Redirect throws the r.URL.Path into a cookie named "redirect" and redirects to the login page
func Redirect(state *State, w http.ResponseWriter, r *http.Request) {
	// Save URL in cookie for later use
	state.sm.Put(r.Context(), cookieRedirect, r.URL.Path)
	// Redirect to the login page, should be at LoginPath
	http.Redirect(w, r, state.Cfg.LoginPath, http.StatusSeeOther)
}

// UsersOnly is a middleware for HandlerFunc-specific stuff, to protect a given handler; users only access
func (state *State) UsersOnly(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

// UsersOnlyH is a middleware to protect a given handler; users only access
func (state *State) UsersOnlyH(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

// AdminsOnly is a middleware to protect a given handler; admin only access
func (state *State) AdminsOnly(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := state.GetUser(r)
		//if username == "" {
		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		//If user is not an Admin, just redirect to index
		if !user.IsAdmin() {
			//log.Println(user.Name + " attempting to access " + r.URL.Path)
			state.SetFlash("Sorry, you are not allowed to see that.", r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AdminsOnlyH is a middleware to protect a given handler; admin only access
func (state *State) AdminsOnlyH(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := state.GetUser(r)
		//if username == "" {
		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		//If user is not an Admin, just redirect to index
		if !user.IsAdmin() {
			//log.Println(user.Name + " attempting to access " + r.URL.Path)
			state.SetFlash("Sorry, you are not allowed to see that.", r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (db *DB) dbInit() {

	err := db.authdb.Update(func(tx *bolt.Tx) error {

		_, err := tx.CreateBucketIfNotExists([]byte(userInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		return nil
	})
	if err != nil {
		log.Fatalln("Error in dbInit():", err)
	}
}

// AnyUsers checks if there are any users in the DB
// This is useful in application initialization flows
func (state *State) AnyUsers() bool {

	var anyUsers bool

	err := state.DB.authdb.View(func(tx *bolt.Tx) error {

		// Check if no users exist and token is blank. If so, bypass token check
		userbucket := tx.Bucket([]byte(userInfoBucketName))
		if userbucket.Stats().KeyN == 0 {
			anyUsers = false
		} else {
			anyUsers = true
		}

		return nil
	})
	if err != nil {
		log.Fatalln("auth.AnyUsers() Boltdb error:", err)
	}

	return anyUsers
}
