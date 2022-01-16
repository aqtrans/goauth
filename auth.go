package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

type key int

const (
	// UserKey is used to store the *User in the context
	UserKey key = 1
	// MsgKey is used to store flash messages in the context
	MsgKey key = 2
	// ChkKey is used to store whether UserEnvMiddle has been hit in the context
	ChkKey key = 3
	// Buckets for boltDB
	authInfoBucketName     = "AuthInfo"
	hashKeyName            = "HashKey"
	blockKeyName           = "BlockKey"
	csrfKeyName            = "CSRFKey"
	userInfoBucketName     = "Users"
	registerKeysBucketName = "RegisterKeys"
	sessionIDsBucketName   = "SessionIDs"
	// Available roles for users
	RoleAdmin = "admin"
	RoleUser  = "user"
	// Names of cookies used
	cookieUser     = "user"
	cookieFlash    = "flash"
	cookieState    = "state"
	cookieRedirect = "redirect"
)

var (
	// LoginPath is the path to the login page, used to redirect protected pages
	//LoginPath = "/login"
	// SignupPath is the path to your signup page, used in the initial registration banner
	//SignupPath          = "/signup"
	errUserDoesNotExist = errors.New("User does not exist")
)

// State holds all required info to get authentication working in the app
type State struct {
	cookie *securecookie.SecureCookie
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

type Token struct {
	User           User
	ExpirationTime int
}

type Config struct {
	CookieSecure bool
	DbPath       string
	LoginPath    string
	SignupPath   string
	// Session lifetime in hours
	SessionLifetimeHours int
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

func (db *DB) getDB() *bolt.DB {
	var err error
	db.authdb, err = bolt.Open(db.path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalln("Error opening auth.DB in getDB()", err)
		return nil
	}
	return db.authdb
}

func (db *DB) releaseDB() {
	err := db.authdb.Close()
	if err != nil {
		log.Fatalln("Error closing auth.db in releaseDB()", err)
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

	db.dbInit()

	state := &State{
		cookie: securecookie.New(db.getAuthInfo()),
		DB:     *db,
		Cfg:    cfg,
	}

	return state
}

// RandBytes generates a random amount of bytes given a specified length
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		log.Fatalln("Error generating random bytes:", err)
		return nil
	}
	return b
}

func randString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes := randBytes(n)
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes)
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

// SetSession Takes a key, and a value to store inside a cookie
// Currently used for user info and related flash messages
func (state *State) setSession(key, val string, w http.ResponseWriter) {

	if encoded, err := state.cookie.Encode(key, val); err == nil {
		cookie := &http.Cookie{
			Name:     key,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, cookie)
	} else {
		log.Println("Error encoding cookie "+key+" value", err)
	}

}

// SetFlash sets a flash message inside a cookie, which, combined with the UserEnvMiddle
//   middleware, pushes the message into context and then template
func (state *State) SetFlash(msg string, w http.ResponseWriter) {
	state.setSession(cookieFlash, msg, w)
}

// Login generates a random session ID, throws that into the DB,
//   then sets that session ID into the cookie
func (state *State) Login(username string, w http.ResponseWriter) {
	user := state.DB.getUserInfo(username)
	sessionID := state.PutSessionID(user)
	state.setSession(cookieUser, sessionID, w)
}

func (state *State) readSession(key string, r *http.Request) (value string) {
	if cookie, err := r.Cookie(key); err == nil {
		err := state.cookie.Decode(key, cookie.Value, &value)
		if err != nil {
			log.Println("Error decoding cookie value for", key, err)
		}
	} else if err != http.ErrNoCookie {
		log.Println("Error reading cookie", key, err)
	}
	return value
}

// ClearSession currently only clearing the user value
// The CSRF token should always be around due to the login form and such
func (state *State) clearSession(key string, w http.ResponseWriter) {
	//state.SetSession(key, "", w, r)
	cookie := &http.Cookie{
		Name:     key,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Now().Add(-7 * 24 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

func (state *State) clearFlash(w http.ResponseWriter) {
	state.clearSession(cookieFlash, w)
}

// GetRedirect returns the URL from the redirect cookie
func (state *State) GetRedirect(r *http.Request, w http.ResponseWriter) (redirURL string) {
	redirURL = state.readSession(cookieRedirect, r)
	if redirURL != "" {
		state.clearSession(cookieRedirect, w)
	}
	return redirURL
}

// IsLoggedIn simply tries to fetch a session ID from the request
//   If more user info is required, use GetUser()
func (state *State) IsLoggedIn(r *http.Request) bool {
	sessionID := state.readSession(cookieUser, r)
	if sessionID == "" {
		//log.Println("No session ID in cookie")
		return false
	}
	user := state.GetSessionUser(sessionID)
	if user == nil {
		//log.Println("Invalid session ID given")
		return false
	}
	return true
}

// GetUserState returns a *User given a session ID cookie inside the request
func (state *State) GetUser(r *http.Request) *User {
	sessionID := state.readSession(cookieUser, r)
	if sessionID == "" {
		//log.Println("No session ID in cookie")
		return nil
	}

	//log.Println("GetUser session ID:", sessionID)

	user := state.GetSessionUser(sessionID)
	if user == nil {
		//log.Println("Invalid session ID given")
		return nil
	}
	return user
}

// GetFlash retrieves token from context
func (state *State) GetFlash(r *http.Request, w http.ResponseWriter) string {
	message := state.readSession(cookieFlash, r)
	if message != "" {
		state.clearFlash(w)
	}
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

	boltdb := db.getDB()
	defer db.releaseDB()

	// Grab given user's password from Bolt
	err := boltdb.View(func(tx *bolt.Tx) error {
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
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.View(func(tx *bolt.Tx) error {
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
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.View(func(tx *bolt.Tx) error {
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

func (db *DB) getAuthInfo() (hashkey, blockkey []byte) {
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(authInfoBucketName))
		v1 := b.Get([]byte(hashKeyName))
		v2 := b.Get([]byte(blockKeyName))
		hashkey = make([]byte, len(v1))
		blockkey = make([]byte, len(v2))
		copy(hashkey, v1)
		copy(blockkey, v2)
		return nil
	})
	if err != nil {
		log.Fatalln("Boltdb error in getAuthInfo():", err)
	}
	return hashkey, blockkey
}

// LogoutHandler clears the "user" cookie, logging the user out
func (state *State) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := state.readSession(cookieUser, r)
	state.DB.DeleteSessionID(sessionID)
	state.clearSession(cookieUser, w)
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

	boltdb := db.getDB()
	defer db.releaseDB()
	//var vb []byte
	adderr := boltdb.Batch(func(tx *bolt.Tx) error {
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
	boltdb := db.getDB()
	defer db.releaseDB()

	var userList []string
	err := boltdb.View(func(tx *bolt.Tx) error {
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
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.Update(func(tx *bolt.Tx) error {
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
	boltdb := db.getDB()
	defer db.releaseDB()

	// Update password only if user exists
	err := boltdb.Update(func(tx *bolt.Tx) error {
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
	state.setSession(cookieRedirect, r.URL.Path, w)
	// Redirect to the login page, should be at LoginPath
	http.Redirect(w, r, state.Cfg.LoginPath, http.StatusSeeOther)
}

// AuthMiddle is a middleware for HandlerFunc-specific stuff, to protect a given handler; users only access
func (state *State) AuthMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleHandler is a middleware to protect a given handler; users only access
func (state *State) AuthMiddleHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

// AuthAdminMiddle is a middleware to protect a given handler; admin only access
func (state *State) AuthAdminMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := state.GetUser(r)
		//if username == "" {
		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		//If user is not an Admin, just redirect to index
		if !user.IsAdmin() {
			//log.Println(user.Name + " attempting to access " + r.URL.Path)
			state.SetFlash("Sorry, you are not allowed to see that.", w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (db *DB) dbInit() {
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {

		_, err := tx.CreateBucketIfNotExists([]byte(userInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		infobucket, err := tx.CreateBucketIfNotExists([]byte(authInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		_, err = tx.CreateBucketIfNotExists([]byte(registerKeysBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		_, err = tx.CreateBucketIfNotExists([]byte(sessionIDsBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		hashKey := infobucket.Get([]byte(hashKeyName))
		if hashKey == nil {
			//log.Println("Throwing hashkey into auth.db.")
			// Generate a random hashKey
			hashKey := randBytes(64)

			err = infobucket.Put([]byte(hashKeyName), hashKey)
			if err != nil {
				log.Println("Error putting hashkey into auth.db:", err)
				return err
			}
		}

		blockKey := infobucket.Get([]byte(blockKeyName))
		if blockKey == nil {
			//log.Println("Throwing blockkey into auth.db.")
			// Generate a random blockKey
			blockKey := randBytes(32)

			err = infobucket.Put([]byte(blockKeyName), blockKey)
			if err != nil {
				log.Println("Error putting blockey into auth.db:", err)
				return err
			}
		}

		csrfKey := infobucket.Get([]byte(csrfKeyName))
		if csrfKey == nil {
			//log.Println("Throwing csrfKey into auth.db.")
			// Generate a random csrfKey
			csrfKey := randBytes(32)

			err = infobucket.Put([]byte(csrfKeyName), csrfKey)
			if err != nil {
				log.Println("Error throwing csrfKey into auth.db:", err)
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Fatalln("Error in dbInit():", err)
	}
}

// GenerateRegisterToken generates a token to register a user, and only a user
func (db *DB) GenerateRegisterToken(role string) string {
	switch role {
	case RoleAdmin, RoleUser:
	default:
		role = RoleUser
	}

	token := randString(12)
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		registerBucket, err := tx.CreateBucketIfNotExists([]byte(registerKeysBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		err = registerBucket.Put([]byte(token), []byte(role))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("GenerateRegisterToken() Boltdb error:", err)
	}
	return token
}

// ValidateRegisterToken validates that a given registration token is valid, exists inside the DB
func (db *DB) ValidateRegisterToken(token string) (bool, string) {
	boltDB := db.getDB()
	defer db.releaseDB()

	var userRole []byte

	invalidToken := errors.New("token does not exist")

	err := boltDB.View(func(tx *bolt.Tx) error {

		// Check if no users exist and token is blank. If so, bypass token check
		userbucket := tx.Bucket([]byte(userInfoBucketName))
		if userbucket.Stats().KeyN == 0 && token == "" {
			return nil
		}

		b := tx.Bucket([]byte(registerKeysBucketName))
		v := b.Get([]byte(token))
		if v == nil {
			return invalidToken
		}
		userRole = make([]byte, len(v))
		copy(userRole, v)
		return nil
	})

	if err == invalidToken {
		return false, ""
	}
	if err != nil && err != invalidToken {
		log.Fatalln("ValidateRegisterToken() Boltdb error:", err)
	}

	return true, string(userRole)
}

// DeleteRegisterToken deletes a registration token
func (db *DB) DeleteRegisterToken(token string) {
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		registerBucket, err := tx.CreateBucketIfNotExists([]byte(registerKeysBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		err = registerBucket.Delete([]byte(token))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("DeleteRegisterToken() Boltdb error:", err)
	}
}

func (db *DB) getCSRFKey() []byte {
	boltDB := db.getDB()
	defer db.releaseDB()

	var csrfKey []byte

	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(authInfoBucketName))
		v1 := b.Get([]byte(csrfKeyName))
		csrfKey = make([]byte, len(v1))
		copy(csrfKey, v1)
		return nil
	})
	if err != nil {
		log.Fatalln("getCSRFKey() Boltdb error:", err)
	}
	return csrfKey
}

// CSRFProtect wraps gorilla/csrf.Protect, only allowing toggling the Secure option
func (state *State) CSRFProtect(secure bool) func(http.Handler) http.Handler {
	return csrf.Protect(state.getCSRFKey(), csrf.Secure(secure), csrf.Path("/"))
}

// CSRFTemplateField wraps gorilla/csrf.TemplateField
func CSRFTemplateField(r *http.Request) template.HTML {
	return csrf.TemplateField(r)
}

// AnyUsers checks if there are any users in the DB
// This is useful in application initialization flows
func (state *State) AnyUsers() bool {
	boltDB := state.DB.getDB()
	defer state.DB.releaseDB()

	var anyUsers bool

	err := boltDB.View(func(tx *bolt.Tx) error {

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

// PutSessionID generates a session ID and ties the ID to the given User
func (state *State) PutSessionID(user *User) string {
	sessionID := randString(128)
	//log.Println("PutSessionID session ID for", user.Name, ":", sessionID)
	boltDB := state.DB.getDB()
	defer state.DB.releaseDB()

	// session lifetime, should be hours:
	lifetime := time.Duration(state.Cfg.SessionLifetimeHours) * time.Minute

	expirationTime := time.Now().Add(lifetime).Unix()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		sessionsBucket, err := tx.CreateBucketIfNotExists([]byte(sessionIDsBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		encoded, err := json.Marshal(Token{
			User:           *user,
			ExpirationTime: int(expirationTime),
		})
		if err != nil {
			return err
		}

		err = sessionsBucket.Put([]byte(sessionID), encoded)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("auth.PutSessionID() Boltdb error:", err)
	}
	return sessionID
}

// GetSessionUser checks for a given session ID in the DB and returns the associated User
func (db *DB) GetSessionUser(sessionID string) *User {
	boltDB := db.getDB()

	var tokenByte []byte
	noSessionID := errors.New("session ID does not exist")

	err := boltDB.View(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(sessionIDsBucketName))
		v := b.Get([]byte(sessionID))
		if v == nil {
			return noSessionID
		}
		tokenByte = make([]byte, len(v))
		copy(tokenByte, v)
		return nil
	})
	db.releaseDB()
	if err == noSessionID {
		return nil
	}
	if err != nil {
		log.Println("auth.GetSessionUser() Boltdb error:", err)
		return nil
	}

	// decode User
	var decodedToken Token
	err = json.Unmarshal(tokenByte, &decodedToken)
	if err != nil {
		log.Println("error decoding user:", err)
		return nil
	}

	if int(time.Now().Unix()) > decodedToken.ExpirationTime {
		//log.Println("token has expired! Deleting session ID")
		db.DeleteSessionID(sessionID)
	}

	return &decodedToken.User
}

// DeleteSessionID deletes a given session ID
func (db *DB) DeleteSessionID(sessionID string) {
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		sessionsBucket, err := tx.CreateBucketIfNotExists([]byte(sessionIDsBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		err = sessionsBucket.Delete([]byte(sessionID))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("auth.DeleteSessionID() Boltdb error:", err)
	}
}

// ListSessions lists all sessions in the DB
func (db *DB) ListSessions() ([]string, error) {
	boltdb := db.getDB()
	defer db.releaseDB()

	var sessionIDlist []string
	err := boltdb.View(func(tx *bolt.Tx) error {
		sessionBucket := tx.Bucket([]byte(sessionIDsBucketName))
		err := sessionBucket.ForEach(func(key, value []byte) error {
			//fmt.Printf("A %s is %s.\n", key, value)
			id := string(key)
			sessionIDlist = append(sessionIDlist, id)
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	return sessionIDlist, err
}

// GetSessionToken checks for a given session ID in the DB and returns the associated Token struct
func (db *DB) GetSessionToken(sessionID string) *Token {
	boltDB := db.getDB()

	var tokenByte []byte
	noSessionID := errors.New("session ID does not exist")

	err := boltDB.View(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(sessionIDsBucketName))
		v := b.Get([]byte(sessionID))
		if v == nil {
			return noSessionID
		}
		tokenByte = make([]byte, len(v))
		copy(tokenByte, v)
		return nil
	})
	db.releaseDB()
	if err == noSessionID {
		return nil
	}
	if err != nil {
		log.Println("auth.GetSessionUser() Boltdb error:", err)
		return nil
	}

	// decode Token
	var decodedToken Token
	err = json.Unmarshal(tokenByte, &decodedToken)
	if err != nil {
		log.Println("error decoding user:", err)
		return nil
	}

	return &decodedToken
}

func (db *DB) expireSessions() {
	boltdb := db.getDB()

	var expired [][]byte

	err := boltdb.View(func(tx *bolt.Tx) error {
		sessionBucket := tx.Bucket([]byte(sessionIDsBucketName))
		err := sessionBucket.ForEach(func(key, value []byte) error {
			var sessID Token
			err := json.Unmarshal(value, &sessID)
			if err != nil {
				log.Println("error decoding token json", err)
				return err
			}

			if int(time.Now().Unix()) > sessID.ExpirationTime {
				expired = append(expired, key)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})

	db.releaseDB()

	if err != nil {
		log.Println("expireSessions() boltdb error:", err)
		return
	}

	for _, token := range expired {
		//log.Println("deleting session", string(token))
		db.DeleteSessionID(string(token))
	}

}

func (s *State) StartCleanup() {
	stopCleanup := make(chan bool)
	ticker := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-ticker.C:
			//log.Println("expiring sessions...")
			s.DB.expireSessions()
		case <-stopCleanup:
			ticker.Stop()
			return
		}
	}
}

// Refresh tokens if they're near expiration, currently half the configured lifetime hours
func (s *State) RefreshTokens(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := s.readSession(cookieUser, r)
		if sessionID == "" {
			next.ServeHTTP(w, r)
			return
		}

		sessionToken := s.DB.GetSessionToken(sessionID)
		if sessionToken == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Refresh time should be half the configured lifetime hours
		refreshTime := time.Duration(s.Cfg.SessionLifetimeHours/2) * time.Hour

		if int(time.Now().Add(refreshTime).Unix()) > sessionToken.ExpirationTime {

			//log.Println("refreshing token", sessionID)

			newSessionID := s.PutSessionID(&sessionToken.User)

			s.setSession(cookieUser, newSessionID, w)

			// Serve before deleting from the database
			next.ServeHTTP(w, r)

			s.DB.DeleteSessionID(sessionID)
			return
		}

		next.ServeHTTP(w, r)
	})
}
