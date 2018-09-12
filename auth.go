package auth

/*
This package handles basic user authentication. It's design is based on https://github.com/xyproto/permissionbolt/,
initializing a 'state' that is passed around to hold the boltDB connection and secureCookie instance.

All cookie values (flash messages and usernames) are encrypted using gorilla/securecookie,
and the HashKey and BlockKey are generated randomly and then are permanent per-db.

The UserEnvMiddle middleware is required in order for the cookie info to be read into a context object.
This ensures the cookie is not repeatedly read every time the user info is needed.

Example for using auth.State in an app:
In main()
       // Bring up authState
       authState, _ = auth.NewAuthState("./data/auth.db")
Use authstate methods and handlers
*/

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
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
	// Available roles for users
	roleAdmin = "admin"
	roleUser  = "user"
	// Names of cookies used
	cookieUser     = "user"
	cookieFlash    = "flash"
	cookieState    = "state"
	cookieRedirect = "redirect"
)

var (
	// Debug variable can be set to true to have debugging info logged, otherwise silent
	Debug = false
	// LoginPath is the path to the login page, used to redirect protected pages
	LoginPath           = "/login"
	errUserDoesNotExist = errors.New("User does not exist")
)

// State holds all required info to get authentication working in the app
type State struct {
	cookie *securecookie.SecureCookie
	DB
}

// DB wraps a bolt.DB struct, so I can test and interact with the db from programs using the lib, while vendoring bolt in both places
type DB struct {
	authdb *bolt.DB
	path   string
}

type authInfo struct {
	hashKey  []byte
	blockKey []byte
}

// User is what is stored inside the context
type User struct {
	Name string
	Role string
}

// GetName is a helper function that sets the user blank if User is nil
// This allows use in Templates and the like
func (u *User) GetName() string {
	if u != nil {
		return u.Name
	}
	return ""
}

// If Debug is set to true, this logs to Stderr
func debugln(v ...interface{}) {
	if Debug {
		var buf bytes.Buffer
		debuglogger := log.New(&buf, "Debug: ", log.Ltime)
		debuglogger.SetOutput(os.Stderr)
		debuglogger.Print(v...)
	}
}

func check(err error) {
	if err != nil {
		pc, fn, line, ok := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		if ok && details != nil {
			log.Printf("[auth.error] in %s[%s:%d] %v", details.Name(), fn, line, err)
		}
	}
}

/*
func (state *State) getDB() *bolt.DB {
	var db *bolt.DB
	//log.Println(state.BoltDB.path)
	db, err := bolt.Open(state.BoltDB.path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		check(err)
		log.Fatalln(err)
		return nil
	}
	state.BoltDB.authdb = db
	return state.BoltDB.authdb
}

func (state *State) releaseDB() {
	err := state.BoltDB.authdb.Close()
	if err != nil {
		check(err)
		log.Fatalln(err)
	}
}
*/

func validRole(role string) bool {
	switch role {
	case roleAdmin, roleUser:
		return true
	default:
		return false
	}
}

func (db *DB) getDB() *bolt.DB {
	//var authDB *bolt.DB
	//log.Println(state.BoltDB.path)
	var err error
	db.authdb, err = bolt.Open(db.path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		check(err)
		log.Fatalln(err)
		return nil
	}
	return db.authdb
}

func (db *DB) releaseDB() {
	err := db.authdb.Close()
	if err != nil {
		check(err)
		log.Fatalln(err)
	}
}

// NewAuthState creates a new AuthState using the BoltDB backend, storing the boltDB connection and cookie info
func NewAuthState(path string) *State {
	var db *bolt.DB
	return NewAuthStateWithDB(&DB{authdb: db, path: path}, path)
}

// NewAuthStateWithDB takes an instance of a boltDB, and returns an AuthState using the BoltDB backend
func NewAuthStateWithDB(db *DB, path string) *State {
	if path == "" {
		log.Fatalln(errors.New("NewAuthStateWithDB: path is blank"))
	}

	db.dbInit()

	return &State{
		cookie: securecookie.New(db.getAuthInfo()),
		DB:     *db,
	}
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

// NewUserInContext takes a username and context, grabs the info for the user, and crams it into the given context
func (state *State) NewUserInContext(c context.Context, username string) context.Context {
	u := state.getUserInfo(username)
	return context.WithValue(c, UserKey, u)
}

func userFromContext(c context.Context) (*User, bool) {
	u, ok := c.Value(UserKey).(*User)
	return u, ok
}

// NewFlashInContext adds a given string as a flash message in the context
func NewFlashInContext(c context.Context, f string) context.Context {
	return context.WithValue(c, MsgKey, f)
}

func flashFromContext(c context.Context) (string, bool) {
	f, ok := c.Value(MsgKey).(string)
	return f, ok
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
		}
		http.SetCookie(w, cookie)
	} else {
		debugln("Error encoding cookie "+key+" value", err)
	}

}

// SetFlash sets a flash message inside a cookie, which, combined with the UserEnvMiddle
//   middleware, pushes the message into context and then template
func (state *State) SetFlash(msg string, w http.ResponseWriter) {
	state.setSession(cookieFlash, msg, w)
}

// SetUsername sets the username into the cookie
func (state *State) SetUsername(msg string, w http.ResponseWriter) {
	state.setSession(cookieUser, msg, w)
}

func (state *State) readSession(key string, w http.ResponseWriter, r *http.Request) (value string) {
	if cookie, err := r.Cookie(key); err == nil {
		err := state.cookie.Decode(key, cookie.Value, &value)
		if err != nil {
			debugln("Error decoding cookie value for", key, err)
			state.setSession(key, "", w)
		}
	} else if err != http.ErrNoCookie {
		debugln("Error reading cookie", key, err)
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

func (state *State) getUsernameFromCookie(r *http.Request, w http.ResponseWriter) (username string) {
	return state.readSession(cookieUser, w, r)
}

/*
func (state *State) getRedirectFromCookie(r *http.Request, w http.ResponseWriter) (redirURL string) {
	redirURL = state.readSession(cookieRedirect, w, r)
	if redirURL != "" {
		state.clearSession(cookieRedirect, w)
	}
	return redirURL
}
*/

func (state *State) getFlashFromCookie(r *http.Request, w http.ResponseWriter) (message string) {
	message = state.readSession(cookieFlash, w, r)
	if message != "" {
		state.clearFlash(w)
	}
	return message
}

/*
func (state *State) Userlist() ([]string, error) {
	return state.Backend.Userlist()
}

func (state *State) GetUserInfo(username string) *User {
	return state.Backend.GetUserInfo(username)
}
*/

/*
// GetUsername retrieves username, and admin bool from context
func GetUsername(c context.Context) (username, role string) {
	//defer timeTrack(time.Now(), "GetUsername")
	userC, ok := fromUserContext(c)
	if !ok {
		userC = &User{}
	}
	if ok {
		username = userC.Username
		role = userC.Role
	}

	return username, role
}
*/

// IsLoggedIn takes a context, tries to fetch user{} from it,
//  and if that succeeds, verifies the username fetched actually exists
func IsLoggedIn(c context.Context) bool {
	u := GetUserState(c)
	if u != nil {
		return true
	}
	return false
}

// GetUserState returns a *User from the context
// The *User should have been crammed in there by UserEnvMiddle
func GetUserState(c context.Context) *User {
	userC, ok := userFromContext(c)
	if ok {
		return userC
	}
	if !checkContext(c) {
		log.Println("ERR: UserEnvMiddle is not being used. It is necessary to setup the context.")
	}
	/*
		if !ok {
			debugln("No UserState in context.")
			pc, fn, line, ok := runtime.Caller(1)
			details := runtime.FuncForPC(pc)
			if ok && details != nil {
				log.Printf("[auth.error] in %s[%s:%d]", details.Name(), fn, line)
			}
		}
	*/
	return nil
}

// GetFlash retrieves token from context
func GetFlash(c context.Context) string {
	//defer timeTrack(time.Now(), "GetUsername")
	var flash string
	t, ok := flashFromContext(c)
	if !ok {
		flash = ""
	}
	if ok {
		flash = t
	}
	if !checkContext(c) {
		log.Println("ERR: UserEnvMiddle is not being used. It is necessary to setup the context.")
	}
	return flash
}

func newCheckInContext(c context.Context) context.Context {
	return context.WithValue(c, ChkKey, true)
}

func checkContext(c context.Context) bool {
	_, ok := c.Value(ChkKey).(bool)
	if ok {
		return true
	}
	return false
}

// IsAdmin checks if the given user is an admin
func (u *User) IsAdmin() bool {
	if u != nil {
		if u.Role == roleAdmin {
			return true
		}
	}

	return false
}

/*
// GetName returns the user's Name
func (u *User) GetName() string {
	if u != nil {
		return u.Name
	}
	return ""
}
*/

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
			// Incorrect password, malformed hash, etc.
			debugln("error verifying password for user", username, err)
			return err
		}
		return nil
	})

	if err != nil {
		// Incorrect password, malformed hash, etc.
		debugln("error verifying password for user", username, err)
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
		check(err)
		return false
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
		check(err)
		return nil
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
		check(err)
		return []byte(""), []byte("")
	}
	return hashkey, blockkey
}

// LogoutHandler clears the "user" cookie, logging the user out
func (state *State) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	state.clearSession(cookieUser, w)
	http.Redirect(w, r, r.Referer(), 302)
}

// NewUser creates a new user with a given plaintext username and password
func (db *DB) NewUser(username, password string) error {
	return db.newUser(username, password, roleUser)
}

// NewAdmin creates a new admin with a given plaintext username and password
func (db *DB) NewAdmin(username, password string) error {
	return db.newUser(username, password, roleAdmin)
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
		check(err)
		return err
	}

	boltdb := db.getDB()
	defer db.releaseDB()
	//var vb []byte
	adderr := boltdb.Batch(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte(userInfoBucketName)).Bucket([]byte(username))
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
		log.Println(username + " has been deleted")
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
		log.Println("User " + username + " has changed their password.")
		return nil
	})
	return err
}

// Redirect throws the r.URL.Path into a cookie named "redirect" and redirects to the login page
func Redirect(state *State, w http.ResponseWriter, r *http.Request) {
	// Save URL in cookie for later use
	state.setSession(cookieRedirect, r.URL.Path, w)
	// Redirect to the login page, should be at LoginPath
	http.Redirect(w, r, LoginPath, http.StatusSeeOther)
	return
}

// AuthMiddle is a middleware for HandlerFunc-specific stuff, to protect a given handler; users only access
func (state *State) AuthMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoggedIn(r.Context()) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleHandler is a middleware to protect a given handler; users only access
func (state *State) AuthMiddleHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoggedIn(r.Context()) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

// AuthAdminMiddle is a middleware to protect a given handler; admin only access
func (state *State) AuthAdminMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserState(r.Context())
		//if username == "" {
		if !IsLoggedIn(r.Context()) {
			Redirect(state, w, r)
		}
		//If user is not an Admin, just redirect to index
		if !user.IsAdmin() {
			log.Println(user.Name + " attempting to access " + r.URL.Path)
			state.SetFlash("Sorry, you are not allowed to see that.", w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

//UserEnvMiddle grabs username, role, and flash message from cookie,
// tosses it into the context for use in various other middlewares
// Note: It grabs simply the username, and stores a full User{} in the context
func (state *State) UserEnvMiddle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := state.getUsernameFromCookie(r, w)
		message := state.getFlashFromCookie(r, w)

		newc := r.Context()

		// Add a little flag to tell whether this middleware has been hit
		newc = newCheckInContext(newc)

		if username != "" {
			newc = state.NewUserInContext(newc, username)
		}

		if message != "" {
			newc = NewFlashInContext(newc, message)
		}

		next.ServeHTTP(w, r.WithContext(newc))
	})
}

/*
func (state *State) AuthCookieMiddle(next http.HandlerFunc) http.HandlerFunc {
	handler := func(w http.ResponseWriter, r *http.Request) {
		username := state.getUsernameFromCookie(r, w)
		if username == "" {
			http.Redirect(w, r, "http://"+r.Host+"/login"+"?url="+r.URL.String(), 302)
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(handler)
}
*/

func (db *DB) dbInit() {
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		registerKeyBucket, err := tx.CreateBucketIfNotExists([]byte(registerKeysBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		userBucket, err := tx.CreateBucketIfNotExists([]byte(userInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		// Check if no users exist. If so, generate a registration key
		if userBucket.Stats().KeyN == 0 {
			// Clear all existing register keys, likely due to failed app startups:
			err := registerKeyBucket.ForEach(func(key, value []byte) error {
				err := registerKeyBucket.Delete(key)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}

			log.Println("No users exist. Generating new register key to register a new admin user...")
			token := randString(12)
			err = registerKeyBucket.Put([]byte(token), []byte(roleAdmin))
			if err != nil {
				check(err)
				return err
			}
			log.Println("Use this register key on your signup page: " + token)
		}

		infobucket, err := tx.CreateBucketIfNotExists([]byte(authInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		hashKey := infobucket.Get([]byte(hashKeyName))
		if hashKey == nil {
			debugln("Throwing hashkey into auth.db.")
			// Generate a random hashKey
			hashKey := randBytes(64)

			err = infobucket.Put([]byte(hashKeyName), hashKey)
			if err != nil {
				check(err)
				return err
			}
		}

		blockKey := infobucket.Get([]byte(blockKeyName))
		if blockKey == nil {
			debugln("Throwing blockkey into auth.db.")
			// Generate a random blockKey
			blockKey := randBytes(32)

			err = infobucket.Put([]byte(blockKeyName), blockKey)
			if err != nil {
				check(err)
				return err
			}
		}

		csrfKey := infobucket.Get([]byte(csrfKeyName))
		if csrfKey == nil {
			debugln("Throwing csrfKey into auth.db.")
			// Generate a random csrfKey
			csrfKey := randBytes(32)

			err = infobucket.Put([]byte(csrfKeyName), csrfKey)
			if err != nil {
				check(err)
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Fatalln("Error in dbInit():", err)
	}
}

//UserSignupPostHandler only handles POST requests, using forms named "username", "password", and "register_key"
// Signing up users as necessary, inside the AuthConf
func (state *State) UserSignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")
		givenToken := r.FormValue("register_key")

		log.Println("Given token:", givenToken)
		isValid, userRole := state.ValidateRegisterToken(givenToken)

		if isValid {
			log.Println("Yay, registration token is valid!")
			// Delete the token so it cannot be reused
			state.DeleteRegisterToken(givenToken)

			err := state.newUser(username, password, userRole)
			if err != nil {
				check(err)
				state.SetFlash("Error adding user. Check logs.", w)
				http.Redirect(w, r, r.Referer(), http.StatusInternalServerError)
				return
			}
			state.SetFlash("Successfully added '"+username+"' user.", w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			state.SetFlash("Registration token is invalid.", w)
			http.Redirect(w, r, "/", http.StatusInternalServerError)
		}

	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}

/* THIS HANDLER STUFF SHOULD ALL BE TAKEN CARE OF IN THE APPS; LEAVING FOR EXAMPLES:

//AdminUserPassChangePostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *State) AdminUserPassChangePostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		// Hash password now so if it fails we catch it before touching Bolt
		//hash, err := passlib.Hash(password)
		hash, err := HashPassword([]byte(password))
		if err != nil {
			// couldn't hash password for some reason
			check(err)
			state.setSession(cookieFlash, "Error hashing password. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		err = state.UpdatePass(username, hash)
		if err != nil {
			check(err)
			state.setSession(cookieFlash, "Error updating password. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		state.setSession(cookieFlash, "Successfully changed '"+username+"' users password.", w)
		http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		return
	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}

//AdminUserDeletePostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *State) AdminUserDeletePostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		err := state.DeleteUser(username)
		if err != nil {
			check(err)
			state.setSession(cookieFlash, "Error deleting user. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		state.setSession(cookieFlash, "Successfully deleted '"+username+"'.", w)
		http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		return
	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}

//SignupPostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *State) SignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		err := state.NewUser(username, password)
		if err != nil {
			check(err)
			state.setSession(cookieFlash, "User registration failed.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
			return
		}
		state.setSession(cookieFlash, "Successful user registration.", w)
		http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		return
	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}
*/

//LoginPostHandler only handles POST requests, verifying forms named "username" and "password"
// Comparing values with those in BoltDB, and if it passes, stores the verified username in the cookie
// Note: As opposed to the other Handlers above, now commented out, this one deals with the redirects, so worth handling in the library.
func (state *State) LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		// Handle login POST request
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Login authentication
		if state.Auth(username, password) {
			state.SetUsername(username, w)
			state.SetFlash("User '"+username+"' successfully logged in.", w)
			// Check if we have a redirect URL in the cookie, if so redirect to it
			//redirURL := state.getRedirectFromCookie(r, w)
			redirURL := state.readSession(cookieRedirect, w, r)
			if redirURL != "" {
				log.Println("Redirecting to", redirURL)
				state.clearSession(cookieRedirect, w)
				http.Redirect(w, r, redirURL, http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/index", http.StatusSeeOther)
			return
		}
		state.SetFlash("User '"+username+"' failed to login. Please check your credentials and try again.", w)
		http.Redirect(w, r, LoginPath, http.StatusInternalServerError)
		return
	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}

// GenerateRegisterToken generates a token to register a user, and only a user
func (db *DB) GenerateRegisterToken(role string) string {
	switch role {
	case roleAdmin, roleUser:
	default:
		log.Println("GenerateRegisterToken role is invalid, setting to user: " + role)
		role = roleUser
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
			check(err)
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("Error putting register token into DB:", err)
	}
	return token
}

// ValidateRegisterToken validates that a given registration token is valid, exists inside the DB
func (db *DB) ValidateRegisterToken(token string) (bool, string) {
	boltDB := db.getDB()
	defer db.releaseDB()

	var userRole []byte

	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(registerKeysBucketName))
		v := b.Get([]byte(token))
		if v == nil {
			return errors.New("token does not exist")
		}
		userRole = make([]byte, len(v))
		log.Println("Role:", string(v))
		copy(userRole, v)
		return nil
	})
	if err != nil {
		log.Println(err)
		return false, ""
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
			check(err)
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("Error putting register token into DB:", err)
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
		log.Println("ERROR: CSRF token not found in authdb. CSRF protection will not work.")
		return []byte("")
	}
	return csrfKey
}

// CSRFProtect wraps gorilla/csrf.Protect, only allowing toggling the Secure option
func (state *State) CSRFProtect(secure bool) func(http.Handler) http.Handler {
	return csrf.Protect(state.getCSRFKey(), csrf.Secure(secure))
}

// CSRFTemplateField wraps gorilla/csrf.TemplateField
func CSRFTemplateField(r *http.Request) template.HTML {
	return csrf.TemplateField(r)
}

// NewUserToken is a convenient handler that generates and provides a new user registration token
func (state *State) NewUserToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Write([]byte("User token:" + state.GenerateRegisterToken("user")))
		return
	default:
	}
}
