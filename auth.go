package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	log "github.com/sirupsen/logrus"
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
	roleAdmin = "admin"
	roleUser  = "user"
	// Names of cookies used
	cookieUser     = "user"
	cookieFlash    = "flash"
	cookieState    = "state"
	cookieRedirect = "redirect"
)

var (
	// LoginPath is the path to the login page, used to redirect protected pages
	LoginPath = "/login"
	// SignupPath is the path to your signup page, used in the initial registration banner
	SignupPath          = "/signup"
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

func validRole(role string) bool {
	switch role {
	case roleAdmin, roleUser:
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

// SetSession Takes a key, and a value to store inside a cookie
// Currently used for user info and related flash messages
func (state *State) setSession(key, val string, w http.ResponseWriter) {

	if encoded, err := state.cookie.Encode(key, val); err == nil {
		cookie := &http.Cookie{
			Name:     key,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteDefaultMode,
		}
		http.SetCookie(w, cookie)
	} else {
		log.Debugln("Error encoding cookie "+key+" value", err)
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
	sessionID := state.DB.PutSessionID(username)
	state.setSession(cookieUser, sessionID, w)
}

func (state *State) readSession(key string, r *http.Request) (value string) {
	if cookie, err := r.Cookie(key); err == nil {
		err := state.cookie.Decode(key, cookie.Value, &value)
		if err != nil {
			log.Debugln("Error decoding cookie value for", key, err)
		}
	} else if err != http.ErrNoCookie {
		log.Debugln("Error reading cookie", key, err)
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
	sessionID := state.readSession(cookieUser, r)
	// If there is a session cookie, get the associated user from the DB
	if sessionID != "" {
		username = state.DB.GetSessionID(sessionID)
	}
	return username
}

// GetRedirect returns the URL from the redirect cookie
func (state *State) GetRedirect(r *http.Request, w http.ResponseWriter) (redirURL string) {
	redirURL = state.readSession(cookieRedirect, r)
	if redirURL != "" {
		state.clearSession(cookieRedirect, w)
	}
	return redirURL
}

func (state *State) getFlashFromCookie(r *http.Request, w http.ResponseWriter) (message string) {
	message = state.readSession(cookieFlash, r)
	if message != "" {
		state.clearFlash(w)
	}
	return message
}

// IsLoggedIn takes a context, tries to fetch user{} from it,
//  and if that succeeds, verifies the username fetched actually exists
func (state *State) IsLoggedIn(r *http.Request) bool {
	u := state.GetUserState(r)

	return u != nil
}

// GetUserState returns a *User from the context
// The *User should have been crammed in there by UserEnvMiddle
func (state *State) GetUserState(r *http.Request) *User {
	sessionID := state.readSession(cookieUser, r)
	if sessionID == "" {
		//log.Println("No session ID in cookie")
		return nil
	}
	username := state.DB.GetSessionID(sessionID)
	if username == "" {
		log.Println("Invalid session ID given")
		return nil
	}
	user := state.DB.getUserInfo(username)
	if user == nil {
		log.Println("User{} is blank for user:", username)
		return nil
	}
	return user
}

// GetFlash retrieves token from context
func (state *State) GetFlash(r *http.Request, w http.ResponseWriter) string {
	return state.getFlashFromCookie(r, w)
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
		log.Debugln("error verifying password for user ", username, err)
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
		log.Debugln("Error hasing password:", err)
		return err
	}

	boltdb := db.getDB()
	defer db.releaseDB()
	//var vb []byte
	adderr := boltdb.Batch(func(tx *bolt.Tx) error {
		masteruserbucket := tx.Bucket([]byte(userInfoBucketName))

		// Check if no users exist. If so, make this one an admin
		if masteruserbucket.Stats().KeyN == 0 {
			role = roleAdmin
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
		log.Debugln(username + " has been deleted")
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
		log.Debugln("User " + username + " has changed their password.")
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
		user := state.GetUserState(r)
		//if username == "" {
		if !state.IsLoggedIn(r) {
			Redirect(state, w, r)
		}
		//If user is not an Admin, just redirect to index
		if !user.IsAdmin() {
			log.Debugln(user.Name + " attempting to access " + r.URL.Path)
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
			log.Debugln("Throwing hashkey into auth.db.")
			// Generate a random hashKey
			hashKey := randBytes(64)

			err = infobucket.Put([]byte(hashKeyName), hashKey)
			if err != nil {
				log.Debugln("Error putting hashkey into auth.db:", err)
				return err
			}
		}

		blockKey := infobucket.Get([]byte(blockKeyName))
		if blockKey == nil {
			log.Debugln("Throwing blockkey into auth.db.")
			// Generate a random blockKey
			blockKey := randBytes(32)

			err = infobucket.Put([]byte(blockKeyName), blockKey)
			if err != nil {
				log.Debugln("Error putting blockey into auth.db:", err)
				return err
			}
		}

		csrfKey := infobucket.Get([]byte(csrfKeyName))
		if csrfKey == nil {
			log.Debugln("Throwing csrfKey into auth.db.")
			// Generate a random csrfKey
			csrfKey := randBytes(32)

			err = infobucket.Put([]byte(csrfKeyName), csrfKey)
			if err != nil {
				log.Debugln("Error throwing csrfKey into auth.db:", err)
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Fatalln("Error in dbInit():", err)
	}
}

//UserSignupPostHandler only handles POST requests, using forms named "username", "password"
// Signing up users as necessary, inside the AuthConf
func (state *State) UserSignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")

		err := state.NewUser(username, password)
		if err != nil {
			log.Debugln("Error adding user:", err)
			state.SetFlash("Error adding user. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusInternalServerError)
			return
		}

		// Login the recently added user
		if state.Auth(username, password) {
			state.Login(username, w)
		}

		state.SetFlash("Successfully added '"+username+"' user.", w)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}

//UserSignupTokenPostHandler only handles POST requests, using forms named "username", "password", and "register_key"
//	This is an alternative to UserSignupPostHandler, adding registration token support
//  That token is verified against the DB before registration
func (state *State) UserSignupTokenPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")
		givenToken := r.FormValue("register_key")

		isValid, userRole := state.ValidateRegisterToken(givenToken)

		if isValid {

			// Delete the token so it cannot be reused if the token is not blank
			// The first user can signup without a token and is granted admin rights
			if givenToken != "" {
				state.DeleteRegisterToken(givenToken)
			} else {
				userRole = roleAdmin
			}

			err := state.newUser(username, password, userRole)
			if err != nil {
				log.Debugln("Error adding user:", err)
				state.SetFlash("Error adding user. Check logs.", w)
				http.Redirect(w, r, r.Referer(), http.StatusInternalServerError)
				return
			}

			// Login the recently added user
			if state.Auth(username, password) {
				state.Login(username, w)
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
			state.Login(username, w)
			state.SetFlash("User '"+username+"' successfully logged in.", w)
			// Check if we have a redirect URL in the cookie, if so redirect to it
			redirURL := state.readSession(cookieRedirect, r)
			if redirURL != "" {
				state.clearSession(cookieRedirect, w)
				http.Redirect(w, r, redirURL, http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		state.SetFlash("User '"+username+"' failed to login. Please check your credentials and try again.", w)
		http.Redirect(w, r, LoginPath, http.StatusSeeOther)
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

// PutSessionID generates a session ID and ties the ID to the given user
func (db *DB) PutSessionID(username string) string {
	sessionID := randString(128)
	log.Debugln("PutSessionID session ID for", username, ":", sessionID)
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		sessionsBucket, err := tx.CreateBucketIfNotExists([]byte(sessionIDsBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		err = sessionsBucket.Put([]byte(sessionID), []byte(username))
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

// GetSessionID checks for a given session ID in the DB and returns the associated username
func (db *DB) GetSessionID(sessionID string) string {
	boltDB := db.getDB()
	defer db.releaseDB()

	var usernameByte []byte
	noSessionID := errors.New("session ID does not exist")

	err := boltDB.View(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(sessionIDsBucketName))
		v := b.Get([]byte(sessionID))
		if v == nil {
			return noSessionID
		}
		usernameByte = make([]byte, len(v))
		copy(usernameByte, v)
		return nil
	})
	if err == noSessionID {
		return ""
	}
	if err != nil {
		log.Fatalln("auth.GetSessionID() Boltdb error:", err)
	}

	return string(usernameByte)
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
