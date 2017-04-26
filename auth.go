package auth

// 03/12/2017 - Massive revamp, using a 'state' instead of variables
//    - Based on https://github.com/xyproto/permissionbolt/
// **Currently using plain "context" package included in Go 1.7, so not backwards compatible**

//Auth functions
// Currently handles the following:
//  User Auth:
//   - User sign-up, stored in a Boltdb named auth.db
//   - User authentication against Boltdb
//       - Cookie-powered
//       - With go1.7/context to help pass around the user info
//   - AdminUser specified is made an Admin, so only one admin
//   - Boltdb powered, using a Users buckets
//   - Success/failure is delivered via a redirect and a flash message
//   -

/* Example for using AuthState in an app:
In main()
       // Bring up authState
       var err error
       authState, err = auth.NewAuthState("./data/auth.db", "admin_username")
       check(err)
Use authstate methods and handlers
*/

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

type key int

const UserKey key = 1
const MsgKey key = 2

var AuthInfoBucketName = []byte("AuthInfo")
var HashKeyName = []byte("HashKey")
var BlockKeyName = []byte("BlockKey")
var UserInfoBucketName = []byte("Users")

var UserDoesntExist = errors.New("User does not exist")

// Debug variable can be set to true to have debugging info logged, otherwise silent
var Debug = false

// AuthState holds all required info to get authentication working in the app
type AuthState struct {
	defaultUser string
	BoltDB      *DB
	cookie      *securecookie.SecureCookie
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

type User struct {
	Username string
	IsAdmin  bool
}

type Flash struct {
	Msg string
}

// If Debug is set to true, this logs to Stderr
func debugln(v ...interface{}) {
	if Debug {
		var buf bytes.Buffer
		debuglogger := log.New(&buf, "Debug: ", log.Ltime)
		debuglogger.SetOutput(os.Stderr)
		debuglogger.Print(v)
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

func (state *AuthState) getDB() (*bolt.DB, error) {
	var db *bolt.DB
	//log.Println(state.BoltDB.path)
	db, err := bolt.Open(state.BoltDB.path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		check(err)
		return nil, err
	}
	state.BoltDB.authdb = db
	return state.BoltDB.authdb, nil
}

func (state *AuthState) releaseDB() {
	state.BoltDB.authdb.Close()
}

// NewAuthState creates a new AuthState, storing the boltDB connection, cookie info, and defaultUsername (which is also the admin user)
func NewAuthState(path, user string) (*AuthState, error) {
	var db *bolt.DB

	return NewAuthStateWithDB(&DB{authdb: db, path: path}, path, user)
}

// NewAuthStateWithDB takes an instance of a boltDB, and returns an AuthState
func NewAuthStateWithDB(db *DB, path, user string) (*AuthState, error) {
	state := new(AuthState)
	state.BoltDB = db
	state.BoltDB.path = path
	// Important to set defaultUser now, before dbInit()
	state.defaultUser = user

	err := state.dbInit()
	check(err)

	hash, block := state.getAuthInfo()
	state.cookie = securecookie.New(hash, block)

	return state, nil
}

// RandBytes generates a random amount of bytes given a specified length
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		check(err)
		return nil
	}
	return b
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

func newUserContext(c context.Context, u *User) context.Context {
	return context.WithValue(c, UserKey, u)
}

func fromUserContext(c context.Context) (*User, bool) {
	u, ok := c.Value(UserKey).(*User)
	return u, ok
}

func newFlashContext(c context.Context, f *Flash) context.Context {
	return context.WithValue(c, MsgKey, f)
}

func fromFlashContext(c context.Context) (*Flash, bool) {
	f, ok := c.Value(MsgKey).(*Flash)
	return f, ok
}

// SetSession Takes a key, and a value to store inside a cookie
// Currently used for user info and related flash messages
func (state *AuthState) SetSession(key, val string, w http.ResponseWriter, r *http.Request) {

	if encoded, err := state.cookie.Encode(key, val); err == nil {
		cookie := &http.Cookie{
			Name:     key,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}

}

func (state *AuthState) ReadSession(key string, w http.ResponseWriter, r *http.Request) (value string) {
	if cookie, err := r.Cookie(key); err == nil {
		err := state.cookie.Decode(key, cookie.Value, &value)
		if err != nil {
			debugln("Error decoding cookie " + key + " value")
			state.SetSession(key, "", w, r)
		}
	}
	return value
}

// SetFlash sets a flash message inside a cookie, which, combined with the UserEnvMiddle
//   middleware, pushes the message into context and then template
func (state *AuthState) SetFlash(msg string, w http.ResponseWriter, r *http.Request) {
	state.SetSession("flash", msg, w, r)
}

// ClearSession currently only clearing the user value
// The CSRF token should always be around due to the login form and such
func (state *AuthState) ClearSession(key string, w http.ResponseWriter, r *http.Request) {
	state.SetSession(key, "", w, r)
}

func (state *AuthState) clearFlash(w http.ResponseWriter, r *http.Request) {
	state.ClearSession("flash", w, r)
}

func (state *AuthState) getUsernameFromCookie(r *http.Request, w http.ResponseWriter) (username string) {
	return state.ReadSession("user", w, r)
}

func (state *AuthState) getFlashFromCookie(r *http.Request, w http.ResponseWriter) (message string) {
	message = state.ReadSession("flash", w, r)
	if message != "" {
		state.clearFlash(w, r)
	}
	return message
}

// GetUsername retrieves username, and admin bool from context
func GetUsername(c context.Context) (username string, isAdmin bool) {
	//defer timeTrack(time.Now(), "GetUsername")
	userC, ok := fromUserContext(c)
	if !ok {
		userC = &User{}
	}
	if ok {
		username = userC.Username
		isAdmin = userC.IsAdmin
	}

	return username, isAdmin
}

// IsLoggedIn takes a context, tries to fetch user{} from it,
//  and if that succeeds, verifies the username fetched actually exists
func IsLoggedIn(c context.Context) bool {
	userC, ok := fromUserContext(c)
	if ok {
		// If username is in a context, and that user exists, return true
		if userC.Username != "" {
			return true
		}
	}
	if !ok {
		debugln("Error IsLoggedIn not OK")
	}
	return false
}

func GetUserState(c context.Context) (user *User) {
	userC, ok := fromUserContext(c)
	if ok {
		// If username is in a context, and that user exists, return that User info
		if userC.Username != "" {
			user = userC
		}
	}
	if !ok {
		debugln("No UserState in context.")
	}
	return user
}

// GetFlash retrieves token from context
func GetFlash(c context.Context) string {
	//defer timeTrack(time.Now(), "GetUsername")
	var flash string
	t, ok := fromFlashContext(c)
	if !ok {
		flash = ""
	}
	if ok {
		flash = t.Msg
	}
	return flash
}

func (state *AuthState) BoltAuth(username, password string) bool {

	// Catch non-existent users before wasting CPU cycles checking hashes
	if !state.doesUserExist(username) {
		log.Println(username + " does not exist but trying to login.")
		return false
	}

	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return false
	}
	defer state.releaseDB()

	// Grab given user's password from Bolt
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UserInfoBucketName)
		v := b.Get([]byte(username))
		if v == nil {
			return UserDoesntExist
		}
		err = CheckPasswordHash(v, []byte(password))
		if err != nil {
			// Incorrect password, malformed hash, etc.
			debugln("error verifying password for user " + username)
			return err
		}
		return nil
	})

	if err != nil {
		// Incorrect password, malformed hash, etc.
		//debugln("error verifying password for user " + username)
		return false
	}
	// TODO: Should look into fleshing this out
	return true
}

// Check if user actually exists
func (state *AuthState) doesUserExist(username string) bool {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return false
	}
	defer state.releaseDB()

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UserInfoBucketName)
		v := b.Get([]byte(username))
		if v == nil {
			return UserDoesntExist
		}
		return nil
	})
	if err == nil {
		return true
	}
	if err != nil && err != UserDoesntExist {
		check(err)
		return false
	}
	return false
}

func (state *AuthState) getAuthInfo() (hashkey, blockkey []byte) {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return []byte(""), []byte("")
	}
	defer state.releaseDB()

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(AuthInfoBucketName)
		v1 := b.Get(HashKeyName)
		v2 := b.Get(BlockKeyName)
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

func (state *AuthState) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	state.ClearSession("user", w, r)
	http.Redirect(w, r, r.Referer(), 302)
}

// Redirect back to given page after successful login or signup.
func postRedir(w http.ResponseWriter, r *http.Request, name string) {
	http.Redirect(w, r, name, http.StatusSeeOther)
}

// Dedicated function to create new users, taking plaintext username, password, and role
//  Hashing done in this function, no need to do it before
func (state *AuthState) NewUser(username, password string) error {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return err
	}
	defer state.releaseDB()

	// Hash password now so if it fails we catch it before touching Bolt
	//hash, err := passlib.Hash(password)
	hash, err := HashPassword([]byte(password))
	if err != nil {
		// couldn't hash password for some reason
		check(err)
		return err
	}

	// If no existing user, store username and hash
	viewerr := db.View(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket(UserInfoBucketName)
		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser != nil {
			return errors.New("User already exists")
		}
		return nil
	})
	if viewerr != nil {
		return viewerr
	}

	//var vb []byte
	adderr := db.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte("Users"))

		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser != nil {
			return errors.New("User already exists")
		}

		err = userbucket.Put([]byte(username), []byte(hash))
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

func (state *AuthState) Userlist() ([]string, error) {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return []string{}, err
	}
	defer state.releaseDB()

	userList := []string{}
	err = db.View(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket(UserInfoBucketName)
		err := userbucket.ForEach(func(key, value []byte) error {
			//fmt.Printf("A %s is %s.\n", key, value)
			userList = append(userList, string(key))
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	return userList, err
}

func (state *AuthState) DeleteUser(username string) error {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return err
	}
	defer state.releaseDB()

	err = db.Update(func(tx *bolt.Tx) error {
		log.Println(username + " has been deleted")
		return tx.Bucket(UserInfoBucketName).Delete([]byte(username))
	})
	if err != nil {
		return err
	}
	return err
}

func (state *AuthState) UpdatePass(username string, hash []byte) error {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return err
	}
	defer state.releaseDB()

	// Update password only if user exists
	err = db.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket(UserInfoBucketName)
		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser == nil {
			return UserDoesntExist
		}
		err := userbucket.Put([]byte(username), hash)
		if err != nil {
			return err
		}
		log.Println("User " + username + " has changed their password.")
		return nil
	})
	return err
}

func (state *AuthState) AuthMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//username := getUsernameFromCookie(r)
		//username, _ := GetUsername(r.Context())
		//if username == "" {
		if !IsLoggedIn(r.Context()) {
			rurl := r.URL.String()
			// Detect if we're in an endless loop, if so, just redirect to root
			if strings.HasPrefix(rurl, "login?url=/login") {
				log.Println("AUTH ERR AuthMiddle is in an endless redirect loop")
				http.Redirect(w, r, "http://"+r.Host+"/login", 302)
				return
			}
			http.Redirect(w, r, "http://"+r.Host+"/login"+"?url="+rurl, 302)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (state *AuthState) AuthMiddleHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoggedIn(r.Context()) {
			rurl := r.URL.String()
			// Detect if we're in an endless loop, if so, just redirect to root
			if strings.HasPrefix(rurl, "login?url=/login") {
				log.Println("AUTH ERR AuthMiddle is in an endless redirect loop")
				http.Redirect(w, r, "http://"+r.Host+"/login", 302)
				return
			}
			http.Redirect(w, r, "http://"+r.Host+"/login"+"?url="+rurl, 302)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (state *AuthState) AuthAdminMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, isAdmin := GetUsername(r.Context())
		//if username == "" {
		if !IsLoggedIn(r.Context()) {
			rurl := r.URL.String()
			// Detect if we're in an endless loop, if so, just redirect to root
			if strings.HasPrefix(rurl, "login?url=/login") {
				log.Println("AUTH ERR AuthAdminMiddle is in an endless redirect loop")
				http.Redirect(w, r, "http://"+r.Host+"/login", 302)
				return
			}
			http.Redirect(w, r, "http://"+r.Host+"/login"+"?url="+rurl, 302)
			return
		}
		//If user is not an Admin, just redirect to index
		if !isAdmin {
			log.Println(username + " attempting to access restricted URL.")
			state.SetSession("flash", "Sorry, you are not allowed to see that.", w, r)
			postRedir(w, r, "/")
			return
		}
		next.ServeHTTP(w, r)
	})
}

//UserEnvMiddle grabs username, role, and flash message from cookie,
// tosses it into the context for use in various other middlewares
func (state *AuthState) UserEnvMiddle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := state.getUsernameFromCookie(r, w)
		message := state.getFlashFromCookie(r, w)

		newc := r.Context()

		if username != "" {
			// Check if user actually exists before setting username
			// If user does not exist, clear the session because something fishy is going on
			if !state.doesUserExist(username) {
				log.Println("auth.UserEnvMiddle ERROR: Somehow a non-existent user was found in a cookie!")
				log.Println(username)
				username = ""
				state.ClearSession("user", w, r)
			}

			// If username is the configured defaultUser, set context to reflect this
			isAdmin := false
			if username == state.defaultUser {
				isAdmin = true
			}
			u := &User{
				Username: username,
				IsAdmin:  isAdmin,
			}

			newc = newUserContext(newc, u)
		}

		if message != "" {
			f := &Flash{
				Msg: message,
			}
			newc = newFlashContext(newc, f)
		}

		next.ServeHTTP(w, r.WithContext(newc))
	})
}

func (state *AuthState) AuthCookieMiddle(next http.HandlerFunc) http.HandlerFunc {
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

func (state *AuthState) dbInit() error {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return err
	}
	defer state.releaseDB()

	err = db.Update(func(tx *bolt.Tx) error {
		userbucket, err := tx.CreateBucketIfNotExists(UserInfoBucketName)
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		infobucket, err := tx.CreateBucketIfNotExists(AuthInfoBucketName)
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		hashKey := infobucket.Get(HashKeyName)
		if hashKey == nil {
			debugln("Throwing hashkey into auth.db.")
			// Generate a random hashKey
			hashKey := RandBytes(64)

			err = infobucket.Put(HashKeyName, hashKey)
			if err != nil {
				check(err)
				return err
			}
		}

		blockKey := infobucket.Get(BlockKeyName)
		if blockKey == nil {
			debugln("Throwing blockkey into auth.db.")
			// Generate a random blockKey
			blockKey := RandBytes(32)

			err = infobucket.Put(BlockKeyName, blockKey)
			if err != nil {
				check(err)
				return err
			}
		}

		userbucketUser := userbucket.Get([]byte(state.defaultUser))
		if userbucketUser == nil {

			//hash, err := passlib.Hash("admin")
			hash, err := HashPassword([]byte("admin"))
			if err != nil {
				// couldn't hash password for some reason
				check(err)
				return err
			}
			err = userbucket.Put([]byte(state.defaultUser), []byte(hash))
			if err != nil {
				check(err)
				return err
			}
			debugln("Admin Boltdb user " + state.defaultUser + " does not exist, creating it.")
			debugln("***DEFAULT USER CREDENTIALS:***")
			debugln("Username: " + state.defaultUser)
			debugln("Password: admin")

			return nil
		}
		return nil
	})
	return err
}

//UserSignupPostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *AuthState) UserSignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		err := state.NewUser(username, password)
		if err != nil {
			check(err)
			state.SetSession("flash", "Error adding user. Check logs.", w, r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		state.SetSession("flash", "Successfully added '"+username+"' user.", w, r)
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

//AdminUserPassChangePostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *AuthState) AdminUserPassChangePostHandler(w http.ResponseWriter, r *http.Request) {
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
			state.SetSession("flash", "Error hashing password. Check logs.", w, r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		err = state.UpdatePass(username, hash)
		if err != nil {
			check(err)
			state.SetSession("flash", "Error updating password. Check logs.", w, r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		state.SetSession("flash", "Successfully changed '"+username+"' users password.", w, r)
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
func (state *AuthState) AdminUserDeletePostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		err := state.DeleteUser(username)
		if err != nil {
			check(err)
			state.SetSession("flash", "Error deleting user. Check logs.", w, r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		state.SetSession("flash", "Successfully deleted '"+username+"'.", w, r)
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
func (state *AuthState) SignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		err := state.NewUser(username, password)
		if err != nil {
			check(err)
			state.SetSession("flash", "User registration failed.", w, r)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		state.SetSession("flash", "Successful user registration.", w, r)
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

//LoginPostHandler only handles POST requests, verifying forms named "username" and "password"
// Comparing values with LDAP or configured username/password combos
func (state *AuthState) LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		// Handle login POST request
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		referer, _ := url.Parse(r.Referer())
		// Check if we have a ?url= query string, from AuthMiddle
		// Otherwise, just use the referrer
		var r2 string
		r2 = referer.Query().Get("url")
		if r2 == "" {
			r2 = r.Referer()
			// if r.Referer is blank, just redirect to index
			if r.Referer() == "" || referer.RequestURI() == "/login" {
				r2 = "/"
			}
		}
		// Login authentication
		if state.BoltAuth(username, password) {
			state.SetSession("user", username, w, r)
			state.SetSession("flash", "User '"+username+"' successfully logged in.", w, r)
			http.Redirect(w, r, r2, http.StatusSeeOther)
			return
		}
		state.SetSession("flash", "User '"+username+"' failed to login. Please check your credentials and try again.", w, r)
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
