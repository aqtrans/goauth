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

// Context is used heavily. UserEnvMiddle tosses the flash/user info from cookies into context,
//   and also checks that the specified user from the cookie exists.

/* Example for using auth.State in an app:
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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"text/template"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

type key int

const (
	UserKey key = 1
	MsgKey key = 2
	authInfoBucketName = "AuthInfo"
	hashKeyName = "HashKey"
	blockKeyName = "BlockKey"
	userInfoBucketName = "Users"
	roleAdmin = "admin"
	roleUser = "user"
)

var (
	//authInfoBucketName = []byte("AuthInfo")
	//hashKeyName        = []byte("HashKey")
	//blockKeyName       = []byte("BlockKey")
	//userInfoBucketName = []byte("Users")
	userDoesntExist    = errors.New("User does not exist")
	// Debug variable can be set to true to have debugging info logged, otherwise silent
	Debug = false
	// LoginPath is the path to the login page, used to redirect protected pages
	LoginPath = "/login"
)

// State holds all required info to get authentication working in the app
type State struct {
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
	Password []byte
	Role string
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

func (state *State) getDB() (*bolt.DB, error) {
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

func (state *State) releaseDB() {
	state.BoltDB.authdb.Close()
}

// NewAuthState creates a new AuthState, storing the boltDB connection and cookie info
func NewAuthState(path string) (*State, error) {
	var db *bolt.DB

	return NewAuthStateWithDB(&DB{authdb: db, path: path}, path)
}

// NewAuthStateWithDB takes an instance of a boltDB, and returns an AuthState
func NewAuthStateWithDB(db *DB, path string) (*State, error) {
	state := new(State)
	state.BoltDB = db
	state.BoltDB.path = path

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
func (state *State) SetSession(key, val string, w http.ResponseWriter) {

	if encoded, err := state.cookie.Encode(key, val); err == nil {
		cookie := &http.Cookie{
			Name:     key,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	} else {
		debugln("Error encoding cookie " + key + " value")
	}

}

// SetFlash sets a flash message inside a cookie, which, combined with the UserEnvMiddle
//   middleware, pushes the message into context and then template
func (state *State) SetFlash(msg string, w http.ResponseWriter, r *http.Request) {
	state.SetSession("flash", msg, w)
}

func (state *State) ReadSession(key string, w http.ResponseWriter, r *http.Request) (value string) {
	if cookie, err := r.Cookie(key); err == nil {
		err := state.cookie.Decode(key, cookie.Value, &value)
		if err != nil {
			debugln("Error decoding cookie value for", key, err)
			state.SetSession(key, "", w)
		}
	} else {
		debugln("Error reading cookie", key, err)
	}
	return value
}

// ClearSession currently only clearing the user value
// The CSRF token should always be around due to the login form and such
func (state *State) ClearSession(key string, w http.ResponseWriter) {
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
	state.ClearSession("flash", w)
}

func (state *State) getUsernameFromCookie(r *http.Request, w http.ResponseWriter) (username string) {
	return state.ReadSession("user", w, r)
}

func (state *State) getRedirectFromCookie(r *http.Request, w http.ResponseWriter) (redirURL string) {
	redirURL = state.ReadSession("redirect", w, r)
	if redirURL != "" {
		state.ClearSession("redirect", w)
	}
	return redirURL
}

func (state *State) getFlashFromCookie(r *http.Request, w http.ResponseWriter) (message string) {
	message = state.ReadSession("flash", w, r)
	if message != "" {
		state.clearFlash(w)
	}
	return message
}

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

func GetUserState(c context.Context) *User {
	userC, ok := fromUserContext(c)
	if ok {
		// If username is in a context, and that user exists, return that User info
		if userC.Username != "" {
			return &User{
				Username: userC.Username,
				Role: userC.Role,
			}
		}
	}
	if !ok {
		debugln("No UserState in context.")
	}
	return nil
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

func (user *User) IsAdmin() bool {
	if user.Role == roleAdmin {
		return true
	}	
	return false
}

func (state *State) BoltAuth(username, password string) bool {

	// Catch non-existent users before wasting CPU cycles checking hashes
	if !state.DoesUserExist(username) {
		// Add a 10ms delay so it's not too obvious that the user does not exist
		time.Sleep(10 * time.Millisecond)
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
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return userDoesntExist
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
func (state *State) DoesUserExist(username string) bool {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return false
	}
	defer state.releaseDB()

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return userDoesntExist
		}
		return nil
	})
	if err == nil {
		return true
	}
	if err != nil && err != userDoesntExist {
		check(err)
		return false
	}
	return false
}

// Get a *User from the bucket
func (state *State) GetUserInfo(username string) *User {
	var user *User
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return nil
	}
	defer state.releaseDB()

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return userDoesntExist
		}
		err := json.Unmarshal(v, &user)
		if err != nil {
			check(err)
		}
		return nil
	})
	if err != nil {
		check(err)
		return nil
	}
	return user

	/*
		s := &Shorturl{
			Created: shorturl.Created,
			Short:   shorturl.Short,
			Long:    shorturl.Long,
			Hits:    shorturl.Hits + 1,
		}
		encoded, err := json.Marshal(s)
		if err != nil {
			log.Println(err)
			return err
		}

		return b.Put([]byte(title), encoded)
	*/
	
}

func (state *State) getAuthInfo() (hashkey, blockkey []byte) {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return []byte(""), []byte("")
	}
	defer state.releaseDB()

	err = db.View(func(tx *bolt.Tx) error {
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

func (state *State) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	state.ClearSession("user", w)
	http.Redirect(w, r, r.Referer(), 302)
}

// NewUser is a dedicated function to create new users, taking plaintext username, password, and role
//  Hashing done in this function, no need to do it before
func (state *State) NewUser(username, password, role string) error {
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
		userbucket := tx.Bucket([]byte(userInfoBucketName))
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

	if role != roleAdmin {
		return errors.New("NewUser role is invalid")
	} else if role != roleUser {
		return errors.New("NewUser role is invalid")
	}

	u := &User{
		Username: username,
		Password: hash,
		Role: role,
	}

	userEncoded, err := json.Marshal(u)
	if err != nil {
		check(err)
		return err
	}

	//var vb []byte
	adderr := db.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte("Users"))

		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser != nil {
			return errors.New("User already exists")
		}

		err = userbucket.Put([]byte(username), userEncoded)
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

func (state *State) Userlist() ([]string, error) {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return []string{}, err
	}
	defer state.releaseDB()

	var userList []string
	err = db.View(func(tx *bolt.Tx) error {
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

func (state *State) DeleteUser(username string) error {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return err
	}
	defer state.releaseDB()

	err = db.Update(func(tx *bolt.Tx) error {
		log.Println(username + " has been deleted")
		return tx.Bucket([]byte(userInfoBucketName)).Delete([]byte(username))
	})
	if err != nil {
		return err
	}
	return err
}

func (state *State) UpdatePass(username string, hash []byte) error {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return err
	}
	defer state.releaseDB()

	// Update password only if user exists
	err = db.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte(userInfoBucketName))
		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser == nil {
			return userDoesntExist
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

// Redirect throws the r.URL.Path into a cookie named "redirect" and redirects to the login page
func Redirect(state *State, w http.ResponseWriter, r *http.Request) {
	// Save URL in cookie for later use
	state.SetSession("redirect", r.URL.Path, w)
	// Redirect to the login page, should be at LoginPath
	http.Redirect(w, r, LoginPath, http.StatusSeeOther)
	return
}

func (state *State) AuthMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoggedIn(r.Context()) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

func (state *State) AuthMiddleHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoggedIn(r.Context()) {
			Redirect(state, w, r)
		}
		next.ServeHTTP(w, r)
	})
}

func (state *State) AuthAdminMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserState(r.Context())
		//if username == "" {
		if !IsLoggedIn(r.Context()) {
			Redirect(state, w, r)
		}
		//If user is not an Admin, just redirect to index
		if !user.IsAdmin() {
			log.Println(user.Username + " attempting to access " + r.URL.Path)
			state.SetSession("flash", "Sorry, you are not allowed to see that.", w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

//UserEnvMiddle grabs username, role, and flash message from cookie,
// tosses it into the context for use in various other middlewares
func (state *State) UserEnvMiddle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := state.getUsernameFromCookie(r, w)
		message := state.getFlashFromCookie(r, w)

		newc := r.Context()

		if username != "" {
			u := state.GetUserInfo(username)
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

func (state *State) dbInit() error {
	var db *bolt.DB
	var err error
	db, err = state.getDB()
	if err != nil {
		return err
	}
	defer state.releaseDB()

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(userInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		infobucket, err := tx.CreateBucketIfNotExists([]byte(authInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		hashKey := infobucket.Get([]byte(hashKeyName))
		if hashKey == nil {
			debugln("Throwing hashkey into auth.db.")
			// Generate a random hashKey
			hashKey := RandBytes(64)

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
			blockKey := RandBytes(32)

			err = infobucket.Put([]byte(blockKeyName), blockKey)
			if err != nil {
				check(err)
				return err
			}
		}

		return nil
	})
	return err
}

//UserSignupPostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *State) UserSignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		err := state.NewUser(username, password, roleUser)
		if err != nil {
			check(err)
			state.SetSession("flash", "Error adding user. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		state.SetSession("flash", "Successfully added '"+username+"' user.", w)
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
			state.SetSession("flash", "Error hashing password. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		err = state.UpdatePass(username, hash)
		if err != nil {
			check(err)
			state.SetSession("flash", "Error updating password. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		state.SetSession("flash", "Successfully changed '"+username+"' users password.", w)
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
			state.SetSession("flash", "Error deleting user. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		state.SetSession("flash", "Successfully deleted '"+username+"'.", w)
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
		err := state.NewUser(username, password, roleUser)
		if err != nil {
			check(err)
			state.SetSession("flash", "User registration failed.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
			return
		}
		state.SetSession("flash", "Successful user registration.", w)
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
// Comparing values with BoltDB values
func (state *State) LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		// Handle login POST request
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))

		// Login authentication
		if state.BoltAuth(username, password) {
			state.SetSession("user", username, w)
			state.SetSession("flash", "User '"+username+"' successfully logged in.", w)
			// Check if we have a redirect URL in the cookie, if so redirect to it
			//redirURL := state.getRedirectFromCookie(r, w)
			redirURL := state.ReadSession("redirect", w, r)
			if redirURL != "" {
				log.Println("Redirecting to", redirURL)
				state.ClearSession("redirect", w)
				http.Redirect(w, r, redirURL, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		state.SetSession("flash", "User '"+username+"' failed to login. Please check your credentials and try again.", w)
		http.Redirect(w, r, LoginPath, http.StatusFound)
		return
	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}
