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
	"os"
	"strings"
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
	boltdb      *DB
	cookie      *securecookie.SecureCookie
}

// DB wraps a bolt.DB struct, so I can test and interact with the db from programs using the lib, while vendoring bolt in both places
type DB struct {
	*bolt.DB
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

// MustOpenAuthDB returns a new, open DB at a specified location.
func MustOpenAuthDB(path string) *DB {
	db, err := bolt.Open(path, 0666, nil)
	if err != nil {
		panic(err)
	}
	return &DB{db}
}

// NewAuthState creates a new AuthState, storing the boltDB connection, cookie info, and defaultUsername (which is also the admin user)
func NewAuthState(path, user string) (*AuthState, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	return NewAuthStateWithDB(&DB{db}, path, user)
}

// NewAuthStateWithDB takes an instance of a boltDB, and returns an AuthState
func NewAuthStateWithDB(db *DB, path, user string) (*AuthState, error) {
	state := new(AuthState)
	state.boltdb = db
	// Important to set defaultUser now, before dbInit()
	state.defaultUser = user

	err := state.dbInit()
	if err != nil {
		log.Fatalln(err)
	}

	hash, block := state.getAuthInfo()
	state.cookie = securecookie.New(hash, block)

	return state, nil
}

// Generate a random amount of bytes given the
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		log.Fatalln(err)
		return nil
	}
	return b
}

// HashPassword generates a bcrypt hash of the password using work factor 14.
func HashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 14)
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

	var hashedUserPassByte []byte
	// Grab given user's password from Bolt
	state.boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UserInfoBucketName)
		v := b.Get([]byte(username))
		if v == nil {
			err := UserDoesntExist
			//log.Println(err)
			return err
		}
		hashedUserPassByte = v
		return nil
	})

	err := CheckPasswordHash(hashedUserPassByte, []byte(password))
	if err != nil {
		// Incorrect password, malformed hash, etc.
		debugln("error verifying password for user " + username)
		return false
	}
	// TODO: Should look into fleshing this out
	return true
}

// Check if user actually exists
func (state *AuthState) doesUserExist(username string) bool {
	err := state.boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UserInfoBucketName)
		v := b.Get([]byte(username))
		if v == nil {
			err := UserDoesntExist
			return err
		}
		return nil
	})
	if err == nil {
		return true
	}
	if err != nil && err != UserDoesntExist {
		log.Println(err)
	}
	return false
}

func (state *AuthState) getAuthInfo() (hashkey, blockkey []byte) {
	err := state.boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(AuthInfoBucketName)
		hashkey = b.Get(HashKeyName)
		blockkey = b.Get(BlockKeyName)
		return nil
	})
	if err != nil {
		panic(err)
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

	// Hash password now so if it fails we catch it before touching Bolt
	//hash, err := passlib.Hash(password)
	hash, err := HashPassword([]byte(password))
	if err != nil {
		// couldn't hash password for some reason
		log.Fatalln(err)
		return err
	}

	// If no existing user, store username and hash
	viewerr := state.boltdb.View(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket(UserInfoBucketName)

		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser != nil {
			err := errors.New("User already exists")
			log.Println(err)
			return err
		}
		return nil
	})
	if viewerr != nil {
		return viewerr
	}

	//var vb []byte
	adderr := state.boltdb.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte("Users"))

		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser != nil {
			err := errors.New("User already exists")
			log.Println(err)
			return err
		}

		err = userbucket.Put([]byte(username), []byte(hash))
		if err != nil {
			log.Println(err)
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
	userList := []string{}
	err := state.boltdb.View(func(tx *bolt.Tx) error {
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
	err := state.boltdb.Update(func(tx *bolt.Tx) error {
		log.Println(username + " has been deleted")
		return tx.Bucket(UserInfoBucketName).Delete([]byte(username))
	})
	if err != nil {
		log.Println(err)
		return err
	}
	return err
}

func (state *AuthState) UpdatePass(username string, hash []byte) error {

	// Update password only if user exists
	state.boltdb.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket(UserInfoBucketName)
		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser == nil {
			err := UserDoesntExist
			log.Println(err)
			return err
		}
		err := userbucket.Put([]byte(username), hash)
		if err != nil {
			return err
		}
		log.Println("User " + username + " has changed their password.")
		return nil
	})
	return nil
}

func (state *AuthState) AuthMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//username := getUsernameFromCookie(r)
		//username, _ := GetUsername(r.Context())
		//if username == "" {
		if !IsLoggedIn(r.Context()) {
			rurl := r.URL.String()
			// Detect if we're in an endless loop, if so, just panic
			if strings.HasPrefix(rurl, "login?url=/login") {
				panic("AuthMiddle is in an endless redirect loop")
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
			// Detect if we're in an endless loop, if so, just panic
			if strings.HasPrefix(rurl, "login?url=/login") {
				panic("AuthMiddle is in an endless redirect loop")
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
			// Detect if we're in an endless loop, if so, just panic
			if strings.HasPrefix(rurl, "login?url=/login") {
				panic("AuthAdminMiddle is in an endless redirect loop")
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

	return state.boltdb.Update(func(tx *bolt.Tx) error {
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
				log.Println(err)
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
				log.Println(err)
				return err
			}
		}

		userbucketUser := userbucket.Get([]byte(state.defaultUser))
		if userbucketUser == nil {

			//hash, err := passlib.Hash("admin")
			hash, err := HashPassword([]byte("admin"))
			if err != nil {
				// couldn't hash password for some reason
				log.Fatalln(err)
				return err
			}
			err = userbucket.Put([]byte(state.defaultUser), []byte(hash))
			if err != nil {
				log.Println(err)
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
}
