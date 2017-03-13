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
//
//  XSRF:
//   - Cross-site Request Forgery protection, using the same concept I use for auth functions above
//   - I personally migrated to gorilla/csrf, as it's go1.7/context compatible and easy to use

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

type key int

const TokenKey key = 0
const UserKey key = 1
const MsgKey key = 2

var AuthInfoBucketName = []byte("AuthInfo")
var HashKeyName = []byte("HashKey")
var BlockKeyName = []byte("BlockKey")
var UserInfoBucketName = []byte("Users")

var UserDoesntExist = errors.New("User does not exist")

type AuthState struct {
	boltdb *bolt.DB
	cookie *securecookie.SecureCookie
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

type Token string

var (
	AdminUser = "admin"
	AdminPass = "admin"
	Debug     = false
)

func NewAuthState(path string) (*AuthState, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	state := new(AuthState)
	state.boltdb = db
	err = state.dbInit()
	if err != nil {
		log.Println(err)
	}

	hash, block := state.getAuthInfo()
	state.cookie = securecookie.New(hash, block)

	return state, nil
}

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

//RandKey generates a random string of specific length
func RandKey(n int) string {
	b := RandBytes(n)
	return base64.RawURLEncoding.EncodeToString(b)
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

func newTokenContext(c context.Context, t string) context.Context {
	return context.WithValue(c, TokenKey, t)
}

func fromTokenContext(c context.Context) (string, bool) {
	t, ok := c.Value(TokenKey).(string)
	return t, ok
}

// SetSession Takes a key, and a value to store inside a cookie
// Currently used for username and CSRF tokens
func (state *AuthState) SetSession(key, val string, w http.ResponseWriter, r *http.Request) {

	if encoded, err := state.cookie.Encode(key, val); err == nil {
		cookie := &http.Cookie{
			Name:  key,
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	}

}

func (state *AuthState) ReadSession(key string, w http.ResponseWriter, r *http.Request) (value string) {
	if cookie, err := r.Cookie(key); err == nil {
		err := state.cookie.Decode(key, cookie.Value, &value)
		if err != nil {
			log.Println("Error decoding cookie " + key + " value")
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

// Retrieve a token
func (state *AuthState) getTokenFromCookie(r *http.Request, w http.ResponseWriter) (token string) {
	return state.ReadSession("token", w, r)
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
func (state *AuthState) IsLoggedIn(c context.Context) bool {
	userC, ok := fromUserContext(c)
	if ok {
		// If username is in a context, and that user exists, return true
		if userC.Username != "" && state.doesUserExist(userC.Username) {
			return true
		}
	}
	if !ok {
		log.Println("Error IsLoggedIn not OK")
	}
	return false
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

// GetToken retrieves token from context
func GetToken(c context.Context) string {
	//defer timeTrack(time.Now(), "GetUsername")
	t, ok := fromTokenContext(c)
	if !ok {
		t = ""
	}
	return t
}

func (state *AuthState) genToken(w http.ResponseWriter, r *http.Request) string {
	token := RandKey(32)
	state.SetSession("token", token, w, r)
	return token
}

// Only set a new token if one doesn't already exist
func (state *AuthState) setToken(w http.ResponseWriter, r *http.Request) (context.Context, string) {
	token := state.ReadSession("token", w, r)
	if token == "" {
		token := RandKey(32)
		state.SetSession("token", token, w, r)
	}
	return newTokenContext(r.Context(), token), token
}

// CheckToken if given an http.Request with a token input, compare it to the token in the session cookie
func (state *AuthState) CheckToken(w http.ResponseWriter, r *http.Request) error {
	flashToken := GetToken(r.Context())
	tmplToken := r.FormValue("token")
	if tmplToken == "" {
		return fmt.Errorf("CSRF Blank! flashToken: %s tmplToken: %s", flashToken, tmplToken)
	}
	if !verifyToken(tmplToken, flashToken) {
		return fmt.Errorf("CSRF Mismatch! flashToken: %s tmplToken: %s", flashToken, tmplToken)
	}
	// Generate a new CSRF token after this one has been used
	newToken := RandKey(32)
	state.SetSession("token", newToken, w, r)
	return nil
}

//UserSignupPostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *AuthState) UserSignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		err := state.newUser(username, password)
		if err != nil {
			panic(err)
		}

		state.SetSession("flash", "Successfully added '"+username+"' user.", w, r)
		postRedir(w, r, r.Referer())

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
			log.Fatalln(err)
			return
		}

		err = state.updatePass(username, hash)
		if err != nil {
			panic(err)
		}
		state.SetSession("flash", "Successfully changed '"+username+"' users password.", w, r)
		postRedir(w, r, r.Referer())

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

		err := state.deleteUser(username)
		if err != nil {
			panic(err)
		}
		state.SetSession("flash", "Successfully changed '"+username+"' users password.", w, r)
		postRedir(w, r, r.Referer())

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
		err := state.newUser(username, password)
		if err != nil {
			state.SetSession("flash", "User registration failed.", w, r)
			postRedir(w, r, "/signup")
			return
		}
		state.SetSession("flash", "Successful user registration.", w, r)
		postRedir(w, r, "/login")
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
		// This should be handled in a separate function inside your app
		/*
			// Serve login page, replacing loginPageHandler
			defer timeTrack(time.Now(), "loginPageHandler")
			title := "login"
			user := GetUsername(r)
			//p, err := loadPage(title, r)
			data := struct {
				UN  string
				Title string
			}{
				user,
				title,
			}
			err := renderTemplate(w, "login.tmpl", data)
			if err != nil {
				log.Println(err)
				return
			}
		*/
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
		if state.auth(username, password) {
			state.SetSession("user", username, w, r)
			state.SetSession("flash", "User '"+username+"' successfully logged in.", w, r)
			postRedir(w, r, r2)
			return
		}
		state.SetSession("flash", "User '"+username+"' failed to login. <br> Please check your credentials and try again.", w, r)
		postRedir(w, r, "/login")
		return

	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}

}

/*
func ldapAuth(un, pw string) bool {
	//Build DN: uid=admin,ou=People,dc=example,dc=com
	dn := Authcfg.LdapUn + "=" + un + ",ou=" + Authcfg.LdapConf.LdapOu + "," + Authcfg.LdapConf.LdapDn
	l := ldap.NewLDAPConnection(Authcfg.LdapConf.LdapUrl, Authcfg.LdapConf.LdapPort)
	err := l.Connect()
	if err != nil {
		utils.Debugln(dn)
		fmt.Printf("LDAP connection error: %v", err)
		return false
	}
	defer l.Close()
	err = l.Bind(dn, pw)
	if err != nil {
		utils.Debugln(dn)
		fmt.Printf("error: %v", err)
		return false
	}
	utils.Debugln("Authenticated via LDAP")
	return true
}
*/

// Bundle of all auth functions, checking which are enabled
func (state *AuthState) auth(username, password string) bool {
	return state.boltAuth(username, password)
}

func (state *AuthState) boltAuth(username, password string) bool {

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
		log.Println("error verifying password for user " + username)
		return false
	}
	// TODO: Should look into fleshing this out
	return true
}

// Check if user actually exists
func (state *AuthState) doesUserExist(username string) bool {
	err := state.boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(UserInfoBucketName))
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

// Taken from nosurf: https://github.com/justinas/nosurf/blob/master/token.go
func verifyToken(realToken, sentToken string) bool {
	return subtle.ConstantTimeCompare([]byte(realToken), []byte(sentToken)) == 1
}

// Dedicated function to create new users, taking plaintext username, password, and role
//  Hashing done in this function, no need to do it before
func (state *AuthState) newUser(username, password string) error {

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

func (state *AuthState) deleteUser(username string) error {
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

func (state *AuthState) updatePass(username string, hash []byte) error {

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
		if !state.IsLoggedIn(r.Context()) {
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
		if !state.IsLoggedIn(r.Context()) {
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

		// Check if user actually exists before setting username
		// If user does not exist, clear the session because something fishy is going on
		if !state.doesUserExist(username) {
			username = ""
			state.ClearSession("user", w, r)
		}

		// If username is the configured AdminUser, set context to reflect this
		isAdmin := false
		if username == AdminUser {
			isAdmin = true
		}
		u := &User{
			Username: username,
			IsAdmin:  isAdmin,
		}
		f := &Flash{
			Msg: message,
		}
		newc := newUserContext(r.Context(), u)
		newc = newFlashContext(newc, f)
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
			log.Println("Throwing hashkey into auth.db.")
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
			log.Println("Throwing blockkey into auth.db.")
			// Generate a random blockKey
			blockKey := RandBytes(32)

			err = infobucket.Put(BlockKeyName, blockKey)
			if err != nil {
				log.Println(err)
				return err
			}
		}

		userbucketUser := userbucket.Get([]byte(AdminUser))
		if userbucketUser == nil {

			//hash, err := passlib.Hash("admin")
			hash, err := HashPassword([]byte(AdminPass))
			if err != nil {
				// couldn't hash password for some reason
				log.Fatalln(err)
				return err
			}
			err = userbucket.Put([]byte(AdminUser), []byte(hash))
			if err != nil {
				log.Println(err)
				return err
			}
			log.Println("Admin Boltdb user " + AdminUser + " does not exist, creating it.")
			fmt.Println("***DEFAULT USER CREDENTIALS:***")
			fmt.Println("Username: " + AdminUser)
			fmt.Println("Password: " + AdminPass)

			return nil
		}
		return nil
	})
}

/*
func Csrf(next http.HandlerFunc) http.HandlerFunc {
	handler := func(w http.ResponseWriter, r *http.Request) {
        r.ParseForm()
		flashToken := GetToken(r)
		tmplToken := r.FormValue("token")
        log.Println("flashToken: "+flashToken)
        log.Println("tmplToken: "+tmplToken)
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(handler)
}
*/
