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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"text/template"

	"golang.org/x/oauth2"
	//"text/template"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pelletier/go-toml"

	"github.com/boltdb/bolt"
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

	errUserDoesNotExist = "User does not exist"
)

var (
	// Debug variable can be set to true to have debugging info logged, otherwise silent
	Debug = false
	// LoginPath is the path to the login page, used to redirect protected pages
	LoginPath = "/login"
)

// State holds all required info to get authentication working in the app
type State struct {
	authBackend
	cookie *securecookie.SecureCookie
}

type authBackend interface {
	Auth(username, password string) bool
	DoesUserExist(username string) bool
	GetUserInfo(username string) *User
	getAuthInfo() (hashkey, blockkey []byte)
	newUser(username, password, role string) error
	Userlist() ([]string, error)
	DeleteUser(username string) error
	UpdatePass(username string, hash []byte) error
	// These are very OIDC-specific
	GetLoginURL(rand string) string
	VerifyUser(code string) (string, string, error)
}

// DB wraps a bolt.DB struct, so I can test and interact with the db from programs using the lib, while vendoring bolt in both places
type DB struct {
	authdb *bolt.DB
	path   string
}

type GoogleOIDC struct {
	tomlPath   string
	Connectors oidcConnectors
}

type oidcConnectors struct {
	Provider *oidc.Provider
	Verifier *oidc.IDTokenVerifier
	Cfg      *oauth2.Config
}

type oidcClaims struct {
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
	//Username string `json:"preferred_username"`
}

type authInfo struct {
	hashKey  []byte
	blockKey []byte
}

type User struct {
	Name     string
	Password []byte
	Role     string
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

// NewBoltAuthState creates a new AuthState using the BoltDB backend, storing the boltDB connection and cookie info
func NewBoltAuthState(path string) *State {
	var db *bolt.DB

	return NewBoltAuthStateWithDB(&DB{authdb: db, path: path}, path)
}

func NewOIDCAuthState(path, id, secret, redirectURL string) *State {

	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		log.Fatalln("Error setting up GoogleOIDC provider:", err)
	}

	g := &GoogleOIDC{
		tomlPath: path,
		Connectors: oidcConnectors{
			Provider: provider,
			Verifier: provider.Verifier(&oidc.Config{ClientID: id}),
			Cfg: &oauth2.Config{
				ClientID:     id,
				ClientSecret: secret,
				RedirectURL:  redirectURL,
				// Discovery returns the OAuth2 endpoints.
				Endpoint: provider.Endpoint(),

				// "openid" is a required scope for OpenID Connect flows.
				Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
			},
		},
	}

	// Load TOML if it exists:
	var tree *toml.Tree
	tree, err = toml.LoadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			_, err := os.Create(path)
			if err != nil {
				log.Fatalln("Error creating toml:", err)
			}
			tree, err = toml.LoadFile(path)
			if err != nil {
				log.Fatalln("Error loading toml:", err)
			}
		} else {
			log.Fatalln("Error loading toml:", err)
		}
	}

	if !tree.Has("AuthInfo") {
		log.Println(path, "does not contain AuthInfo. Generating them...")
		hashKey := RandString(64)
		tree.SetPath([]string{"AuthInfo", "HashKey"}, hashKey)
		blockKey := RandString(32)
		tree.SetPath([]string{"AuthInfo", "BlockKey"}, blockKey)
		g.saveTOMLTree(tree)
	}

	//omg1, omg2 := g.getAuthInfo()
	//log.Println(len(omg1), len(omg2))

	return &State{
		authBackend: g,
		cookie:      securecookie.New(g.getAuthInfo()),
	}
}

// NewBoltAuthStateWithDB takes an instance of a boltDB, and returns an AuthState using the BoltDB backend
func NewBoltAuthStateWithDB(db *DB, path string) *State {
	if path == "" {
		log.Fatalln(errors.New("NewAuthStateWithDB: path is blank"))
	}

	db.dbInit()

	return &State{
		authBackend: db,
		cookie:      securecookie.New(db.getAuthInfo()),
	}
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

func RandString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes := RandBytes(n)
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

func newUserContext(c context.Context, u *User) context.Context {
	return context.WithValue(c, UserKey, u)
}

func userFromContext(c context.Context) (*User, bool) {
	u, ok := c.Value(UserKey).(*User)
	return u, ok
}

func newFlashContext(c context.Context, f *Flash) context.Context {
	return context.WithValue(c, MsgKey, f)
}

func flashFromContext(c context.Context) (*Flash, bool) {
	f, ok := c.Value(MsgKey).(*Flash)
	return f, ok
}

func newChkContext(c context.Context) context.Context {
	return context.WithValue(c, ChkKey, true)
}

func chkFromContext(c context.Context) bool {
	_, ok := c.Value(ChkKey).(bool)
	return ok
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

// SetState sets the state, for OIDC connections
func (state *State) SetState(msg string, w http.ResponseWriter) {
	state.setSession(cookieState, msg, w)
}

// ReadState reads the state (and nonce, but they should be the same value)
func (state *State) ReadState(w http.ResponseWriter, r *http.Request) string {
	theState := state.readSession(cookieState, w, r)
	// Clear state cookie after it's read
	state.clearSession(cookieState, w)
	return theState
}

func (state *State) SetUsername(msg string, w http.ResponseWriter) {
	state.setSession(cookieUser, msg, w)
}

func (state *State) ReadUsername(w http.ResponseWriter, r *http.Request) string {
	return state.readSession(cookieUser, w, r)
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

func GetUserState(c context.Context) *User {
	userC, ok := userFromContext(c)
	if ok {
		return userC
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
		flash = t.Msg
	}
	return flash
}

func (user *User) IsAdmin() bool {
	if user != nil {
		if user.Role == roleAdmin {
			return true
		}
	}

	return false
}

func (user *User) GetName() string {
	if user != nil {
		return user.Name
	}
	return ""
}

func (g *GoogleOIDC) getTOMLTree() *toml.Tree {
	tree, err := toml.LoadFile(g.tomlPath)
	if err != nil {
		log.Fatalln("Error loading toml:", err)
	}

	return tree
}

func (g *GoogleOIDC) getUserTree(username string) *toml.Tree {
	tree := g.getTOMLTree()
	if tree.HasPath([]string{"users", username}) {
		userTree := tree.GetPath([]string{"users", username}).(*toml.Tree)
		return userTree
	}
	return nil
}

func (g *GoogleOIDC) saveTOMLTree(tree *toml.Tree) {
	tomlFile, err := os.Create(g.tomlPath)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = tree.WriteTo(tomlFile)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(tree.String())
	log.Println(g.tomlPath, "successfully saved.")
}

// TODO: Actually get this working!
func (g *GoogleOIDC) Auth(username, password string) bool {
	tree := g.getTOMLTree()

	// Only allow logging in when email is defined in the TOML
	if tree.HasPath([]string{"users", username}) {

		// Hash the password just given
		hash, err := HashPassword([]byte(password))
		if err != nil {
			// couldn't hash password for some reason
			log.Fatalln(err)
		}

		tree.SetPath([]string{"users", username, "password"}, string(hash))

		// Set role to user if one was not given
		if !tree.HasPath([]string{"users", username, "role"}) {
			tree.SetPath([]string{"users", username, "role"}, roleUser)
		}
		g.saveTOMLTree(tree)
		return true
	}

	if tree.HasPath([]string{"users", username}) {
		hashString := tree.GetPath([]string{"users", username, "password"}).(string)
		bHash := []byte(hashString)
		err := CheckPasswordHash(bHash, []byte(password))
		if err != nil {
			log.Println("Error verifying password:", err)
			return false
		}
		return true
	}

	return false
}

func (g *GoogleOIDC) DeleteUser(username string) error {
	tree := g.getTOMLTree()
	if tree.HasPath([]string{"users", username}) {
		treeMap := tree.ToMap()
		delete(treeMap, "users."+username)
		newTree, err := toml.TreeFromMap(treeMap)
		if err != nil {
			return err
		}
		g.saveTOMLTree(newTree)
	}
	return nil
}

// DoesUserExist in this case, takes the raw ID token, and verifies it against the Google OIDC endpoint
func (g *GoogleOIDC) DoesUserExist(username string) bool {
	// Might reuse this check below at some point, to check if a user has registered before or something?
	//return t.getTOMLTree().HasPath([]string{"users", username})
	/*
		// Parse and verify ID Token payload.
		idToken, err := g.Connectors.Verifier.Verify(context.Background(), username)
		if err != nil {
			log.Println("Error verifying rawIDToken:", err)
			return false
		}

		// Extract custom claims
		var claims oidcClaims
		if err == nil {
			if err := idToken.Claims(&claims); err != nil {
				log.Println("Error extracting claims:", err)
				return false
			}
		}
		return true
	*/

	return false
}

// GetUserInfo verifies a given ID token (retrieved from a cookie more than likely) and unmarshal's the 'claim', picking the email address out
// It also attempts to fetch the user's role from the TOML file
func (g *GoogleOIDC) GetUserInfo(username string) *User {
	/*
		// Parse and verify ID Token payload.
		idToken, err := g.Connectors.Verifier.Verify(context.Background(), username)
		if err != nil {
			log.Println("Error verifying rawIDToken:", err)
			return nil
		}

		// Extract custom claims
		var claims oidcClaims
		if err == nil {
			if err := idToken.Claims(&claims); err != nil {
				log.Println("Error extracting claims:", err)
				return nil
			}
		}
	*/

	var role string
	// If TOML contains [users.username], try and fetch users role from it
	// Otherwise presume they are just a 'user'
	if g.getTOMLTree().HasPath([]string{"users", username}) {
		tree := g.getTOMLTree().GetPath([]string{"users", username}).(*toml.Tree)
		role = tree.Get("role").(string)
	}

	if role == "" {
		role = roleUser
	}
	user := &User{
		Name: username,
		Role: role,
	}
	return user
}

func (t *GoogleOIDC) UpdatePass(username string, hash []byte) error {
	// Nothing to do for passwords here
	return nil
}

func (t *GoogleOIDC) Userlist() ([]string, error) {
	tree := t.getTOMLTree().Get("users").(*toml.Tree)
	return tree.Keys(), nil

}

func (t *GoogleOIDC) getAuthInfo() (hashkey, blockkey []byte) {
	tree := t.getTOMLTree().Get("AuthInfo").(*toml.Tree)
	hashkeyS := tree.Get("HashKey").(string)
	blockkeyS := tree.Get("BlockKey").(string)
	return []byte(hashkeyS), []byte(blockkeyS)
}

func (t *GoogleOIDC) newUser(username, password, role string) error {
	// Check that the given role is valid before even opening the DB
	switch role {
	case roleAdmin, roleUser:
	default:
		return errors.New("NewUser role is invalid: " + role)
	}

	tree := t.getTOMLTree().Get("users").(*toml.Tree)
	tree.SetPath([]string{"users", username, "role"}, role)
	return nil
}

// GetLoginURL takes a (hopefully) randomly generated string and passes it along to AuthCodeURL
// This random string should be set in the cookie using userstate.SetState(), then read in the callback HTTP handler
func (g *GoogleOIDC) GetLoginURL(rand string) string {
	return g.Connectors.Cfg.AuthCodeURL(rand, oidc.Nonce(rand))
}

func (g *GoogleOIDC) VerifyUser(code string) (string, string, error) {

	token, err := g.Connectors.Cfg.Exchange(context.Background(), code)
	if err != nil {
		errorMsg := fmt.Sprintf("Code exchange failed: %v", err)
		return "", "", errors.New(errorMsg)
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", "", errors.New("id_token missing")
	}

	// Parse and verify ID Token payload.
	idToken, err := g.Connectors.Verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		errorMsg := fmt.Sprintf("Error verifying rawIDToken: %v", err)
		return "", "", errors.New(errorMsg)
	}

	//log.Println("Token Nonce:", idToken.Nonce)

	/*
		// Extract custom claims from id_token
		var claims oidcClaims
		if err := idToken.Claims(&claims); err != nil {
			errorMsg := fmt.Sprintf("Error extracting claims:", err)
			return "", errors.New(errorMsg)
		}
		log.Println(claims)
	*/

	userInfo, err := g.Connectors.Provider.UserInfo(context.Background(), oauth2.StaticTokenSource(token))
	if err != nil {
		errorMsg := fmt.Sprintf("Error fetching user info using token: %v", err)
		return "", "", errors.New(errorMsg)
	}

	// Possible TODO: Return token.AccessToken here?
	// Findings on whether storing the id_token in cookie are mixed
	// This is a secure cookie, so should be OK from prying eyes

	// Could I store the "code" given at the top? Unsure what exactly that is

	// Returning users email, and the nonce from the token.
	// That nonce is then compared to the nonce inside the client cookie in GoogleCallback()
	return userInfo.Email, idToken.Nonce, nil

}

func (db *DB) GetLoginURL(rand string) string {
	return LoginPath
}

func (db *DB) VerifyUser(code string) (string, string, error) {
	return "", "", nil
}

func (db *DB) Auth(username, password string) bool {

	boltdb := db.getDB()
	defer db.releaseDB()

	var user *User
	// Grab given user's password from Bolt
	err := boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return errors.New(errUserDoesNotExist)
		}

		err := json.Unmarshal(v, &user)
		if err != nil {
			check(err)
			return err
		}
		err = CheckPasswordHash(user.Password, []byte(password))
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

// Check if user actually exists
func (db *DB) DoesUserExist(username string) bool {
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return errors.New(errUserDoesNotExist)
		}
		return nil
	})
	if err == nil {
		return true
	}
	if err != nil && err != errors.New(errUserDoesNotExist) {
		check(err)
		return false
	}
	return false
}

// Get a *User from the bucket
func (db *DB) GetUserInfo(username string) *User {
	var user *User
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return errors.New(errUserDoesNotExist)
		}
		err := json.Unmarshal(v, &user)
		if err != nil {
			check(err)
			return err
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

func (state *State) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	state.clearSession(cookieUser, w)
	http.Redirect(w, r, r.Referer(), 302)
}

// NewUser creates a new user with a given plaintext username and password
func (state *State) NewUser(username, password string) error {
	return state.newUser(username, password, roleUser)
}

// NewAdmin creates a new admin with a given plaintext username and password
func (state *State) NewAdmin(username, password string) error {
	return state.newUser(username, password, roleAdmin)
}

// newUser is a dedicated function to create new users, taking plaintext username, password, and role
//  Hashing done in this function, no need to do it before
func (db *DB) newUser(username, password, role string) error {

	// Check that the given role is valid before even opening the DB
	switch role {
	case roleAdmin, roleUser:
	default:
		return errors.New("NewUser role is invalid: " + role)
	}

	// Same for hasing; Hash password now so if it fails we catch it before touching Bolt
	hash, err := HashPassword([]byte(password))
	if err != nil {
		// couldn't hash password for some reason
		check(err)
		return err
	}

	u := &User{
		Name:     username,
		Password: hash,
		Role:     role,
	}

	userEncoded, err := json.Marshal(u)
	if err != nil {
		check(err)
		return err
	}

	boltdb := db.getDB()
	defer db.releaseDB()
	//var vb []byte
	adderr := boltdb.Update(func(tx *bolt.Tx) error {
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

func (db *DB) DeleteUser(username string) error {
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.Update(func(tx *bolt.Tx) error {
		log.Println(username + " has been deleted")
		return tx.Bucket([]byte(userInfoBucketName)).Delete([]byte(username))
	})
	if err != nil {
		return err
	}
	return err
}

func (db *DB) UpdatePass(username string, hash []byte) error {
	boltdb := db.getDB()
	defer db.releaseDB()

	// Update password only if user exists
	err := boltdb.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte(userInfoBucketName))
		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser == nil {
			return errors.New(errUserDoesNotExist)
		}

		var user *User
		err := json.Unmarshal(userbucketUser, &user)
		if err != nil {
			check(err)
			return err
		}

		user.Password = hash

		encoded, err := json.Marshal(user)
		if err != nil {
			log.Println(err)
			return err
		}

		err = userbucket.Put([]byte(username), encoded)
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
			log.Println(user.GetName() + " attempting to access " + r.URL.Path)
			state.setSession(cookieFlash, "Sorry, you are not allowed to see that.", w)
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
		//newc = newChkContext(newc)

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
	if err != nil {
		log.Fatalln("Error in dbInit():", err)
	}
}

/* THIS HANDLER STUFF SHOULD ALL BE TAKEN CARE OF IN THE APPS; LEAVING FOR EXAMPLES:

//UserSignupPostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func (state *State) UserSignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		err := state.NewUser(username, password)
		if err != nil {
			check(err)
			state.setSession(cookieFlash, "Error adding user. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
		}
		state.setSession(cookieFlash, "Successfully added '"+username+"' user.", w)
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
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))

		// Login authentication
		if state.Auth(username, password) {
			state.setSession(cookieUser, username, w)
			state.SetFlash("User '"+username+"' successfully logged in.", w)
			// Check if we have a redirect URL in the cookie, if so redirect to it
			//redirURL := state.getRedirectFromCookie(r, w)
			redirURL := state.readSession(cookieRedirect, w, r)
			if redirURL != "" {
				log.Println("Redirecting to", redirURL)
				state.clearSession(cookieRedirect, w)
				http.Redirect(w, r, redirURL, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		state.SetFlash("User '"+username+"' failed to login. Please check your credentials and try again.", w)
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

func (state *State) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	b := RandString(12)
	state.SetState(b, w)

	url := state.GetLoginURL(b)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (state *State) GoogleCallback(w http.ResponseWriter, r *http.Request) {

	cookieState := r.FormValue("state")
	expectedState := state.ReadState(w, r)

	if cookieState != expectedState {
		log.Println("state and expectedState do not match.", state, expectedState)
		state.clearSession(cookieState, w)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	username, nonce, err := state.VerifyUser(code)
	if nonce != expectedState {
		state.clearSession(cookieState, w)
		log.Println("Nonce does not match!")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	if err != nil {
		log.Println("Error verifying user:", err)
		state.clearSession(cookieState, w)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	state.SetUsername(username, w)

	// Set the ID token into the "token" securecookie
	//userstate.SetToken(rawIDToken, w)

	state.SetFlash("User '"+username+"' successfully logged in.", w)
	// Check if we have a redirect URL in the cookie, if so redirect to it
	redirURL := state.readSession(cookieRedirect, w, r)
	if redirURL != "" {
		log.Println("Redirecting to", redirURL)
		state.clearSession(cookieRedirect, w)
		http.Redirect(w, r, redirURL, http.StatusTemporaryRedirect)
		return
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	return
}
