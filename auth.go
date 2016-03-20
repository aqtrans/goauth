package auth

//Auth functions

import (
	//"github.com/gorilla/securecookie"
    "github.com/gorilla/sessions"
	"github.com/mavricknz/ldap"
    "github.com/gorilla/context"
    "gopkg.in/hlandau/passlib.v1"
    "errors"
	//"github.com/gorilla/mux"
	"html/template"
	"log"
	"fmt"
	"net/http"
    "net/url"
    "os"
	//"time"
	"encoding/json"
    "jba.io/go/utils"
    "strings"
)

type key int
const TokenKey key = 0
const UserKey key = 1

// AuthConf: Pass Auth inside auth.json
/*    
    "AuthConf": {
            "Users": {},
            "LdapEnabled": true,
            "LdapPort": 389,
            "LdapUrl": "frink.es.gy",
            "LdapUn": "uid",
            "LdapOu": "People",
            "LdapDn": "dc=jba,dc=io"
    }
*/
// Then decode and populate this struct using code from the main app
type AuthConf struct {
	Users       map[string]string
    Roles       map[string]string
	LdapEnabled bool
	LdapPort uint16 `json:",omitempty"`
	LdapUrl  string `json:",omitempty"`
	LdapDn   string `json:",omitempty"`
	LdapUn   string `json:",omitempty"`
	LdapOu   string `json:",omitempty"`
}

type Cookie struct {
    Username string
}

//JSON Response
type jsonresponse struct {
	Name    string `json:"name,omitempty"`
	Success bool   `json:"success"`
}

var	Authcfg = AuthConf{}

//var sCookieHandler = securecookie.New(
//	securecookie.GenerateRandomKey(64),
//	securecookie.GenerateRandomKey(32))

var CookieHandler = sessions.NewCookieStore(
	[]byte("5CO4mHhkuV4BVDZT72pfkNxVhxOMHMN9lTZjGihKJoNWOUQf5j32NF2nx8RQypUh"),
	[]byte("YuBmqpu4I40ObfPHw0gl7jeF88bk4eT4"),
)    


func init() {
	authconf, _ := os.Open("auth.json")
	decoder := json.NewDecoder(authconf)
	err := decoder.Decode(&Authcfg)
	if err != nil {
		fmt.Println("error decoding Auth config:", err)
	}
    //authcfg.Users = make(map[string]string)
    //j, _ := json.Marshal(authcfg)
    //log.Println(string(j))
}

//func AuthConfig(un, pass, ldapport, ldapurl, ldapdn, ldapun string) {
//}

// Takes a key, and a value to store inside a cookie
// Currently used for username and CSRF tokens
func SetSession(key, val string, w http.ResponseWriter, r *http.Request) {
	//defer timeTrack(time.Now(), "SetSession")
    session, err := CookieHandler.Get(r, "session")
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    session.Options = &sessions.Options{
        Path: "/",
        HttpOnly: true,
        Secure: false,
    }
	session.Values[key] = val
    session.Save(r, w)
}

// Clear session, currently only clearing the user value
// The CSRF token should always be around due to the login form and such
func ClearSession(w http.ResponseWriter, r *http.Request) {
    s, err := CookieHandler.Get(r, "session")
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    _, ok := s.Values["user"].(string)
    if ok {
        delete(s.Values, "user")
        s.Save(r, w)
    }
}

func getUsernameFromCookie(r *http.Request) (username string) {
	//defer timeTrack(time.Now(), "GetUsername")
    s, _ := CookieHandler.Get(r, "session")
    username, ok := s.Values["user"].(string)
    if !ok {
        username = ""
    }
	//log.Println("GetUsername: "+username)
	return username
}

// Retrieve a token 
func getTokenFromCookie(r *http.Request) (token string) {
	//defer timeTrack(time.Now(), "GetUsername")
    s, _ := CookieHandler.Get(r, "session")
    token, ok := s.Values["token"].(string)
    if !ok {
        
    }
    return token
}

// Retrieve username from context
func GetUsername(r *http.Request) (username string) {
	//defer timeTrack(time.Now(), "GetUsername")
    u, ok := context.GetOk(r, UserKey)
    if !ok {
        utils.Debugln("No username in context.")
        u = ""
    }
	return u.(string)
}

// Retrieve token from context
func GetToken(r *http.Request) (token string) {
	//defer timeTrack(time.Now(), "GetUsername")
    t, ok := context.GetOk(r, TokenKey)
    if !ok {
        utils.Debugln("No token in context.")
        t = ""
    }
    return t.(string)
}

func genToken(w http.ResponseWriter, r *http.Request) (token string) {
    token = utils.RandKey(32)
    SetSession("token", token, w, r)
    utils.Debugln("genToken: "+token)
    return token     
}

// Only set a new token if one doesn't already exist
func setToken(w http.ResponseWriter, r *http.Request) (token string) {
    s, _ := CookieHandler.Get(r, "session")
    token, ok := s.Values["token"].(string)
    if !ok {
        token = utils.RandKey(32)
        SetSession("token", token, w, r)
        utils.Debugln("new token generated")
    }
    utils.Debugln("setToken: " + token)
    context.Set(r, TokenKey, token)
    return token
}

// Given an http.Request with a token input, compare it to the token in the session cookie
func CheckToken(w http.ResponseWriter, r *http.Request) error {
    flashToken := GetToken(r)
    tmplToken := r.FormValue("token")
    //log.Println("flashToken: "+flashToken)
    //log.Println("tmplToken: "+tmplToken) 
    if tmplToken == "" {
		//http.Error(w, "CSRF Blank.", 500)
		utils.Debugln("**CSRF blank**")
		return fmt.Errorf("CSRF Blank! flashToken: %s tmplToken: %s", flashToken, tmplToken)
    }
    if tmplToken != flashToken {
		//http.Error(w, "CSRF error!", 500)
		utils.Debugln("**CSRF mismatch!**")
		return fmt.Errorf("CSRF Mismatch! flashToken: %s tmplToken: %s", flashToken, tmplToken)       
    }
    // Generate a new CSRF token after this one has been used
    newToken := utils.RandKey(32)
    SetSession("token", newToken, w, r)
    utils.Debugln("newToken: "+newToken) 
    return nil
}

//AdminUserPostHandler only handles POST requests, using forms named "username" and "password"
// Signing up users as necessary, inside the AuthConf
func AdminUserPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
		case "GET":
        case "POST":
			username := template.HTMLEscapeString(r.FormValue("username"))
			password := template.HTMLEscapeString(r.FormValue("password"))
            role := r.FormValue("role")
            err := newUser(username, password, role)
            if err != nil {
                utils.Debugln(err)
                panic(err)
            }
            
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
func SignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
		case "GET":
        case "POST":
			username := template.HTMLEscapeString(r.FormValue("username"))
			password := template.HTMLEscapeString(r.FormValue("password"))
            role := "User"
            err := newUser(username, password, role)
            if err != nil {
                utils.Debugln(err)
                panic(err)
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
// Comparing values with LDAP or configured username/password combos
func LoginPostHandler(cfg AuthConf, w http.ResponseWriter, r *http.Request) {

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
            //log.Println(cfg)
			// Handle login POST request
			username := template.HTMLEscapeString(r.FormValue("username"))
			password := template.HTMLEscapeString(r.FormValue("password"))
            referer, err := url.Parse(r.Referer())
            if err != nil {
                utils.Debugln(err)
            }
            
            // Check if we have a ?url= query string, from AuthMiddle
            // Otherwise, just use the referrer 
            var r2 string
            r2 = referer.Query().Get("url")
            if r2 == "" {
               utils.Debugln("referer is blank")
               r2 = r.Referer()
            }
			//log.Println(r.FormValue("username"))
			//log.Println(r.FormValue("password"))
            
            // CSRF check
            //CheckToken(w, r)
			
			// Login authentication
			// Check if LDAP is enabled
			if cfg.LdapEnabled {
				if ldapAuth(cfg, username, password) || jsonAuth(cfg, username, password) {	
					SetSession("user", username, w, r)
					utils.Debugln(username + " successfully logged in.")
                    writeJ(w, r, r2, true)
					//loginRedir(w, r, r2)
                    return
				} else {
					writeJ(w, r, "", false)
                    return
				}		
			} else if jsonAuth(cfg, username, password){	
				SetSession("user", username, w, r)
				utils.Debugln(username + " successfully logged in.")
                writeJ(w, r, r2, true)
                //loginRedir(w, r, r2)
                return
			} else {
				writeJ(w, r, "", false)
                return
			}	
		case "PUT":
			// Update an existing record.
		case "DELETE":
			// Remove the record.
		default:
			// Give an error message.
	}
	

}

func ldapAuth(cfg AuthConf, un, pw string) bool {
	//Build DN: uid=admin,ou=People,dc=example,dc=com
	dn := cfg.LdapUn+"="+un+",ou="+cfg.LdapOu+","+cfg.LdapDn
	l := ldap.NewLDAPConnection(cfg.LdapUrl, cfg.LdapPort)
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

func jsonAuth(cfg AuthConf, username, password string) bool {
    hashedUserPass := cfg.Users[username]

    // newHash and err should be blank/nil on success
    newHash, err := passlib.Verify(password, hashedUserPass)
    if err != nil {
        // Incorrect password, malformed hash, etc.
        utils.Debugln(err)
        return false
    }

    if newHash != "" {
        // passlib thinks we should upgrade to a new stronger hash.
        // ... store the new hash in the database ...
        utils.Debugln("newHash isn't empty... " + newHash)
        err := updatePass(username, newHash)
        if err != nil {
            utils.Debugln(err)
            return false
        }
    }
    utils.Debugln("Authenticated via JSON")
    return true
    
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ClearSession(w, r)
	utils.Debugln("Logout")
	http.Redirect(w, r, r.Referer(), 302)
}

// Failures should be handled by this, sending back JSON data to be handled in a small banner on the page.
func writeJ(w http.ResponseWriter, r *http.Request, name string, success bool) error {
    j := jsonresponse{
        Name:    name,
        Success: success,
    }
    json, err := makeJSON(w, j)
    if err != nil {
        return err
    }
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.WriteHeader(200)
    w.Write(json)
    return nil
}

// Redirect back to given page after successful login.
// Failure should be handled by JS, taking advantage of writeJ func above.
func loginRedir(w http.ResponseWriter, r *http.Request, name string) {
    if name != "" {
        http.Redirect(w, r, name, http.StatusFound)
    }
    writeJ(w, r, "", true)
}

func makeJSON(w http.ResponseWriter, data interface{}) ([]byte, error) {
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return nil, err
	}
	//Debugln(string(jsonData))
	return jsonData, nil
}

// Dedicated function to create new users, taking plaintext username, password, and role
//  Hashing done in this function, no need to do it elsewhere
func newUser(username, password, role string) error {
    hash, err := passlib.Hash(password)
    if err != nil {
        // couldn't hash password for some reason
        log.Fatalln(err)
        return err
    }
    
    // If no existing user, store username and hash
    //authcfg.Users = make(map[string]string)
    cfgUser := Authcfg.Users[username]
    if cfgUser == "" {
        Authcfg.Users[username] = hash
        Authcfg.Roles[username] = role
        j, _ := json.MarshalIndent(Authcfg, "", "    ")
        //log.Println(authcfg.Users)
        //log.Println(j)
        authjson, _ := os.OpenFile("auth.json", os.O_RDWR|os.O_CREATE, 0660)
        _, err := authjson.Write(j)
        if err != nil {
            return err
        }
        return nil
    }
    return nil
}

func updatePass(username, hash string) error {
    cfgUser := Authcfg.Users[username]
    // Only update existing user's passwords
    if cfgUser == "" {
        passErr := errors.New("Attempting to update password of unknown user" + username)
        utils.Debugln(passErr)
        return passErr
    }
    Authcfg.Users[username] = hash
    j, _ := json.MarshalIndent(Authcfg, "", "    ")
    utils.Debugln(j)
    authjson, _ := os.OpenFile("auth.json", os.O_RDWR|os.O_CREATE, 0660)
    _, err := authjson.Write(j)
    if err != nil {
        return err
    }
    return nil
}

//XsrfMiddle is a middleware that tries (no guarantees) to protect against Cross-Site Request Forgery
// On GET requests, it 
func XsrfMiddle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check if there's an existing xsrf
        // If not, generate one in the cookie
        reqID := setToken(w, r)
        utils.Debugln("reqID: "+reqID)
        switch r.Method {
            case "GET":
                context.Set(r, TokenKey, reqID)
                next.ServeHTTP(w, r) 
            case "POST":
                tmplToken := r.FormValue("token")
                utils.Debugln("POST: flashToken: "+reqID)
                utils.Debugln("POST: tmplToken: "+tmplToken)
                // Actually check CSRF token, since this is a POST request
                if tmplToken == "" {
                    http.Error(w, "CSRF Blank.", 500)
                    utils.Debugln("**CSRF blank**")
                    return
                }
                if tmplToken != reqID {
                    http.Error(w, "CSRF error!", 500)
                    utils.Debugln("**CSRF mismatch!**")
                    return        
                }
                
                // If this is a POST request, and the tokens match, generate a new one
                newToken := utils.RandKey(32)
                SetSession("token", newToken, w, r)
                utils.Debugln("newToken: "+newToken)
                
                next.ServeHTTP(w, r)
            case "PUT":
            
                next.ServeHTTP(w, r)
            case "DELETE":
            
                next.ServeHTTP(w, r)
            default:
            
                next.ServeHTTP(w, r)
        }

	})
}

func AuthMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//username := getUsernameFromCookie(r)
        username := GetUsername(r)
		if username == "" {
            rurl := r.URL.String()
			utils.Debugln("AuthMiddleware mitigating: " + r.Host + rurl)
			//w.Write([]byte("OMG"))
            
            // Detect if we're in an endless loop, if so, just panic
            if strings.HasPrefix(rurl, "login?url=/login") {
                panic("AuthMiddle is in an endless redirect loop")
                return
            }
			http.Redirect(w, r, "http://"+r.Host+"/login"+"?url="+rurl, 302)
			return
		}
		utils.Debugln(username + " is visiting " + r.Referer())
        //context.Set(r, UserKey, username) 
		next.ServeHTTP(w, r)
	})
}

func AuthAdminMiddle(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//username := getUsernameFromCookie(r)
        username := GetUsername(r)
		if username == "" {
            rurl := r.URL.String()
			utils.Debugln("AuthAdminMiddleware mitigating: " + r.Host + rurl)
			//w.Write([]byte("OMG"))
            
            // Detect if we're in an endless loop, if so, just panic
            if strings.HasPrefix(rurl, "login?url=/login") {
                panic("AuthAdminMiddle is in an endless redirect loop")
                return
            }
			http.Redirect(w, r, "http://"+r.Host+"/login"+"?url="+rurl, 302)
			return
		}
        _, prs := Authcfg.Roles[username]
        if !prs {
            w.Write([]byte("YOU ARE NOT AN ADMIN"))
            return
        }
        
		utils.Debugln(username + " is visiting " + r.Referer())
        utils.Debugln(username)
        //context.Set(r, UserKey, username) 
		next.ServeHTTP(w, r)
	})
}

//UserEnvMiddle grabs username from cookie, tosses it into the context for use in various other middlewares
func UserEnvMiddle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := getUsernameFromCookie(r)
		//log.Println(username + " is visiting " + r.Referer())
        //log.Println(username)
        context.Set(r, UserKey, username) 
		next.ServeHTTP(w, r)
	})
}


func AuthCookieMiddle(next http.HandlerFunc) http.HandlerFunc {
	handler := func(w http.ResponseWriter, r *http.Request) {
		username := getUsernameFromCookie(r)
		if username == "" {
			utils.Debugln("AuthMiddleware mitigating: " + r.Host + r.URL.String())
			//w.Write([]byte("OMG"))
			http.Redirect(w, r, "http://"+r.Host+"/login"+"?url="+r.URL.String(), 302)
			return
		}
		utils.Debugln(username + " is visiting " + r.Referer())
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(handler)
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
