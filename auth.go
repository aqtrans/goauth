package auth

//Auth functions

import (
	"github.com/gorilla/securecookie"
	"github.com/mavricknz/ldap"
	//"github.com/gorilla/mux"
	"html/template"
	"log"
	"fmt"
	"net/http"
	//"time"
	"encoding/json"
)

// Pass an Auth subset inside conf.json
/*    
    "AuthConf": {
            "Username": "aqtrans",
            "Password": "8489",
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
	Username string
	Password string
	LdapEnabled bool
	LdapPort uint16 `json:",omitempty"`
	LdapUrl  string `json:",omitempty"`
	LdapDn   string `json:",omitempty"`
	LdapUn   string `json:",omitempty"`
	LdapOu   string `json:",omitempty"`
}

//JSON Response
type jsonresponse struct {
	Name    string `json:"name,omitempty"`
	Success bool   `json:"success"`
}

var	cfg = AuthConf{}

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func AuthConfig(un, pass, ldapport, ldapurl, ldapdn, ldapun string) {

}

func SetSession(username string, w http.ResponseWriter) {
	//defer timeTrack(time.Now(), "SetSession")
	value := map[string]string{
		"user": username,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:     "session",
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	}
}

func ClearSession(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

func GetUsername(r *http.Request) (username string) {
	//defer timeTrack(time.Now(), "GetUsername")
	if cookie, err := r.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			username = cookieValue["user"]
			//log.Println(cookieValue)
		}
	} else {
		username = ""
	}
	//log.Println("GetUsername: "+username)
	return username
}

// GET request: serves a 
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
			log.Println("Referrer: " + r.Referer())
			//log.Println(r.FormValue("username"))
			//log.Println(r.FormValue("password"))
			
			// LDAP
			//if username == cfg.Username && password == cfg.Password {
			// Check if LDAP is enabled
			if cfg.LdapEnabled {
				if ldapAuth(cfg, username, password) || (username == cfg.Username && password == cfg.Password) {	
					SetSession(username, w)
					log.Println(username + " successfully logged in.")
					writeJ(w, "", true)
				} else {
					writeJ(w, "", false)
				}		
			} else if username == cfg.Username && password == cfg.Password {	
				SetSession(username, w)
				log.Println(username + " successfully logged in.")
				writeJ(w, "", true)
			} else {
				writeJ(w, "", false)
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
		log.Println(dn)
		fmt.Printf("LDAP connectiong error: %v", err)
		return false
	}
	defer l.Close()
	err = l.Bind(dn, pw)
	if err != nil {
		log.Println(dn)
		fmt.Printf("error: %v", err)
		return false
	}
	log.Println("Authenticated")
	return true			
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ClearSession(w, r)
	log.Println("Logout")
	http.Redirect(w, r, r.Referer(), 302)
}

func writeJ(w http.ResponseWriter, name string, success bool) error {
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
	//Debugln(string(json))
	return nil
}

func makeJSON(w http.ResponseWriter, data interface{}) ([]byte, error) {
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return nil, err
	}
	//Debugln(string(jsonData))
	return jsonData, nil
}

func Auth(next http.HandlerFunc) http.HandlerFunc {
	handler := func(w http.ResponseWriter, r *http.Request) {
		username := GetUsername(r)
		if username == "" {
			log.Println("AuthMiddleware mitigating: " + r.Host + r.URL.String())
			//w.Write([]byte("OMG"))
			http.Redirect(w, r, "http://"+r.Host+"/login", 302)
			return
		}
		log.Println(username + " is visiting " + r.Referer())
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(handler)
}
