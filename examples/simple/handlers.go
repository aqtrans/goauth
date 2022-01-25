package main

import (
	"log"
	"net/http"

	"git.jba.io/go/auth"
)

//UserSignupTokenPostHandler only handles POST requests, using forms named "username", "password", and "register_key"
//	This is an alternative to UserSignupPostHandler, adding registration token support
//  That token is verified against the DB before registration
func (e *env) UserSignupTokenPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")
		givenToken := r.FormValue("register_key")

		isValid, userRole := e.authState.ValidateRegisterToken(givenToken)

		if isValid {

			// Delete the token so it cannot be reused if the token is not blank
			// The first user can signup without a token and is granted admin rights
			if givenToken != "" {
				e.authState.DeleteRegisterToken(givenToken)
			}

			if userRole == auth.RoleAdmin {
				err := e.authState.NewAdmin(username, password)
				if err != nil {
					log.Println("Error adding admin:", err)
					e.authState.SetFlash("Error adding user. Check logs.", w)
					http.Redirect(w, r, r.Referer(), http.StatusInternalServerError)
					return
				}
			} else if userRole == auth.RoleUser {
				err := e.authState.NewUser(username, password)
				if err != nil {
					log.Println("Error adding user:", err)
					e.authState.SetFlash("Error adding user. Check logs.", w)
					http.Redirect(w, r, r.Referer(), http.StatusInternalServerError)
					return
				}
			}

			// Login the recently added user
			if e.authState.Auth(username, password) {
				e.authState.Login(username, w)
			}

			e.authState.SetFlash("Successfully added '"+username+"' user.", w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			e.authState.SetFlash("Registration token is invalid.", w)
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
func (e *env) LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		// Handle login POST request
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Login authentication
		if e.authState.Auth(username, password) {
			e.authState.Login(username, w)
			e.authState.SetFlash("User '"+username+"' successfully logged in.", w)
			// Check if we have a redirect URL in the cookie, if so redirect to it
			redirURL := e.authState.GetRedirect(r, w)
			if redirURL != "" {
				http.Redirect(w, r, redirURL, http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		e.authState.SetFlash("User '"+username+"' failed to login. Please check your credentials and try again.", w)
		http.Redirect(w, r, e.authState.Cfg.LoginPath, http.StatusSeeOther)
		return
	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}

// NewUserToken is a convenient handler that generates and provides a new user registration token
func (e *env) NewUserToken(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Write([]byte("User token:" + e.authState.GenerateRegisterToken("user")))
		return
	default:
	}
}

//UserSignupPostHandler only handles POST requests, using forms named "username", "password"
// Signing up users as necessary, inside the AuthConf
func (e *env) UserSignupPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")

		err := e.authState.NewUser(username, password)
		if err != nil {
			log.Println("Error adding user:", err)
			e.authState.SetFlash("Error adding user. Check logs.", w)
			http.Redirect(w, r, r.Referer(), http.StatusInternalServerError)
			return
		}

		// Login the recently added user
		if e.authState.Auth(username, password) {
			e.authState.Login(username, w)
		}

		e.authState.SetFlash("Successfully added '"+username+"' user.", w)
		http.Redirect(w, r, "/", http.StatusSeeOther)

	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}
