package main

/*
Simple example app
`go run main.go` and visit http://127.0.0.1:5000 for an example of signup and flash messages
AnyUsers() is used in the indexHandler to ensure an initial user is registered
No registration tokens are needed to signup
*/

import (
	"log"
	"net/http"

	"git.jba.io/go/auth/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type env struct {
	authState auth.State
}

func (e *env) indexHandler(w http.ResponseWriter, r *http.Request) {

	// AnyUsers() tests if there are any existing users. Useful for initial signup flows.
	if !e.authState.AnyUsers() {
		log.Println("Need to signup...")
		e.authState.SetFlash("Welcome! Sign up to start creating and editing pages.", r)
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	var username string
	user := e.authState.GetUser(r)
	if user != nil {
		username = user.Name
	}

	flashmsg := e.authState.GetFlash(r)

	w.Write([]byte(`
	<html>
	<body>
	<p>Flash:` + flashmsg + `</p>
	Welcome ` + username + `<br>
	<a href="/secret">Users Only</a><br>
	<a href="/login">Login</a><br>
	<a href="/logout">Logout</a>
	`))
}

func (e *env) signupHandler(w http.ResponseWriter, r *http.Request) {
	flashmsg := e.authState.GetFlash(r)
	w.Write([]byte(`
	<html>
	<body>
	<p>Flash:` + flashmsg + `</p>
	<form method="post" action="/signup_post" id="signup">
	<input type="text" id="username" name="username" placeholder="Username" size="12">
	<input type="password" id="password" name="password" placeholder="Password" size="12">
	<button type="submit" class="button">Sign Up</button>
	</form>	
	</body>
	</html>
	`))
}

func (e *env) loginHandler(w http.ResponseWriter, r *http.Request) {
	flashmsg := e.authState.GetFlash(r)
	w.Write([]byte(`
	<html>
	<body>
	<p>Flash:` + flashmsg + `</p>
	<form method="post" action="/login_post" id="login">
	<input type="text" id="username" name="username" placeholder="Username" size="12">
	<input type="password" id="password" name="password" placeholder="Password" size="12">
	<button type="submit" class="button">Login</button>
	</form>	
	</body>
	</html>
	`))
}

func (e *env) secretHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Only Users May View This Page"))
}

func (e *env) loginPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		// Handle login POST request
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Login authentication
		if e.authState.Auth(username, password) {
			e.authState.Login(username, r)
			e.authState.SetFlash("User '"+username+"' successfully logged in.", r)

			// Check if we have a redirect URL in the cookie, if so redirect to it
			redirURL := e.authState.GetRedirect(r)
			if redirURL != "" {
				http.Redirect(w, r, redirURL, http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		e.authState.SetFlash("User '"+username+"' failed to login. Please check your credentials and try again.", r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	case "PUT":
	case "DELETE":
	default:
	}
}

func main() {
	// Bring up authState
	c := auth.Config{
		DbPath:               "./auth.db",
		SessionLifetimeHours: 5,
	}
	a := auth.NewAuthState(c)

	e := &env{
		authState: *a,
	}

	// Set flash message
	//authState.SetFlash("Flash message test...")

	// Add user
	//authState.DB.NewAdmin("admin", "test")

	r := chi.NewRouter()
	r.Use(a.LoadAndSave)
	r.Use(middleware.Logger)
	r.Use(middleware.RequestID)

	r.Get("/", e.indexHandler)
	r.Get("/secret", e.authState.AuthMiddle(e.secretHandler))

	r.Get("/signup", e.signupHandler)
	r.Post("/signup_post", e.UserSignupPostHandler)

	r.Get("/login", e.loginHandler)
	r.Post("/login_post", e.LoginPostHandler)

	r.Get("/logout", e.authState.LogoutHandler)

	log.Println("listening on http://127.0.0.1:5000")
	http.ListenAndServe("127.0.0.1:5000", r)
}
