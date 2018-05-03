package main

import (
	"fmt"
	"log"
	"net/http"

	"jba.io/go/auth"
)

var userstate *auth.State

func main() {
	userstate = auth.NewOIDCAuthState("omg.toml", "1095755855869-qk6in13jr4ckf604qp59511ossihkqle.apps.googleusercontent.com", "IFriZgF-yDdOsOAQ6W6gDFHD", "http://127.0.0.1:3000/callback")

	auth.Debug = true
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleGoogleLogin)
	http.HandleFunc("/callback", handleGoogleCallback)
	log.Println("listening on port 3000")
	err := http.ListenAndServe("127.0.0.1:3000", nil)
	if err != nil {
		log.Println(err)
	}

}

func handleMain(w http.ResponseWriter, r *http.Request) {
	username := userstate.ReadUsername(w, r)

	if username != "" {
		fmt.Fprintf(w, `<html><body>
			Welcome %v!
			</body></html>`, userstate.GetUserInfo(username).Name)
		return
	}

	fmt.Fprintf(w, `<html><body>
			<a href="/login">Log in with Google</a>
			</body></html>`)
	return
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	b := auth.RandString(8)
	userstate.SetState(b, w)

	url := userstate.GetLoginURL(b)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {

	state := r.FormValue("state")
	expectedState := userstate.ReadState(w, r)

	if state != expectedState {
		log.Println("state and expectedState do not match.", state, expectedState)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	username, err := userstate.VerifyUser(code)
	if err != nil {
		log.Println("Error verifying user:", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	userstate.SetUsername(username, w)

	// Set the ID token into the "token" securecookie
	//userstate.SetToken(rawIDToken, w)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	return
}
