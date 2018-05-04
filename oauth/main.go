package main

import (
	"fmt"
	"log"
	"net/http"

	"jba.io/go/auth"
)

var userstate *auth.State

func main() {
	userstate = auth.NewOIDCAuthState("auth.toml", "CLIENT-ID", "SECRET", "http://127.0.0.1:3000/callback")

	auth.Debug = true
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", userstate.GoogleLogin)
	http.HandleFunc("/callback", userstate.GoogleCallback)
	log.Println("listening on port 3000")
	err := http.ListenAndServe("127.0.0.1:3000", nil)
	if err != nil {
		log.Println(err)
	}

}

func handleMain(w http.ResponseWriter, r *http.Request) {
	username := userstate.ReadUsername(w, r)

	if username != "" {
		userInfo := userstate.GetUserInfo(username)
		fmt.Fprintf(w, `<html><body>
			Welcome %v! You are a %v.
			</body></html>`, userInfo.Name, userInfo.Role)
		return
	}

	fmt.Fprintf(w, `<html><body>
			<a href="/login">Log in with Google</a>
			</body></html>`)
	return
}
