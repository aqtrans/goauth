package main

import (
	"fmt"
	"io/ioutil"
	"jba.io/go/auth"
	"log"
	"net/http"
)

var userstate *auth.State

var oa = auth.BuildOAuthConf()

func main() {
	userstate = auth.NewBoltAuthState("omg.db")
	auth.Debug = true
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/GoogleLogin", handleGoogleLogin)
	http.HandleFunc("/GoogleCallback", handleGoogleCallback)
	fmt.Println(http.ListenAndServe("127.0.0.1:3000", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body>
		<a href="/GoogleLogin">Log in with Google</a>
		</body></html>`)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	b := auth.RandString(8)
	userstate.SetState(b, w)

	url := oa.AuthCodeURL(b)
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
	token, err := oa.Exchange(r.Context(), code)
	if err != nil {
		log.Println("Code exchange failed:", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	client := oa.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Println("Client GET failed:", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	log.Println("Resp body: ", string(data))
}
