package main

import (
	"fmt"
	"log"
	"net/http"

	"jba.io/go/auth"
)

var userstate *auth.GoogleOIDC

func main() {
	userstate = auth.NewOIDCAuthState("omg.toml", "1095755855869-qk6in13jr4ckf604qp59511ossihkqle.apps.googleusercontent.com", "IFriZgF-yDdOsOAQ6W6gDFHD", "http://127.0.0.1:3000/callback")
	userstate.Init()

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
	token := userstate.ReadToken(w, r)
	if userstate.DoesUserExist(token) {
		fmt.Fprintf(w, `<html><body>
			Welcome %v!
			</body></html>`, userstate.GetUserInfo(token).Name)
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

	url := userstate.OIDC.Cfg.AuthCodeURL(b)
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
	token, err := userstate.OIDC.Cfg.Exchange(r.Context(), code)
	if err != nil {
		log.Println("Code exchange failed:", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Println("id_token missing.")
		return
	}

	// Parse and verify ID Token payload.
	idToken, err := userstate.OIDC.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Println("Error verifying rawIDToken:", err)
		return
	}

	// Set the ID token into the "token" securecookie
	userstate.SetToken(rawIDToken, w)

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		log.Println("Error extracting claims:", err)
		return
	}
	log.Println(claims)
	w.Write([]byte(claims.Email))
}
