package auth

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	//"net/url"
	"os"
	"testing"
)

func init() {
	Debug = true
}

// tempfile returns a temporary file path.
func tempfile() string {
	f, err := ioutil.TempFile("", "bolt-")
	if err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}
	if err := os.Remove(f.Name()); err != nil {
		panic(err)
	}
	return f.Name()
}

func TestBolt(t *testing.T) {
	tmpdb := tempfile()
	authState, err := NewAuthState(tmpdb)
	if err != nil {
		t.Fatal(err)
	}
	/*
		var db *bolt.DB
		db, err = authState.getDB()
		if err != nil {
			log.Println(err)
		}
		authState.BoltDB.authdb = db
		authState.BoltDB.path = tmpdb
		defer authState.releaseDB()
	*/
	defer os.Remove(tmpdb)

	_, err = authState.Userlist()
	if err != nil {
		t.Fatal(err)
	}

	err = authState.NewAdmin("adminTest", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !authState.DoesUserExist("adminTest") {
		t.Fatal("ERR: adminTest user does not exist in authState!")
	}
	if !authState.BoltAuth("adminTest", "test") {
		t.Fatal("ERR: cannot login for some reason!")
	}
	if authState.BoltAuth("adminTest2", "test") {
		t.Fatal("ERR: non-existent user can login for some reason!")
	}
	if authState.BoltAuth("adminTest", "test2") {
		t.Fatal("ERR: user can login with bad password for some reason!")
	}

	pass2, err := HashPassword([]byte("test2"))
	if err != nil {
		t.Error(err)
	}
	err = authState.UpdatePass("adminTest", pass2)
	if err != nil {
		t.Error(err)
	}
	if !authState.BoltAuth("adminTest", "test2") {
		t.Fatal("ERR: cannot login after changing password for some reason!")
	}

	err = authState.UpdatePass("adminTest2", pass2)
	if err == nil {
		t.Error("Able to update password for non-existent user")
	}

	err = authState.DeleteUser("adminTest")
	if err != nil {
		t.Fatal(err)
	}
	if authState.DoesUserExist("adminTest") {
		t.Fatal("ERR: adminTest user exists after deleting!")
	}
}

func TestContext(t *testing.T) {
	// Try fetching without anything in the context first
	ctx := context.Background()

	user := GetUserState(ctx)
	if user != nil {
		t.Error("user from context is not nil")
	}

	if IsLoggedIn(ctx) {
		t.Error("IsLoggedIn from context is not false")
	}

	userC1 := GetUserState(ctx)
	if userC1 != nil {
		t.Error("userC1.username has something in it")
	}

	// Now make a context
	u := &User{
		Name: "admin",
		Role: roleAdmin,
	}

	ctx = newUserContext(ctx, u)

	user2 := GetUserState(ctx)
	if user2.GetName() != "admin" {
		t.Error("username2 from context does not equal admin")
	}
	if !user2.IsAdmin() {
		t.Error("isAdmin2 from context is not true")
	}

	if !IsLoggedIn(ctx) {
		t.Error("IsLoggedIn from context is not true")
	}

	userC2 := GetUserState(ctx)
	if userC2.GetName() != "admin" {
		t.Error("userC2.username does not equal admin")
	}

	f := &Flash{
		Msg: "message",
	}
	ctx = newFlashContext(ctx, f)

	msgC := GetFlash(ctx)
	if msgC != f.Msg {
		t.Error("msgC does not equal f.Msg")
	}

}

func TestCookies(t *testing.T) {

	tmpdb := tempfile()
	authState, err := NewAuthState(tmpdb)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpdb)

	w := httptest.NewRecorder()

	authState.setSession("omg", "testing", w)

	request := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}

	if authState.readSession("omg", w, request) != "testing" {
		t.Error("Cookie value is unable to be decoded")
	}

}

func TestFailedLogin(t *testing.T) {

	tmpdb := tempfile()
	authState, err := NewAuthState(tmpdb)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpdb)

	// Attempt a bad login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	request.Form = url.Values{}
	request.Form.Add("username", "admin1")
	request.Form.Add("password", "admin1")
	authState.LoginPostHandler(w, request)
	request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

	//t.Log(w.HeaderMap["Set-Cookie"])

	// Fail if we are not redirected to /login
	if w.Header().Get("Location") != "/login" {
		t.Error("Failed login was not redirected to /login")
	}

	/* TODO: Once I'm using some CONSTs for returned cookie flash messages, check for that "flash" returns ErrFailedLogin or whatever it is
	if authState.ReadSession("flash", w, request) != "testing" {
		t.Error("Flash message was not a failed login message")
	}
	*/

}

func TestSuccessfulLogin(t *testing.T) {

	tmpdb := tempfile()
	authState, err := NewAuthState(tmpdb)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	request.Form = url.Values{}
	request.Form.Add("username", "admin")
	request.Form.Add("password", "admin")
	authState.LoginPostHandler(w, request)
	request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

	//t.Log(w.HeaderMap["Set-Cookie"])

	if w.Header().Get("Location") != "/" {
		t.Log(w.HeaderMap)
		t.Log(authState.readSession("flash", w, request))
		t.Error("Successful login was not redirected to /")
	}

	/* TODO: Once I'm using some CONSTs for returned cookie flash messages, check for that "flash" returns ErrFailedLogin or whatever it is
	if authState.ReadSession("flash", w, request) != "testing" {
		t.Error("Flash message was not a failed login message")
	}
	*/

}

func TestFails(t *testing.T) {
	authState, err := NewAuthState("")
	if err == nil {
		t.Fatal(err)
	}
	if authState != nil {
		t.Error("authState is not nil when fed an empty authdb location")
	}
}
