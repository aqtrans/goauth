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
	authState := NewBoltAuthState(tmpdb)

	defer os.Remove(tmpdb)

	_, err := authState.Userlist()
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
	if !authState.Auth("adminTest", "test") {
		t.Fatal("ERR: cannot login for some reason!")
	}
	if authState.Auth("adminTest2", "test") {
		t.Fatal("ERR: non-existent user can login for some reason!")
	}
	if authState.Auth("adminTest", "test2") {
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
	if !authState.Auth("adminTest", "test2") {
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

	userState := GetUserState(ctx)
	if userState != nil {
		t.Error("userState from context is not nil")
	}

	if IsLoggedIn(ctx) {
		t.Error("IsLoggedIn from context is not false")
	}

	userState2 := GetUserState(ctx)
	if userState2 != nil {
		t.Error("userState2.username has something in it")
	}

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)
	authState.NewAdmin("admin", "admin")

	ctx = authState.NewUserInContext(ctx, "admin")

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

	f := &flash{
		Msg: "message",
	}
	ctx = f.NewFlashInContext(ctx)

	msgC := GetFlash(ctx)
	if msgC != f.Msg {
		t.Error("msgC does not equal f.Msg")
	}

}

func TestCookies(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
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
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	// Attempt a bad login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
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
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
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

func TestInvalidRole(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	err := authState.newUser("admin", "admin", "omg")
	if err == nil {
		t.Error("Role 'omg' was considered valid to state.newUser()!")
	}
}

func TestClearSession(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	request.Form = url.Values{}
	request.Form.Add("username", "admin")
	request.Form.Add("password", "admin")
	authState.LoginPostHandler(w, request)

	// After a good login, copy Cookie into a new request
	request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap that should then come back Expired and such
	w2 := httptest.NewRecorder()

	authState.LogoutHandler(w2, request)

	request.Header = http.Header{"Cookie": w2.HeaderMap["Set-Cookie"]}

	finalRequest := &http.Request{Header: http.Header{"Cookie": w2.HeaderMap["Set-Cookie"]}}
	cookie, err := finalRequest.Cookie("user")
	if err != nil {
		t.Error(err)
	}

	if cookie.Value != "" {
		t.Error("Cookie value for user still exists after LogoutHandler: ", cookie.Value)
	}

	/* TODO: Once I'm using some CONSTs for returned cookie flash messages, check for that "flash" returns ErrFailedLogin or whatever it is
	if authState.ReadSession("flash", w, request) != "testing" {
		t.Error("Flash message was not a failed login message")
	}
	*/

}

func TestReadSession(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Form = url.Values{}
	request.Form.Add("username", "admin")
	request.Form.Add("password", "admin")
	authState.LoginPostHandler(w, request)

	// After a good login, copy Cookie into a new request
	request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

	user := authState.getUsernameFromCookie(request, w)
	if user != "admin" {
		t.Error("getUsernameFromCookie did not properly return admin: ", user)
	}

	/* TODO: Once I'm using some CONSTs for returned cookie flash messages, check for that "flash" returns ErrFailedLogin or whatever it is
	if authState.ReadSession("flash", w, request) != "testing" {
		t.Error("Flash message was not a failed login message")
	}
	*/

}

func TestReadUserInfo(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	err := authState.NewAdmin("admin", "admin")
	if err != nil {
		t.Error("Error adding NewAdmin(): ", err)
	}

	admin := authState.getUserInfo("admin")
	if admin == nil {
		t.Error("admin.User{} retrieved is nil.")
	}
	if !admin.IsAdmin() {
		t.Error("admin.IsAdmin() did not return true.")
	}
	if admin.GetName() != "admin" {
		t.Error("admin.GetName() did not return admin.")
	}

	err = authState.NewUser("user", "12345")
	if err != nil {
		t.Error("Error adding NewUser: ", err)
	}

	user := authState.getUserInfo("user")
	if user == nil {
		t.Error("user.User{} retrieved is nil.")
	}
	if user.IsAdmin() {
		t.Error("user.IsAdmin() did not return false.")
	}
	if user.GetName() != "user" {
		t.Error("user.GetName() did not return user.")
	}

	userList, err := authState.Userlist()
	if err != nil {
		t.Error("Error retrieving Userlist(): ", err)
	}
	if userList == nil {
		t.Error("Userlist() is nil.")
	}

}

func TestRedirect(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("GET", "/index", nil)
	Redirect(authState, w, request)

	// After a good login, copy Cookie into a new request
	request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

	finalRequest := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
	cookie, err := finalRequest.Cookie("redirect")
	if err != nil {
		t.Error(err)
	}

	if cookie.Value == "" {
		t.Error("Cookie value for redirect is blank even after Redirect(): ", cookie.Value)
	}
}

func TestAuthMiddle1(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Form = url.Values{}
	request.Form.Add("username", "admin")
	request.Form.Add("password", "admin")
	authState.LoginPostHandler(w, request)

	// After a good login, copy Cookie into a new request
	request2, err := http.NewRequest("GET", "/index", nil)
	request2.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap
	w2 := httptest.NewRecorder()

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})

	handler := authState.UserEnvMiddle(authState.AuthMiddle(test))
	handler.ServeHTTP(w2, request2)

	if w2.Header().Get("Location") == "/login" {
		t.Log(w2.HeaderMap)
		t.Error("AuthMiddle redirected to /login even after successful login.")
	}

	/*
		// After a good login, copy Cookie into a new request
		request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

		finalRequest := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
		cookie, err := finalRequest.Cookie("redirect")
		if err != nil {
			t.Error(err)
		}

		if cookie.Value == "" {
			t.Error("Cookie value for redirect is blank even after Redirect(): ", cookie.Value)
		}
	*/
}

func TestAuthMiddle2(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("GET", "/index", nil)
	if err != nil {
		t.Fatal(err)
	}

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})
	t.Log(w.HeaderMap)

	handler := authState.UserEnvMiddle(authState.AuthMiddle(test))
	handler.ServeHTTP(w, request)

	if w.Header().Get("Location") != "/login" {
		t.Log(w.HeaderMap)
		t.Error("AuthMiddle did not redirect to /login")
	}

	/*
		// After a good login, copy Cookie into a new request
		request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

		finalRequest := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
		cookie, err := finalRequest.Cookie("redirect")
		if err != nil {
			t.Error(err)
		}

		if cookie.Value == "" {
			t.Error("Cookie value for redirect is blank even after Redirect(): ", cookie.Value)
		}
	*/
}

func TestAuthAdminMiddle1(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Form = url.Values{}
	request.Form.Add("username", "admin")
	request.Form.Add("password", "admin")
	authState.LoginPostHandler(w, request)

	// After a good login, copy Cookie into a new request
	request2, err := http.NewRequest("GET", "/index", nil)
	request2.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap
	w2 := httptest.NewRecorder()

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})

	handler := authState.UserEnvMiddle(authState.AuthAdminMiddle(test))
	handler.ServeHTTP(w2, request2)

	if w2.Header().Get("Location") == "/login" {
		t.Log(w2.HeaderMap)
		t.Error("AuthAdminMiddle redirected to /login even after successful login.")
	}

	/*
		// After a good login, copy Cookie into a new request
		request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

		finalRequest := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
		cookie, err := finalRequest.Cookie("redirect")
		if err != nil {
			t.Error(err)
		}

		if cookie.Value == "" {
			t.Error("Cookie value for redirect is blank even after Redirect(): ", cookie.Value)
		}
	*/
}

func TestAuthAdminMiddle2(t *testing.T) {

	tmpdb := tempfile()
	authState := NewBoltAuthState(tmpdb)
	defer os.Remove(tmpdb)

	authState.NewUser("user", "12345")

	// Attempt a good login
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Form = url.Values{}
	request.Form.Add("username", "user")
	request.Form.Add("password", "12345")
	authState.LoginPostHandler(w, request)

	// After a good login, copy Cookie into a new request
	request2, err := http.NewRequest("GET", "/index", nil)
	if err != nil {
		t.Fatal(err)
	}
	request2.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap
	w2 := httptest.NewRecorder()

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})

	handler := authState.UserEnvMiddle(authState.AuthAdminMiddle(test))
	handler.ServeHTTP(w2, request2)

	if w2.Header().Get("Location") != "/" {
		t.Log(w2.HeaderMap)
		t.Error("AuthAdminMiddle did not redirect to / when user tried to access protected page.")
	}

	/*
		// After a good login, copy Cookie into a new request
		request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

		finalRequest := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}
		cookie, err := finalRequest.Cookie("redirect")
		if err != nil {
			t.Error(err)
		}

		if cookie.Value == "" {
			t.Error("Cookie value for redirect is blank even after Redirect(): ", cookie.Value)
		}
	*/
}
