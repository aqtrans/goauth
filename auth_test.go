package auth

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"

	//"net/url"
	"os"
	"testing"
)

/*
func init() {
	logrus.SetLevel(logrus.DebugLevel)
}
*/

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
	authState := NewAuthState(tmpdb)

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

func TestCookies(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	w := httptest.NewRecorder()

	authState.setSession("omg", "testing", w)

	request := &http.Request{Header: http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}}

	if authState.readSession("omg", request) != "testing" {
		t.Error("Cookie value is unable to be decoded")
	}

}

func TestFailedLogin(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
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
	authState := NewAuthState(tmpdb)
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

	t.Log(w.HeaderMap["Set-Cookie"])

	if w.Header().Get("Location") != "/" {
		t.Log(w.HeaderMap)
		t.Log(authState.readSession("flash", request))
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
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	err := authState.newUser("admin", "admin", "omg")
	if err == nil {
		t.Error("Role 'omg' was considered valid to state.newUser()!")
	}
}

func TestClearSession(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
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
	authState := NewAuthState(tmpdb)
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
	authState := NewAuthState(tmpdb)
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
	if admin.Name != "admin" {
		t.Error("admin.Name did not return admin.")
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
	if user.Name != "user" {
		t.Error("user.Name did not return user.")
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
	authState := NewAuthState(tmpdb)
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
	authState := NewAuthState(tmpdb)
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

	handler := authState.AuthMiddle(test)
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
	authState := NewAuthState(tmpdb)
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

	handler := authState.AuthMiddle(test)
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
	authState := NewAuthState(tmpdb)
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

	handler := authState.AuthAdminMiddle(test)
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
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	// Register 2 users, as first will automatically be an admin
	authState.NewUser("firstuser", "12345")
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

	handler := authState.AuthAdminMiddle(test)
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

func TestRegisterKey(t *testing.T) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	token := authState.GenerateRegisterToken("admin")
	valid, role := authState.ValidateRegisterToken(token)
	if !valid {
		t.Error("Generated register token is not valid.")
	}
	if role != "admin" {
		t.Error("Generated token not reporting as an admin token.")
	}
}

func TestRegisterKey2(t *testing.T) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	token := authState.GenerateRegisterToken("Admin")
	// Test to make sure that invalid roles fallback to user
	valid, role := authState.ValidateRegisterToken(token)
	if !valid {
		t.Error("Generated register token is not valid.")
	}
	if role != "user" {
		t.Error("Generated token not reporting as an user token.")
	}
}

func TestUserSignupPostHandler(t *testing.T) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	// Generate a register token
	token := authState.GenerateRegisterToken("admin")

	// Attempt to signup with the token
	w := httptest.NewRecorder()
	request, err := http.NewRequest("POST", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Form = url.Values{}
	request.Form.Add("username", "admin")
	request.Form.Add("password", "admin")
	request.Form.Add("register_key", token)

	authState.UserSignupPostHandler(w, request)

	if w.Code != http.StatusSeeOther {
		t.Error("HTTP response code after signup is not 303:", w.Code)
	}
}

func TestGetCSRFKey(t *testing.T) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	csrfKey := authState.getCSRFKey()
	if len(csrfKey) == 0 {
		t.Error("getCSRFKey returned a 0 length key.")
	}

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})

	h := authState.CSRFProtect(false)
	h(test)

	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	CSRFTemplateField(r)
	/*
		if csrf == template.HTML("") {
			t.Error("CSRFTemplateField is nil")
		}
	*/

	authState.NewUserToken(w, r)
	/*
		if w.Code != http.StatusFound {
			t.Error("HTTP response code is not 200.", w.Code)
		}
	*/
}

func TestUserGetName(t *testing.T) {
	u := &User{}
	name := u.GetName()
	if name != "" {
		t.Error("User.Getname() did not return a blank string.")
	}
}

func BenchmarkNewUser(b *testing.B) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb)

	for i := 0; i < b.N; i++ {
		authState.NewUser("user", "12345")
	}
}
