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
func tempfile() Config {
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
	cfg := Config{
		DbPath: f.Name(),
	}
	return cfg
}

func (authState State) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
	case "POST":
		// Handle login POST request
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Login authentication
		if authState.Auth(username, password) {
			authState.Login(username, r)
			authState.SetFlash("User '"+username+"' successfully logged in.", r)
			// Check if we have a redirect URL in the cookie, if so redirect to it
			redirURL := authState.GetRedirect(r)
			if redirURL != "" {
				http.Redirect(w, r, redirURL, http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		authState.SetFlash("User '"+username+"' failed to login. Please check your credentials and try again.", r)
		http.Redirect(w, r, authState.Cfg.LoginPath, http.StatusSeeOther)
		return
	case "PUT":
		// Update an existing record.
	case "DELETE":
		// Remove the record.
	default:
		// Give an error message.
	}
}

func TestBolt(t *testing.T) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)

	defer os.Remove(tmpdb.DbPath)

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

	err = authState.NewAdmin("adminTest", "test")
	if err == nil {
		t.Error("able to register two users with the same username")
	}

	if !authState.AnyUsers() {
		t.Fatal("AnyUsers is not returning any users")
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

func TestFailedLogin(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	// Attempt a bad login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)

	r.Form = url.Values{}
	r.Form.Add("username", "admin1")
	r.Form.Add("password", "admin1")

	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	r.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}

	//t.Log(w.HeaderMap["Set-Cookie"])

	wanted := authState.Cfg.LoginPath
	got := w.Header().Get("Location")

	// Fail if we are not redirected to authState.Cfg.LoginPath
	if got != wanted {
		t.Errorf("Failed login was not redirected to LoginPath: %v", w.Header().Get("Location"))
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
	defer os.Remove(tmpdb.DbPath)

	username := "admin1"
	password := "admin1"

	err := authState.NewAdmin(username, password)
	if err != nil {
		t.Error(err)
	}

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)

	r.Form = url.Values{}
	r.Form.Add("username", username)
	r.Form.Add("password", password)

	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	r.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}

	if w.Header().Get("Location") != "/" {
		t.Log(w.Result().Header)
		t.Log(authState.GetFlash(r))
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
	defer os.Remove(tmpdb.DbPath)

	err := authState.newUser("admin", "admin", "omg")
	if err == nil {
		t.Error("Role 'omg' was considered valid to state.newUser()!")
	}
}

func TestClearSession(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Form = url.Values{}
	username := "admin1"
	password := "admin1"

	r.Form = url.Values{}
	r.Form.Add("username", username)
	r.Form.Add("password", password)
	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	// After a good login, copy Cookie into a new request
	r.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap that should then come back Expired and such
	w2 := httptest.NewRecorder()

	testHandler2 := http.HandlerFunc(authState.LogoutHandler)
	h2 := authState.LoadAndSave(testHandler2)
	h2.ServeHTTP(w2, r)

	r.Header = http.Header{"Cookie": w2.Result().Header["Set-Cookie"]}

	finalRequest := &http.Request{Header: http.Header{"Cookie": w2.Result().Header["Set-Cookie"]}}
	_, err := finalRequest.Cookie("user")
	if err != nil && err != http.ErrNoCookie {
		t.Error(err)
	}

}

func TestReadSession(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	username := "admin1"
	password := "admin1"

	authState.NewAdmin(username, password)

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Form = url.Values{}
	r.Form.Add("username", username)
	r.Form.Add("password", password)
	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	testHandler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := authState.GetUser(r)
		if user.Name != username {
			t.Error("GetUser did not properly return admin: ", user)
		}
		flash := authState.GetFlash(r)
		if flash != "User 'admin1' successfully logged in." {
			t.Error("Flash message is not a successful login message.")
		}
	})

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}

	h2 := authState.LoadAndSave(testHandler2)
	h2.ServeHTTP(w2, r2)

}

func TestReadUserInfo(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

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
	if admin != nil && admin.Name != "admin" {
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
	if user != nil && user.Name != "user" {
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
	defer os.Remove(tmpdb.DbPath)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/index", nil)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Redirect(authState, w, r)
	})

	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	// After a good login, copy Cookie into a new request
	r.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}

	testHandler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirURL := authState.GetRedirect(r)
		if redirURL != "/index" {
			t.Error("GetRedirect does not return the actual redirect URL.")
		}
	})

	h2 := authState.LoadAndSave(testHandler2)
	h2.ServeHTTP(w, r)

}

func TestAuthMiddle1(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	username := "admin1"
	password := "admin1"

	authState.NewAdmin(username, password)

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Form = url.Values{}
	r.Form.Add("username", username)
	r.Form.Add("password", password)
	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	// After a good login, copy Cookie into a new request
	request2 := httptest.NewRequest("GET", "/index", nil)
	request2.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap
	w2 := httptest.NewRecorder()

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})

	handler := authState.LoadAndSave(authState.UsersOnly(test))
	handler.ServeHTTP(w2, request2)

	if w2.Header().Get("Location") == authState.Cfg.LoginPath {
		t.Log(w2.Result().Header)
		t.Error("UsersOnly redirected to /login even after successful login.")
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
	defer os.Remove(tmpdb.DbPath)

	username := "admin1"
	password := "admin1"

	authState.NewAdmin(username, password)

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Form = url.Values{}
	r.Form.Add("username", username)
	r.Form.Add("password", password)
	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})

	handler := authState.LoadAndSave(authState.UsersOnly(test))
	handler.ServeHTTP(w2, r2)

	if w2.Result().StatusCode != http.StatusOK {
		t.Error("UsersOnly did not allow us through")
	}

}

func TestAuthAdminMiddle1(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	username := "admin1"
	password := "admin1"

	authState.NewAdmin(username, password)

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Form = url.Values{}
	r.Form.Add("username", username)
	r.Form.Add("password", password)
	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	// After a good login, copy Cookie into a new request
	request2 := httptest.NewRequest("GET", "/index", nil)
	request2.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap
	w2 := httptest.NewRecorder()

	if w2.Header().Get("Location") == "/login" {
		t.Log(w2.Result().Header)
		t.Error("AuthAdminMiddle redirected to /login even after successful login.")
	}

}

func TestAuthAdminMiddle2(t *testing.T) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	username := "admin1"
	password := "admin1"

	// Register 2 users, as first will automatically be an admin
	authState.NewUser(username, password)
	authState.NewUser("user", "12345")

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	r.Form = url.Values{}
	r.Form.Add("username", "user")
	r.Form.Add("password", "12345")
	testHandler := http.HandlerFunc(authState.loginHandler)
	h := authState.LoadAndSave(testHandler)
	h.ServeHTTP(w, r)

	request2 := httptest.NewRequest("GET", "/index", nil)

	request2.Header = http.Header{"Cookie": w.Result().Header["Set-Cookie"]}
	// Create a new recorder to get a clean HeaderMap
	w2 := httptest.NewRecorder()

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("omg"))
	})

	handler := authState.LoadAndSave(authState.AdminsOnly(test))
	handler.ServeHTTP(w2, request2)

	if w2.Header().Get("Location") != "/" {
		t.Log(w2.Result().Header)
		t.Error("AdminsOnly did not redirect to / when user tried to access protected page.")
	}
}

func TestRegisterKey(t *testing.T) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	token := authState.GenerateRegisterToken("admin")
	valid, role := authState.ValidateRegisterToken(token)
	if !valid {
		t.Error("Generated register token is not valid.")
	}
	if role != "admin" {
		t.Error("Generated token not reporting as an admin token.")
	}

	authState.DeleteRegisterToken(token)
	valid2, _ := authState.ValidateRegisterToken(token)
	if valid2 {
		t.Error("Token is still valid after being deleted.")
	}
}

func TestRegisterKey2(t *testing.T) {
	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

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
	defer os.Remove(tmpdb.DbPath)

	for i := 0; i < b.N; i++ {
		authState.NewUser("user", "12345")
	}
}

func BenchmarkAuthMiddle(b *testing.B) {

	tmpdb := tempfile()
	authState := NewAuthState(tmpdb)
	defer os.Remove(tmpdb.DbPath)

	authState.NewAdmin("admin", "admin")

	// Attempt a good login
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/index", nil)

	test := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//authState.getUsernameFromCookie(r, w)
		w.Write([]byte("omg"))
	})

	handler := authState.LoadAndSave(authState.UsersOnly(test))

	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, r)
	}

}
