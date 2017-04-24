package auth

import (
	"io/ioutil"
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
	authState, err := NewAuthState(tmpdb, "admin")
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

	err = authState.NewUser("adminTest", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !authState.doesUserExist("adminTest") {
		t.Fatal("ERR: adminTest user does not exist in authState!")
	}
	if !authState.BoltAuth("adminTest", "test") {
		t.Fatal("ERR: cannot login for some reason!")
	}
	err = authState.DeleteUser("adminTest")
	if err != nil {
		t.Fatal(err)
	}
	if authState.doesUserExist("adminTest") {
		t.Fatal("ERR: adminTest user exists after deleting!")
	}
}
