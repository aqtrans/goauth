package auth

import (
	"github.com/boltdb/bolt"
	"io/ioutil"
	"os"
	"testing"
)

type AuthDB struct {
	*DB
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

// MustOpenDB returns a new, open DB at a temporary location.
func mustOpenDB() *AuthDB {
	tmpdb, err := bolt.Open(tempfile(), 0666, nil)
	if err != nil {
		panic(err)
	}
	return &AuthDB{&DB{tmpdb}}
}

func (tmpdb *AuthDB) Close() error {
	//log.Println(tmpdb.Path())
	defer os.Remove(tmpdb.Path())
	return tmpdb.DB.Close()
}

func (tmpdb *AuthDB) MustClose() {
	if err := tmpdb.Close(); err != nil {
		panic(err)
	}
}

func TestBolt(t *testing.T) {
	authDB := mustOpenDB()
	authState, err := NewAuthStateWithDB(authDB.DB, tempfile(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer authDB.Close()
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
