package auth

import (
	"errors"
	fmt "fmt"
	"log"
	"time"

	"github.com/boltdb/bolt"
	proto "github.com/golang/protobuf/proto"
)

const (
	// Buckets for boltDB
	authInfoBucketName     = "AuthInfo"
	hashKeyName            = "HashKey"
	blockKeyName           = "BlockKey"
	userInfoBucketName     = "Users"
	registerKeysBucketName = "RegisterKeys"
)

// DB wraps a bolt.DB struct, so I can test and interact with the db from programs using the lib, while vendoring bolt in both places
type DB struct {
	authdb *bolt.DB
	path   string
}

func (db *DB) getDB() *bolt.DB {
	//var authDB *bolt.DB
	//log.Println(state.BoltDB.path)
	var err error
	db.authdb, err = bolt.Open(db.path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		check(err)
		log.Fatalln(err)
		return nil
	}
	return db.authdb
}

func (db *DB) releaseDB() {
	err := db.authdb.Close()
	if err != nil {
		check(err)
		log.Fatalln(err)
	}
}

func (db DB) init() {
	db.dbInit()
}

func (db DB) dbInit() {
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		registerKeyBucket, err := tx.CreateBucketIfNotExists([]byte(registerKeysBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		userBucket, err := tx.CreateBucketIfNotExists([]byte(userInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		// Check if no users exist. If so, generate a registration key
		if userBucket.Stats().KeyN == 0 {
			// Clear all existing register keys, likely due to failed app startups:
			err := registerKeyBucket.ForEach(func(key, value []byte) error {
				err := registerKeyBucket.Delete(key)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}

			log.Println("No users exist. Generating new register key to register a new admin user...")
			token := randString(12)
			err = registerKeyBucket.Put([]byte(token), []byte(roleAdmin))
			if err != nil {
				check(err)
				return err
			}
			log.Println("Use this register key on your signup page: " + token)
		}

		infobucket, err := tx.CreateBucketIfNotExists([]byte(authInfoBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		hashKey := infobucket.Get([]byte(hashKeyName))
		if hashKey == nil {
			debugln("Throwing hashkey into auth.db.")
			// Generate a random hashKey
			hashKey := randBytes(64)

			err = infobucket.Put([]byte(hashKeyName), hashKey)
			if err != nil {
				check(err)
				return err
			}
		}

		blockKey := infobucket.Get([]byte(blockKeyName))
		if blockKey == nil {
			debugln("Throwing blockkey into auth.db.")
			// Generate a random blockKey
			blockKey := randBytes(32)

			err = infobucket.Put([]byte(blockKeyName), blockKey)
			if err != nil {
				check(err)
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Fatalln("Error in dbInit():", err)
	}
}

func (db DB) getAuthInfo() authInfo {
	boltDB := db.getDB()
	defer db.releaseDB()

	var hashkey []byte
	var blockkey []byte

	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(authInfoBucketName))
		v1 := b.Get([]byte(hashKeyName))
		v2 := b.Get([]byte(blockKeyName))
		hashkey = make([]byte, len(v1))
		blockkey = make([]byte, len(v2))
		copy(hashkey, v1)
		copy(blockkey, v2)
		return nil
	})
	if err != nil {
		check(err)
		return authInfo{[]byte(""), []byte("")}
	}
	return authInfo{
		hashKey:  hashkey,
		blockKey: blockkey,
	}
}

// NewUser creates a new user with a given plaintext username and password
func (db DB) NewUser(username, password string) error {
	return db.newUser(username, password, roleUser)
}

// NewAdmin creates a new admin with a given plaintext username and password
func (db DB) NewAdmin(username, password string) error {
	return db.newUser(username, password, roleAdmin)
}

// newUser is a dedicated function to create new users, taking plaintext username, password, and role
//  Hashing done in this function, no need to do it before
func (db DB) newUser(username, password, role string) error {

	// Check that the given role is valid before even opening the DB
	roleEnum, ok := User_Role_value[role]
	if !ok {
		return errors.New("NewUser role is invalid: " + role)
	}

	// Same for hasing; Hash password now so if it fails we catch it before touching Bolt
	hash, err := HashPassword([]byte(password))
	if err != nil {
		// couldn't hash password for some reason
		check(err)
		return err
	}

	u := &User{
		Name:     username,
		Password: hash,
		Role:     User_Role(roleEnum),
	}

	userEncoded, err := proto.Marshal(u)
	if err != nil {
		check(err)
		return err
	}

	boltdb := db.getDB()
	defer db.releaseDB()
	//var vb []byte
	adderr := boltdb.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte("Users"))

		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser != nil {
			return errors.New("User already exists")
		}

		err = userbucket.Put([]byte(username), userEncoded)
		if err != nil {
			return err
		}

		return nil
	})

	if adderr != nil {
		return adderr
	}

	return nil
}

// Userlist lists all users in the DB
func (db DB) Userlist() ([]string, error) {
	boltdb := db.getDB()
	defer db.releaseDB()

	var userList []string
	err := boltdb.View(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte(userInfoBucketName))
		err := userbucket.ForEach(func(key, value []byte) error {
			//fmt.Printf("A %s is %s.\n", key, value)
			user := string(key)
			userList = append(userList, user)
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	return userList, err
}

// DeleteUser deletes a given user from the DB
func (db DB) DeleteUser(username string) error {
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.Update(func(tx *bolt.Tx) error {
		log.Println(username + " has been deleted")
		return tx.Bucket([]byte(userInfoBucketName)).Delete([]byte(username))
	})
	if err != nil {
		return err
	}
	return err
}

// UpdatePass updates a given user's password to the given hash
// Password hashing must be done by the caller
func (db DB) UpdatePass(username string, hash []byte) error {
	boltdb := db.getDB()
	defer db.releaseDB()

	// Update password only if user exists
	err := boltdb.Update(func(tx *bolt.Tx) error {
		userbucket := tx.Bucket([]byte(userInfoBucketName))
		userbucketUser := userbucket.Get([]byte(username))

		// userbucketUser should be nil if user doesn't exist
		if userbucketUser == nil {
			return errors.New(errUserDoesNotExist)
		}

		var u User
		err := proto.Unmarshal(userbucketUser, &u)
		if err != nil {
			check(err)
			return err
		}

		u.Password = hash

		encoded, err := proto.Marshal(&u)
		if err != nil {
			log.Println(err)
			return err
		}

		err = userbucket.Put([]byte(username), encoded)
		if err != nil {
			return err
		}
		log.Println("User " + username + " has changed their password.")
		return nil
	})
	return err
}

// Auth authenticates a given username and password
func (db DB) Auth(username, password string) bool {

	boltdb := db.getDB()
	defer db.releaseDB()

	var u User
	// Grab given user's password from Bolt
	err := boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return errors.New(errUserDoesNotExist)
		}

		err := proto.Unmarshal(v, &u)
		if err != nil {
			check(err)
			return err
		}
		err = CheckPasswordHash(u.Password, []byte(password))
		if err != nil {
			// Incorrect password, malformed hash, etc.
			debugln("error verifying password for user", username, err)
			return err
		}
		return nil
	})

	if err != nil {
		// Incorrect password, malformed hash, etc.
		debugln("error verifying password for user", username, err)
		return false
	}
	// TODO: Should look into fleshing this out
	return true
}

func (db DB) UserExists(username string) bool {
	return db.DoesUserExist(username)
}

// DoesUserExist checks if user actually exists in the DB
func (db DB) DoesUserExist(username string) bool {
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return errors.New(errUserDoesNotExist)
		}
		return nil
	})
	if err == nil {
		return true
	}
	if err != nil && err != errors.New(errUserDoesNotExist) {
		check(err)
		return false
	}
	return false
}

// GetUserInfo gets a *User from the DB
func (db DB) getUserInfo(username string) *User {
	var u User
	boltdb := db.getDB()
	defer db.releaseDB()

	err := boltdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(userInfoBucketName))
		v := b.Get([]byte(username))
		if v == nil {
			return errors.New(errUserDoesNotExist)
		}
		err := proto.Unmarshal(v, &u)
		if err != nil {
			check(err)
			return err
		}
		return nil
	})
	if err != nil {
		check(err)
		return nil
	}
	return &u

	/*
		s := &Shorturl{
			Created: shorturl.Created,
			Short:   shorturl.Short,
			Long:    shorturl.Long,
			Hits:    shorturl.Hits + 1,
		}
		encoded, err := json.Marshal(s)
		if err != nil {
			log.Println(err)
			return err
		}

		return b.Put([]byte(title), encoded)
	*/

}

// GenerateRegisterToken generates a token to register a user, and only a user
func (db DB) GenerateRegisterToken(role string) string {
	switch role {
	case roleAdmin, roleUser:
	default:
		log.Println("GenerateRegisterToken role is invalid: " + role)
		role = roleUser
	}

	token := randString(12)
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		registerBucket, err := tx.CreateBucketIfNotExists([]byte(registerKeysBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		err = registerBucket.Put([]byte(token), []byte(role))
		if err != nil {
			check(err)
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("Error putting register token into DB:", err)
	}
	return token
}

// ValidateRegisterToken validates that a given registration token is valid, exists inside the DB
func (db DB) ValidateRegisterToken(token string) (bool, string) {
	boltDB := db.getDB()
	defer db.releaseDB()

	var userRole []byte

	err := boltDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(registerKeysBucketName))
		v := b.Get([]byte(token))
		if v == nil {
			return errors.New("token does not exist")
		}
		userRole = make([]byte, len(v))
		log.Println("Role:", string(v))
		copy(userRole, v)
		return nil
	})
	if err != nil {
		log.Println(err)
		return false, ""
	}

	return true, string(userRole)
}

// DeleteRegisterToken deletes a registration token
func (db DB) DeleteRegisterToken(token string) {
	boltDB := db.getDB()
	defer db.releaseDB()

	err := boltDB.Update(func(tx *bolt.Tx) error {
		registerBucket, err := tx.CreateBucketIfNotExists([]byte(registerKeysBucketName))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		err = registerBucket.Delete([]byte(token))
		if err != nil {
			check(err)
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalln("Error putting register token into DB:", err)
	}
}
