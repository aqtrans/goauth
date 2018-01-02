package main

import (
	"flag"
	"log"
	"jba.io/go/auth"
)

func main() {
    var boltDB string
	flag.StringVar(&boltDB, "boltDB", "./auth.db", "Location to the auth.db.")
    var adminUser string
    flag.StringVar(&adminUser, "adminUser", "admin", "User who is considered admin; defined at runtime.")	
	authState, err := auth.NewAuthState(boltDB, adminUser)
	if err != nil {
		log.Println(err)
	}
	userlist, err := authState.Userlist()
	if err != nil {
		log.Println(err)
	}
	log.Println(userlist)
}