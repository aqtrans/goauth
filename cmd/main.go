package main

import (
	//"flag"
	"log"

	"github.com/spf13/cobra"
	"jba.io/go/auth"
)

func main() {
	var boltDB string

	/*
		userlist, err := authState.Userlist()
		if err != nil {
			log.Println(err)
		}
		log.Println(userlist)
	*/

	var rootCmd = &cobra.Command{Use: "app"}
	rootCmd.PersistentFlags().StringVarP(&boltDB, "boltDB", "b", "./auth.db", "Path to the auth.db.")

	var cmdAddUser = &cobra.Command{
		Use:   "add [username] [password] [role]",
		Short: "Add a user",
		Long:  `Add a username and password as the given role, either user or admin.`,
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			//log.Println(args[0], args[1], args[2])
			authState := auth.NewAuthState(boltDB)
			if args[2] == "admin" {
				authState.NewAdmin(args[0], args[1])
			}
			if args[2] == "user" {
				authState.NewUser(args[0], args[1])
			}
		},
	}
	var cmdListUsers = &cobra.Command{
		Use:   "list",
		Short: "List users",
		Long:  `List all users in given boltDB.`,
		Run: func(cmd *cobra.Command, args []string) {
			//log.Println(args[0], args[1], args[2])
			authState := auth.NewAuthState(boltDB)
			userList, err := authState.Userlist()
			if err != nil {
				log.Println(err)
			}
			log.Println(userList)
		},
	}

	rootCmd.AddCommand(cmdAddUser, cmdListUsers)
	rootCmd.Execute()
}
