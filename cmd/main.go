package main

import (
	//"flag"

	"log"

	"git.jba.io/go/auth/v2"
	"github.com/spf13/cobra"
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
			} else if args[2] == "user" {
				authState.NewUser(args[0], args[1])
			} else {
				log.Fatalln("Invalid role. admin or user only.", args[2])
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

	var cmdGenerateRegistrationKey = &cobra.Command{
		Use:   "gen [role]",
		Short: "Generate a registration key",
		Long:  `Generate a registration key for a user or admin.`,
		Run: func(cmd *cobra.Command, args []string) {
			//log.Println(args[0], args[1], args[2])
			authState := auth.NewAuthState(boltDB)
			if args[2] == "admin" {
				authState.GenerateRegisterToken(args[2])
			} else if args[2] == "user" {
				authState.GenerateRegisterToken(args[2])
			} else {
				log.Fatalln("Invalid role. admin or user only.", args[2])
			}
		},
	}

	rootCmd.AddCommand(cmdAddUser, cmdListUsers, cmdGenerateRegistrationKey)
	rootCmd.Execute()
}
