# Golang HTTP authentication library, no catchy name.

This is a library I wrote when I found existing http auth libraries lacking in one area or another.  
Not entirely documented yet, but I've pounded most of the kinks out and felt it was about time to share.  

It's design is based on https://github.com/xyproto/permissionbolt/, initializing a 'state' that is passed  
around to hold the boltDB connection and secureCookie instance.

## Features:  
   - Users and keys are stored inside a `bboltdb`
   - Cookies are authenticated and encrypted using `gorilla/securecookie`
      - The hash and block keys are generated upon DB initialization and stored in the auth.db
   - User registration and authentication
      - Passwords are hashed with bcrypt, using a work factor of 14
      - When logging in, a 128 character session ID is generated and stored in the DB and cookie
      - Optionally, one-time-use registration tokens can be required to sign up
   - Cross-site Request Forgery protection, using the `gorilla/csrf` library is integrated, storing the CSRF key in the same auth.db
   - Flash messages, stored inside a cookie and deleted once read
   - Built-in HTTP handlers are provided for some of the more agnostic POST requests, including: 
      - `LogoutHandler`: clearing the session cookie
      - `UserSignupPostHandler`: provided a `username` and `password` form value, create a new user, and log that user in
      - `UserSignupTokenPostHandler`: provided a `username`, `password`, and `register_key` form value, validate the registration token, create a new user, and log that user in
      - `LoginPostHandler`: provided a `username`, and `password` form value, authenticate and log the user in
      - `NewUserToken`: generate a new registration token

## Example:

There is a simple example application available in `examples/simple/main.go`, showing the basics of integrating this library into an application.
