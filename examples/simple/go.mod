module simple-auth

go 1.17

replace git.jba.io/go/auth/v2 => /home/aqtrans/go/src/git.jba.io/go/auth

require (
	git.jba.io/go/auth/v2 v2.0.0-beta.2
	github.com/go-chi/chi/v5 v5.0.7
)

require (
	github.com/alexedwards/scs/boltstore v0.0.0-20211203064041-370cc303b69f // indirect
	github.com/alexedwards/scs/v2 v2.5.0 // indirect
	github.com/gorilla/csrf v1.7.1 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	golang.org/x/crypto v0.0.0-20220112180741-5e0467b6c7ce // indirect
	golang.org/x/sys v0.0.0-20220114195835-da31bd327af9 // indirect
)
