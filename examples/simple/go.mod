module simple-auth

go 1.21

toolchain go1.22.0

replace git.jba.io/go/auth/v2 => /home/aqtrans/go/src/git.jba.io/go/auth

require (
	git.jba.io/go/auth/v2 v2.0.0-beta.2
	github.com/go-chi/chi/v5 v5.0.7
)

require (
	github.com/alexedwards/scs/boltstore v0.0.0-20231113091146-cef4b05350c8 // indirect
	github.com/alexedwards/scs/v2 v2.7.0 // indirect
	github.com/gorilla/csrf v1.7.1 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.etcd.io/bbolt v1.3.8 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
