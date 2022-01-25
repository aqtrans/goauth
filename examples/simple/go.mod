module simple-auth

go 1.17

replace git.jba.io/go/auth => /home/aqtrans/go/src/git.jba.io/go/auth

require (
	git.jba.io/go/auth v1.2.1
	github.com/dimfeld/httptreemux v5.0.1+incompatible
)

require (
	github.com/go-chi/chi/v5 v5.0.7 // indirect
	github.com/gorilla/csrf v1.7.0 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
)
