package auth

import (
	"database/sql"

	_ "github.com/cznic/ql/driver"
)

type qlDB struct {
	authdb *sql.DB
	path   string
}
