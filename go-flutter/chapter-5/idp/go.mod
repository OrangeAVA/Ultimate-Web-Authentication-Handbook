module idp

go 1.24.2

require (
	github.com/go-oauth2/oauth2/v4 v4.5.2
	github.com/go-session/session v3.1.2+incompatible
)

require golang.org/x/crypto v0.22.0 // indirect

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/tidwall/btree v1.6.0 // indirect
	github.com/tidwall/buntdb v1.3.0 // indirect
	github.com/tidwall/gjson v1.14.4 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	howa.in/common v0.0.0-00010101000000-000000000000
)

replace howa.in/common => ../../common
