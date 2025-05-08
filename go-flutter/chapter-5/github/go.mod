module gh

go 1.24.2

require (
	github.com/google/uuid v1.3.0
	golang.org/x/oauth2 v0.7.0
)

require golang.org/x/crypto v0.22.0 // indirect

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78
	golang.org/x/net v0.21.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	howa.in/common v0.0.0-00010101000000-000000000000
)
replace howa.in/common => ../../common