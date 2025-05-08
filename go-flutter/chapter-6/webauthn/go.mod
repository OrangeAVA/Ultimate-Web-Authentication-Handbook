module wauthn_demo

go 1.24.2

toolchain go1.24.3

require github.com/go-webauthn/webauthn v0.8.2

require (
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.36.0 // indirect
)

require (
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/go-webauthn/revoke v0.1.9 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.31.0 // indirect
	howa.in/common v0.0.0-00010101000000-000000000000
)

replace howa.in/common => ../../common
