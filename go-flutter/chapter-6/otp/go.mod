module totp

go 1.24.2

toolchain go1.24.3

require github.com/pquerna/otp v1.4.0

require (
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.36.0 // indirect
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	howa.in/common v0.0.0-00010101000000-000000000000
)

replace howa.in/common => ../../common
