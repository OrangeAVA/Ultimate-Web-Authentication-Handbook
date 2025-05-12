module howa.in/chapter-4/idp

go 1.24.2

require golang.org/x/crypto v0.36.0

require (
	github.com/crewjam/saml v0.4.13
	github.com/rs/cors v1.9.0
)

require (
	github.com/beevik/etree v1.1.0 // indirect
	github.com/crewjam/httperr v0.2.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.3 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russellhaering/goxmldsig v1.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/zenazn/goji v1.0.1 // indirect
	howa.in/common v0.0.0-00010101000000-000000000000
)

replace howa.in/common => ../../common
