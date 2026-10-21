module github.com/vivshankar/tools-go

go 1.26.0

require (
	github.com/go-jose/go-jose/v4 v4.1.6
	github.com/google/uuid v1.6.0
	github.com/ibm-verify/verify-auth-go v0.0.0-00010101000000-000000000000
	github.com/jellydator/ttlcache/v3 v3.4.1
	github.com/stretchr/testify v1.11.1
)

require (
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/gorilla/mux v1.8.1
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ibm-verify/verify-auth-go => ../../ibm-verify/verify-auth-go
