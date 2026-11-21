module github.com/otuschhoff/gokrb5/v8/examples

go 1.26.0

require (
	github.com/gorilla/sessions v1.4.0
	github.com/jcmturner/goidentity/v6 v6.0.1
	github.com/otuschhoff/gokrb5/v8 v8.0.0
)

require (
	github.com/github/smimesign v0.2.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.58.0 // indirect
)

// These examples are built from a repository checkout, against the local library.
replace github.com/otuschhoff/gokrb5/v8 => ..
