package pku2u

import (
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

type securityContext struct {
	*gssapi.SecurityContext
	credentials *credentials.Credentials
}

// Credentials returns the authenticated peer identity.
func (context *securityContext) Credentials() *credentials.Credentials {
	return context.credentials
}
