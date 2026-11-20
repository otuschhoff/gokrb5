package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	goidentity "github.com/jcmturner/goidentity/v6"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
)

// KRB5BasicAuthenticator implements gokrb5.com/jcmturner/goidentity.Authenticator interface.
// It takes username and password so can be used for basic authentication.
type KRB5BasicAuthenticator struct {
	BasicHeaderValue string
	serviceSettings  *Settings
	clientSettings   *client.Settings
	clientConfig     *config.Config
	realm            string
	username         string
	password         string
}

// NewKRB5BasicAuthenticator creates a Kerberos Basic authenticator.
func NewKRB5BasicAuthenticator(
	headerVal string,
	krb5conf *config.Config,
	serviceSettings *Settings,
	clientSettings *client.Settings,
) KRB5BasicAuthenticator {
	var authenticator KRB5BasicAuthenticator
	authenticator.BasicHeaderValue = headerVal
	authenticator.clientConfig = krb5conf
	authenticator.serviceSettings = serviceSettings
	authenticator.clientSettings = clientSettings
	return authenticator
}

// Authenticate and return the identity. The boolean indicates if the authentication was successful.
//
//nolint:ireturn // Implements the goidentity.Authenticator contract.
func (a KRB5BasicAuthenticator) Authenticate() (goidentity.Identity, bool, error) {
	var i goidentity.Identity
	var ok bool
	var err error
	a.realm, a.username, a.password, err = parseBasicHeaderValue(a.BasicHeaderValue)
	if err != nil {
		err = fmt.Errorf("could not parse basic authentication header: %w", err)
		return i, ok, err
	}
	cl := client.NewWithPassword(a.username, a.realm, a.password, a.clientConfig)
	err = cl.Login()
	if err != nil {
		// Username and/or password could be wrong
		err = fmt.Errorf("error with user credentials during login: %w", err)
		return i, ok, err
	}
	tkt, _, err := cl.GetServiceTicket(a.serviceSettings.SName())
	if err != nil {
		err = fmt.Errorf("could not get service ticket: %w", err)
		return i, ok, err
	}
	err = tkt.DecryptEncPart(a.serviceSettings.Keytab, a.serviceSettings.KeytabPrincipal())
	if err != nil {
		err = fmt.Errorf("could not decrypt service ticket: %w", err)
		return i, ok, err
	}
	cl.Credentials.SetAuthTime(time.Now().UTC())
	if err = attachPACCredentials(cl.Credentials, &tkt, a.serviceSettings); err != nil {
		return i, ok, err
	}
	cl.Credentials.SetAuthenticated(true)
	return cl.Credentials, true, nil
}

// Mechanism returns the authentication mechanism.
func (a KRB5BasicAuthenticator) Mechanism() string {
	return "Kerberos Basic"
}

func parseBasicHeaderValue(s string) (string, string, string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", "", "", fmt.Errorf("decode basic authentication value: %w", err)
	}
	user, password, found := strings.Cut(string(b), ":")
	if !found {
		return "", "", "", errors.New("basic authentication value does not contain a password separator")
	}
	if domain, username, ok := strings.Cut(user, `\`); ok {
		return domain, username, password, nil
	}
	if username, domain, ok := strings.Cut(user, "@"); ok {
		return domain, username, password, nil
	}
	return "", user, password, nil
}
