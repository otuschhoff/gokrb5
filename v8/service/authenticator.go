package service

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	goidentity "github.com/jcmturner/goidentity/v6"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
)

// NewKRB5BasicAuthenticator creates a new NewKRB5BasicAuthenticator
func NewKRB5BasicAuthenticator(headerVal string, krb5conf *config.Config, serviceSettings *Settings, clientSettings *client.Settings) KRB5BasicAuthenticator {
	return KRB5BasicAuthenticator{
		BasicHeaderValue: headerVal,
		clientConfig:     krb5conf,
		serviceSettings:  serviceSettings,
		clientSettings:   clientSettings,
	}
}

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

// Authenticate and return the identity. The boolean indicates if the authentication was successful.
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
	var domain string
	var username string
	var password string
	var err error
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return domain, username, password, fmt.Errorf("decode basic authentication value: %w", err)
	}
	v := string(b)
	vc := strings.SplitN(v, ":", 2)
	if len(vc) != 2 {
		err = fmt.Errorf("basic authentication value does not contain a password separator")
		return domain, username, password, err
	}
	password = vc[1]
	// Domain and username can be specified in 2 formats:
	// <Username> - no domain specified
	// <Domain>\<Username>
	// <Username>@<Domain>
	switch {
	case strings.Contains(vc[0], `\`):
		u := strings.SplitN(vc[0], `\`, 2)
		domain = u[0]
		username = u[1]
	case strings.Contains(vc[0], `@`):
		u := strings.SplitN(vc[0], `@`, 2)
		domain = u[1]
		username = u[0]
	default:
		username = vc[0]
	}
	return domain, username, password, err
}
