package client

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type fastArmorCredentials struct {
	ticket messages.Ticket
	key    types.EncryptionKey
	cname  types.PrincipalName
	realm  string
}

// Settings holds optional client settings.
type Settings struct {
	disablePAFXFast         bool
	assumePreAuthentication bool
	preAuthEType            int32
	preAuthType             int32
	fastArmor               *fastArmorCredentials
	fastArmorKeytab         *keytab.Keytab
	requireFAST             bool
	kkdcpClient             *http.Client
	logger                  *log.Logger
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	DisablePAFXFast         bool
	AssumePreAuthentication bool
	RequireFAST             bool
}

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := new(Settings)
	for _, set := range settings {
		set(s)
	}
	return s
}

// DisablePAReqEncPARep configures the client not to request encrypted PA-REP.
func DisablePAReqEncPARep(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePAFXFast = b
	}
}

// DisablePAFXFAST used to configure the client to not use PA_FX_FAST.
//
// s := NewSettings(DisablePAFXFAST(true))
//
// Deprecated: use DisablePAReqEncPARep.
func DisablePAFXFAST(b bool) func(*Settings) {
	return DisablePAReqEncPARep(b)
}

// DisablePAReqEncPARep indicates whether the client should omit
// PA-REQ-ENC-PA-REP.
func (s *Settings) DisablePAReqEncPARep() bool {
	return s.disablePAFXFast
}

// DisablePAFXFAST indicates is the client should disable the use of PA_FX_FAST.
//
// Deprecated: use DisablePAReqEncPARep.
func (s *Settings) DisablePAFXFAST() bool {
	return s.DisablePAReqEncPARep()
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true))
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication = b
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication
}

// FASTArmor configures an armor TGT belonging to the client's principal.
func FASTArmor(ticket messages.Ticket, key types.EncryptionKey) func(*Settings) {
	return func(s *Settings) {
		s.fastArmor = &fastArmorCredentials{ticket: ticket, key: key}
	}
}

// FASTArmorWithIdentity configures an armor TGT and its client identity.
func FASTArmorWithIdentity(ticket messages.Ticket, key types.EncryptionKey, cname types.PrincipalName, realm string) func(*Settings) {
	return func(s *Settings) {
		s.fastArmor = &fastArmorCredentials{ticket: ticket, key: key, cname: cname, realm: realm}
	}
}

// FASTArmorFromKeytab configures the client to acquire an armor TGT. A
// machine-account principal is preferred when the keytab contains one.
func FASTArmorFromKeytab(kt *keytab.Keytab) func(*Settings) {
	return func(s *Settings) {
		s.fastArmorKeytab = kt
	}
}

// RequireFAST requires every configured AS and TGS exchange to be armored.
func RequireFAST(required bool) func(*Settings) {
	return func(s *Settings) {
		s.requireFAST = required
	}
}

// RequireFAST indicates whether unarmored KDC responses must be rejected.
func (s *Settings) RequireFAST() bool {
	return s.requireFAST
}

// KKDCPClient configures the HTTP client used for KDC proxy requests. The
// client's transport controls TLS trust, client certificates, and proxies.
func KKDCPClient(httpClient *http.Client) func(*Settings) {
	return func(s *Settings) {
		s.kkdcpClient = httpClient
	}
}

func (s *Settings) httpClient() *http.Client {
	if s.kkdcpClient != nil {
		return s.kkdcpClient
	}
	return &http.Client{Timeout: 5 * time.Second}
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		DisablePAFXFast:         s.disablePAFXFast,
		AssumePreAuthentication: s.assumePreAuthentication,
		RequireFAST:             s.requireFAST,
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil

}
