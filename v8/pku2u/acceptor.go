package pku2u

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// Acceptor establishes a PKU2U context and acts as the KDC for its self-ticket.
type Acceptor struct {
	settings        settings
	metadata        TrustedCertifiers
	metadataPresent bool
	step            int
	asResult        *asResult
}

// NewAcceptor creates a single-use PKU2U acceptor mechanism.
func NewAcceptor(identity *Identity, anchors *x509.CertPool, options ...Option) *Acceptor {
	return &Acceptor{settings: newSettings(identity, anchors, options)}
}

// OID returns the PKU2U GSS mechanism OID.
func (*Acceptor) OID() asn1.ObjectIdentifier { return gssapi.OIDPKU2U.OID() }

// QueryMetadata advertises the acceptor's trust anchors.
func (acceptor *Acceptor) QueryMetadata(_ string, _ bool) ([]byte, error) {
	return TrustedCertifiersFromPool(acceptor.settings.roots).Marshal()
}

// ExchangeMetadata records the certifiers trusted by the initiator.
func (acceptor *Acceptor) ExchangeMetadata(encoded []byte, _ bool) error {
	var metadata TrustedCertifiers
	if err := metadata.Unmarshal(encoded); err != nil {
		return err
	}
	if !metadata.Accepts(acceptor.settings.identity) {
		return fmt.Errorf("PKU2U acceptor certificate is not accepted by peer metadata")
	}
	acceptor.metadata, acceptor.metadataPresent = metadata, true
	return nil
}

// AcceptSecContext advances the acceptor side of PKU2U.
func (acceptor *Acceptor) AcceptSecContext(input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	switch acceptor.step {
	case 0:
		if acceptor.metadataPresent && !acceptor.metadata.Accepts(acceptor.settings.identity) {
			return nil, nil, false, fmt.Errorf("PKU2U acceptor certificate is not accepted by peer")
		}
		output, result, err := acceptASExchange(input, acceptor.settings)
		if err != nil {
			return nil, nil, false, err
		}
		acceptor.asResult, acceptor.step = result, 1
		return output, nil, false, nil
	case 1:
		output, context, err := acceptor.acceptAPRequest(input)
		if err != nil {
			return nil, nil, false, err
		}
		acceptor.step = 2
		return output, context, true, nil
	default:
		return nil, nil, false, fmt.Errorf("PKU2U acceptor context is already established")
	}
}

func (acceptor *Acceptor) acceptAPRequest(encoded []byte) ([]byte, gssapi.Context, error) {
	var request messages.APReq
	if err := request.Unmarshal(encoded); err != nil {
		return nil, nil, err
	}
	if !types.IsFlagSet(&request.APOptions, flags.APOptionMutualRequired) {
		return nil, nil, fmt.Errorf("PKU2U requires mutual AP authentication")
	}
	if request.Ticket.Realm != Realm || !request.Ticket.SName.Equal(acceptor.asResult.ticket.SName) {
		return nil, nil, fmt.Errorf("PKU2U AP request ticket is for the wrong service")
	}
	if err := request.Ticket.Decrypt(acceptor.asResult.ticketKey); err != nil {
		return nil, nil, err
	}
	valid, err := request.Ticket.ValidAt(acceptor.settings.currentTime(), acceptor.settings.clockSkew)
	if err != nil || !valid {
		return nil, nil, fmt.Errorf("validate PKU2U ticket: %w", err)
	}
	if err := request.DecryptAuthenticator(request.Ticket.DecryptedEncPart.Key); err != nil {
		return nil, nil, err
	}
	if request.Authenticator.CRealm != Realm || !request.Authenticator.CName.Equal(request.Ticket.DecryptedEncPart.CName) {
		return nil, nil, fmt.Errorf("PKU2U authenticator identity does not match ticket")
	}
	if request.Authenticator.Cusec < 0 || request.Authenticator.Cusec > 999999 {
		return nil, nil, fmt.Errorf("PKU2U authenticator microseconds are invalid")
	}
	authenticatorTime := request.Authenticator.CTime.Add(time.Duration(request.Authenticator.Cusec) * time.Microsecond)
	now := acceptor.settings.currentTime()
	if now.Sub(authenticatorTime) > acceptor.settings.clockSkew || authenticatorTime.Sub(now) > acceptor.settings.clockSkew {
		return nil, nil, fmt.Errorf("PKU2U authenticator exceeds permitted clock skew")
	}
	if request.Authenticator.Cksum.CksumType != chksumtype.GSSAPI {
		return nil, nil, fmt.Errorf("PKU2U authenticator lacks an RFC 4121 checksum")
	}
	var checksum gssapi.AuthenticatorChecksum
	if err := checksum.Unmarshal(request.Authenticator.Cksum.Checksum); err != nil {
		return nil, nil, err
	}
	required := uint32(gssapi.ContextFlagMutual | gssapi.ContextFlagInteg)
	if checksum.Flags&required != required {
		return nil, nil, fmt.Errorf("PKU2U authenticator does not request mutual integrity protection")
	}
	if len(request.Authenticator.SubKey.KeyValue) == 0 {
		return nil, nil, fmt.Errorf("PKU2U authenticator subkey is missing")
	}
	if !isPKU2UEType(request.Authenticator.SubKey.KeyType) {
		return nil, nil, fmt.Errorf("PKU2U authenticator subkey must use AES")
	}
	etype, err := crypto.GetEtype(request.Authenticator.SubKey.KeyType)
	if err != nil {
		return nil, nil, err
	}
	acceptorSubkey, err := types.GenerateEncryptionKey(etype)
	if err != nil {
		return nil, nil, err
	}
	sequence, err := randomSequence()
	if err != nil {
		return nil, nil, err
	}
	reply, err := messages.NewAPRepFromAuthenticator(request.Authenticator, request.Authenticator.SubKey, acceptorSubkey, int64(sequence))
	if err != nil {
		return nil, nil, err
	}
	output, err := reply.Marshal()
	if err != nil {
		return nil, nil, err
	}
	context, err := gssapi.NewSecurityContext(acceptorSubkey, false, sequence, uint64(request.Authenticator.SeqNumber), true)
	if err != nil {
		return nil, nil, err
	}
	peerCredentials, err := credentialsFromCertificate(acceptor.asResult.peer.Signer, acceptor.asResult.peerChain)
	if err != nil {
		return nil, nil, err
	}
	return output, &securityContext{SecurityContext: context, credentials: peerCredentials}, nil
}

// InitSecContext rejects use of an acceptor as an initiator.
func (*Acceptor) InitSecContext(string, []byte, ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	return nil, nil, false, fmt.Errorf("PKU2U acceptor cannot initiate a security context")
}

func randomSequence() (uint64, error) {
	var encoded [8]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(encoded[:]) & 0x3fffffff, nil
}

func credentialsFromCertificate(certificate *x509.Certificate, chain []*x509.Certificate) (*credentials.Credentials, error) {
	principal, err := PrincipalFromCertificate(certificate)
	if err != nil {
		return nil, err
	}
	result := credentials.NewFromPrincipalName(principal, Realm)
	result.SetAuthenticated(true)
	result.SetAuthTime(time.Now().UTC())
	names, err := pkinit.CertificatePrincipalNames(certificate)
	if err != nil {
		return nil, err
	}
	upn := ""
	if len(names) > 0 {
		upn = names[0]
	}
	result.SetCertificateIdentity(credentials.CertificateIdentity{
		Certificate: certificate, Chain: chain, SubjectDN: certificate.Subject.String(),
		UPN: upn, IssuedBy: certificate.Issuer.String(),
	})
	return result, nil
}
