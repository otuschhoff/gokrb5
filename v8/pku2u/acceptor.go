package pku2u

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
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

const maxAPSequence = 1<<30 - 1

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
//
//nolint:ireturn // Implements gssapi.ContextMechanism.
func (acceptor *Acceptor) AcceptSecContext(
	input []byte, _ ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	switch acceptor.step {
	case 0:
		if acceptor.metadataPresent && !acceptor.metadata.Accepts(acceptor.settings.identity) {
			return nil, nil, false, errors.New("PKU2U acceptor certificate is not accepted by peer")
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
		return nil, nil, false, errors.New("PKU2U acceptor context is already established")
	}
}

// InitSecContext rejects use of an acceptor as an initiator.
//
//nolint:ireturn // Implements gssapi.ContextMechanism.
func (*Acceptor) InitSecContext(string, []byte, ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	return nil, nil, false, errors.New("PKU2U acceptor cannot initiate a security context")
}

func (acceptor *Acceptor) acceptAPRequest(encoded []byte) ([]byte, *securityContext, error) {
	var request messages.APReq
	if err := request.Unmarshal(encoded); err != nil {
		return nil, nil, fmt.Errorf("decode PKU2U AP request: %w", err)
	}
	if !types.IsFlagSet(&request.APOptions, flags.APOptionMutualRequired) {
		return nil, nil, errors.New("PKU2U requires mutual AP authentication")
	}
	if err := acceptor.validateAPTicket(&request.Ticket); err != nil {
		return nil, nil, err
	}
	if err := acceptor.validateAPAuthenticator(&request); err != nil {
		return nil, nil, err
	}
	return acceptor.replyToAPRequest(&request)
}

func (acceptor *Acceptor) validateAPTicket(ticket *messages.Ticket) error {
	if ticket.Realm != Realm || !ticket.SName.Equal(acceptor.asResult.ticket.SName) {
		return errors.New("PKU2U AP request ticket is for the wrong service")
	}
	if err := ticket.Decrypt(acceptor.asResult.ticketKey); err != nil {
		return fmt.Errorf("decrypt PKU2U ticket: %w", err)
	}
	valid, err := ticket.ValidAt(acceptor.settings.currentTime(), acceptor.settings.clockSkew)
	if err != nil {
		return fmt.Errorf("validate PKU2U ticket: %w", err)
	}
	if !valid {
		return errors.New("PKU2U ticket is not valid")
	}
	return nil
}

func (acceptor *Acceptor) validateAPAuthenticator(request *messages.APReq) error {
	if err := request.DecryptAuthenticator(request.Ticket.DecryptedEncPart.Key); err != nil {
		return fmt.Errorf("decrypt PKU2U authenticator: %w", err)
	}
	authenticator := &request.Authenticator
	if authenticator.CRealm != Realm || !authenticator.CName.Equal(request.Ticket.DecryptedEncPart.CName) {
		return errors.New("PKU2U authenticator identity does not match ticket")
	}
	if err := acceptor.validateAPAuthenticatorTime(authenticator); err != nil {
		return err
	}
	if err := validateAPChecksum(authenticator.Cksum); err != nil {
		return err
	}
	if len(authenticator.SubKey.KeyValue) == 0 {
		return errors.New("PKU2U authenticator subkey is missing")
	}
	if !isPKU2UEType(authenticator.SubKey.KeyType) {
		return errors.New("PKU2U authenticator subkey must use AES")
	}
	return nil
}

func (acceptor *Acceptor) validateAPAuthenticatorTime(authenticator *types.Authenticator) error {
	if authenticator.Cusec < 0 || authenticator.Cusec > 999999 {
		return errors.New("PKU2U authenticator microseconds are invalid")
	}
	authenticatorTime := authenticator.CTime.Add(time.Duration(authenticator.Cusec) * time.Microsecond)
	now := acceptor.settings.currentTime()
	skew := acceptor.settings.clockSkew
	if now.Sub(authenticatorTime) > skew || authenticatorTime.Sub(now) > skew {
		return errors.New("PKU2U authenticator exceeds permitted clock skew")
	}
	return nil
}

func validateAPChecksum(checksum types.Checksum) error {
	if checksum.CksumType != chksumtype.GSSAPI {
		return errors.New("PKU2U authenticator lacks an RFC 4121 checksum")
	}
	var decoded gssapi.AuthenticatorChecksum
	if err := decoded.Unmarshal(checksum.Checksum); err != nil {
		return fmt.Errorf("decode PKU2U authenticator checksum: %w", err)
	}
	required := uint32(gssapi.ContextFlagMutual | gssapi.ContextFlagInteg)
	if decoded.Flags&required != required {
		return errors.New("PKU2U authenticator does not request mutual integrity protection")
	}
	return nil
}

func (acceptor *Acceptor) replyToAPRequest(request *messages.APReq) ([]byte, *securityContext, error) {
	etype, err := crypto.GetEtype(request.Authenticator.SubKey.KeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("select PKU2U acceptor subkey enctype: %w", err)
	}
	acceptorSubkey, err := types.GenerateEncryptionKey(etype)
	if err != nil {
		return nil, nil, fmt.Errorf("generate PKU2U acceptor subkey: %w", err)
	}
	sequence, err := randomSequence()
	if err != nil {
		return nil, nil, err
	}
	output, err := marshalPKU2UReply(request, acceptorSubkey, sequence)
	if err != nil {
		return nil, nil, err
	}
	peerSequence, err := pku2uSequenceUint64(request.Authenticator.SeqNumber)
	if err != nil {
		return nil, nil, err
	}
	context, err := gssapi.NewSecurityContext(acceptorSubkey, false, sequence, peerSequence, true)
	if err != nil {
		return nil, nil, fmt.Errorf("create PKU2U acceptor security context: %w", err)
	}
	peerCredentials, err := credentialsFromCertificate(acceptor.asResult.peer.Signer, acceptor.asResult.peerChain)
	if err != nil {
		return nil, nil, err
	}
	return output, &securityContext{SecurityContext: context, credentials: peerCredentials}, nil
}

func pku2uSequenceInt64(sequence uint64) (int64, error) {
	if sequence > maxAPSequence {
		return 0, fmt.Errorf("PKU2U sequence number %d exceeds 30-bit range", sequence)
	}
	return int64(sequence), nil
}

func pku2uSequenceUint64(sequence int64) (uint64, error) {
	if sequence < 0 || sequence > maxAPSequence {
		return 0, fmt.Errorf("PKU2U sequence number %d exceeds 30-bit range", sequence)
	}
	return uint64(sequence), nil
}

func marshalPKU2UReply(request *messages.APReq, key types.EncryptionKey, sequence uint64) ([]byte, error) {
	sequenceInt, err := pku2uSequenceInt64(sequence)
	if err != nil {
		return nil, err
	}
	reply, err := messages.NewAPRepFromAuthenticator(request.Authenticator, request.Authenticator.SubKey, key, sequenceInt)
	if err != nil {
		return nil, fmt.Errorf("build PKU2U AP reply: %w", err)
	}
	encoded, err := reply.Marshal()
	if err != nil {
		return encoded, fmt.Errorf("marshal PKU2U AP reply: %w", err)
	}
	return encoded, nil
}

func randomSequence() (uint64, error) {
	var encoded [8]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return 0, fmt.Errorf("generate PKU2U acceptor sequence number: %w", err)
	}
	return binary.BigEndian.Uint64(encoded[:]) & maxAPSequence, nil
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
		return nil, fmt.Errorf("read PKU2U peer certificate principal names: %w", err)
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
