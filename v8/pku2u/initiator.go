package pku2u

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	initiatorStart = iota
	initiatorAwaitASReply
	initiatorAwaitAPReply
	initiatorEstablished
)

// Initiator establishes a PKU2U context for one target.
type Initiator struct {
	settings        settings
	metadata        TrustedCertifiers
	metadataPresent bool
	step            int
	as              *initiatorASState
	asResult        *asResult
	authenticator   types.Authenticator
}

// NewInitiator creates a single-use PKU2U initiator mechanism.
func NewInitiator(identity *Identity, anchors *x509.CertPool, options ...Option) *Initiator {
	initiator := new(Initiator)
	initiator.settings = newSettings(identity, anchors, options)
	return initiator
}

// OID returns the PKU2U GSS mechanism OID.
func (*Initiator) OID() asn1.ObjectIdentifier { return gssapi.OIDPKU2U.OID() }

// QueryMetadata advertises the initiator's trust anchors.
func (initiator *Initiator) QueryMetadata(_ string, _ bool) ([]byte, error) {
	return TrustedCertifiersFromPool(initiator.settings.roots).Marshal()
}

// ExchangeMetadata records the certifiers trusted by the acceptor.
func (initiator *Initiator) ExchangeMetadata(encoded []byte, _ bool) error {
	var metadata TrustedCertifiers
	if err := metadata.Unmarshal(encoded); err != nil {
		return err
	}
	if !metadata.Accepts(initiator.settings.identity) {
		return errors.New("PKU2U initiator certificate is not accepted by peer metadata")
	}
	initiator.metadata, initiator.metadataPresent = metadata, true
	return nil
}

// InitSecContext advances the initiator side of PKU2U.
//
//nolint:ireturn // gssapi.ContextMechanism requires the gssapi.Context return type.
func (initiator *Initiator) InitSecContext(
	target string,
	input []byte,
	_ ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	switch initiator.step {
	case initiatorStart:
		output, err := initiator.startASExchange(target, input)
		return output, nil, false, err
	case initiatorAwaitASReply:
		output, err := initiator.sendAPRequest(input)
		return output, nil, false, err
	case initiatorAwaitAPReply:
		context, err := initiator.finishAPExchange(input)
		if err != nil {
			return nil, nil, false, err
		}
		return nil, context, true, nil
	default:
		return nil, nil, false, errors.New("PKU2U initiator context is already established")
	}
}

// AcceptSecContext rejects use of an initiator as an acceptor.
func (*Initiator) AcceptSecContext([]byte, ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	return nil, nil, false, errors.New("PKU2U initiator cannot accept a security context")
}

func (initiator *Initiator) startASExchange(target string, input []byte) ([]byte, error) {
	if len(input) != 0 {
		return nil, errors.New("unexpected PKU2U input before AS request")
	}
	if initiator.metadataPresent && !initiator.metadata.Accepts(initiator.settings.identity) {
		return nil, errors.New("PKU2U initiator certificate is not accepted by peer")
	}
	output, state, err := beginASExchange(initiator.settings, target)
	if err != nil {
		return nil, err
	}
	initiator.as, initiator.step = state, initiatorAwaitASReply
	return output, nil
}

func (initiator *Initiator) sendAPRequest(input []byte) ([]byte, error) {
	result, err := finishASExchange(initiator.as, input, initiator.settings)
	if err != nil {
		return nil, err
	}
	authenticator, err := types.NewAuthenticator(Realm, initiator.as.request.ReqBody.CName)
	if err != nil {
		return nil, fmt.Errorf("build PKU2U authenticator: %w", err)
	}
	checksum, err := gssapi.NewAuthenticatorChecksum(
		nil,
		gssapi.ContextFlagMutual,
		gssapi.ContextFlagInteg,
		gssapi.ContextFlagConf,
	).Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKU2U authenticator checksum: %w", err)
	}
	authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
	etype, err := crypto.GetEtype(result.sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("select PKU2U initiator subkey enctype: %w", err)
	}
	err = authenticator.GenerateSeqNumberAndSubKey(result.sessionKey.KeyType, etype.GetKeyByteSize())
	if err != nil {
		return nil, fmt.Errorf("generate PKU2U initiator sequence and subkey: %w", err)
	}
	request, err := messages.NewAPReq(result.ticket, result.sessionKey, authenticator)
	if err != nil {
		return nil, fmt.Errorf("build PKU2U AP request: %w", err)
	}
	types.SetFlag(&request.APOptions, flags.APOptionMutualRequired)
	output, err := request.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKU2U AP request: %w", err)
	}
	initiator.asResult, initiator.authenticator, initiator.step = result, authenticator, initiatorAwaitAPReply
	return output, nil
}

func (initiator *Initiator) finishAPExchange(input []byte) (*securityContext, error) {
	var reply messages.APRep
	if err := reply.Unmarshal(input); err != nil {
		return nil, fmt.Errorf("decode PKU2U AP reply: %w", err)
	}
	if err := reply.Verify(initiator.authenticator, initiator.authenticator.SubKey); err != nil {
		return nil, fmt.Errorf("verify PKU2U AP reply: %w", err)
	}
	part := &reply.DecryptedEncPart
	if len(part.Subkey.KeyValue) == 0 {
		return nil, errors.New("PKU2U AP reply does not contain an acceptor subkey")
	}
	if !isPKU2UEType(part.Subkey.KeyType) {
		return nil, errors.New("PKU2U AP reply subkey must use AES")
	}
	context, err := newPKU2UInitiatorContext(initiator.authenticator.SeqNumber, part.SequenceNumber, part.Subkey)
	if err != nil {
		return nil, err
	}
	peerCredentials, err := credentialsFromCertificate(initiator.asResult.peer.Signer, initiator.asResult.peerChain)
	if err != nil {
		return nil, err
	}
	initiator.step = initiatorEstablished
	return &securityContext{SecurityContext: context, credentials: peerCredentials}, nil
}

func newPKU2UInitiatorContext(
	initiatorSequence, acceptorSequence int64,
	key types.EncryptionKey,
) (*gssapi.SecurityContext, error) {
	send, err := pku2uSequenceUint64(initiatorSequence)
	if err != nil {
		return nil, err
	}
	receive, err := pku2uSequenceUint64(acceptorSequence)
	if err != nil {
		return nil, err
	}
	context, err := gssapi.NewSecurityContext(key, true, send, receive, true)
	if err != nil {
		return nil, fmt.Errorf("create PKU2U initiator security context: %w", err)
	}
	return context, nil
}
