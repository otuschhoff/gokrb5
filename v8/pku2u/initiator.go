package pku2u

import (
	"crypto/x509"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
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
	return &Initiator{settings: newSettings(identity, anchors, options)}
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
		return fmt.Errorf("PKU2U initiator certificate is not accepted by peer metadata")
	}
	initiator.metadata, initiator.metadataPresent = metadata, true
	return nil
}

// InitSecContext advances the initiator side of PKU2U.
func (initiator *Initiator) InitSecContext(target string, input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	switch initiator.step {
	case 0:
		if len(input) != 0 {
			return nil, nil, false, fmt.Errorf("unexpected PKU2U input before AS request")
		}
		if initiator.metadataPresent && !initiator.metadata.Accepts(initiator.settings.identity) {
			return nil, nil, false, fmt.Errorf("PKU2U initiator certificate is not accepted by peer")
		}
		output, state, err := beginASExchange(initiator.settings, target)
		if err != nil {
			return nil, nil, false, err
		}
		initiator.as, initiator.step = state, 1
		return output, nil, false, nil
	case 1:
		result, err := finishASExchange(initiator.as, input, initiator.settings)
		if err != nil {
			return nil, nil, false, err
		}
		authenticator, err := types.NewAuthenticator(Realm, initiator.as.request.ReqBody.CName)
		if err != nil {
			return nil, nil, false, err
		}
		checksum, err := gssapi.NewAuthenticatorChecksum(nil, gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf).Marshal()
		if err != nil {
			return nil, nil, false, err
		}
		authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
		etype, err := crypto.GetEtype(result.sessionKey.KeyType)
		if err != nil {
			return nil, nil, false, err
		}
		if err := authenticator.GenerateSeqNumberAndSubKey(result.sessionKey.KeyType, etype.GetKeyByteSize()); err != nil {
			return nil, nil, false, err
		}
		request, err := messages.NewAPReq(result.ticket, result.sessionKey, authenticator)
		if err != nil {
			return nil, nil, false, err
		}
		types.SetFlag(&request.APOptions, flags.APOptionMutualRequired)
		output, err := request.Marshal()
		if err != nil {
			return nil, nil, false, err
		}
		initiator.asResult, initiator.authenticator, initiator.step = result, authenticator, 2
		return output, nil, false, nil
	case 2:
		var reply messages.APRep
		if err := reply.Unmarshal(input); err != nil {
			return nil, nil, false, err
		}
		if err := reply.Verify(initiator.authenticator, initiator.authenticator.SubKey); err != nil {
			return nil, nil, false, err
		}
		if len(reply.DecryptedEncPart.Subkey.KeyValue) == 0 {
			return nil, nil, false, fmt.Errorf("PKU2U AP reply does not contain an acceptor subkey")
		}
		if !isPKU2UEType(reply.DecryptedEncPart.Subkey.KeyType) {
			return nil, nil, false, fmt.Errorf("PKU2U AP reply subkey must use AES")
		}
		context, err := gssapi.NewSecurityContext(
			reply.DecryptedEncPart.Subkey, true,
			uint64(initiator.authenticator.SeqNumber), uint64(reply.DecryptedEncPart.SequenceNumber), true,
		)
		if err != nil {
			return nil, nil, false, err
		}
		peerCredentials, err := credentialsFromCertificate(initiator.asResult.peer.Signer, initiator.asResult.peerChain)
		if err != nil {
			return nil, nil, false, err
		}
		initiator.step = 3
		return nil, &securityContext{SecurityContext: context, credentials: peerCredentials}, true, nil
	default:
		return nil, nil, false, fmt.Errorf("PKU2U initiator context is already established")
	}
}

// AcceptSecContext rejects use of an initiator as an acceptor.
func (*Initiator) AcceptSecContext([]byte, ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	return nil, nil, false, fmt.Errorf("PKU2U initiator cannot accept a security context")
}
