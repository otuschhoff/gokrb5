// Package spnego implements the Simple and Protected GSSAPI Negotiation Mechanism for Kerberos authentication.
package spnego

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/client"
	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// SPNEGO implements the GSS-API mechanism for RFC 4178
type SPNEGO struct {
	serviceSettings  *service.Settings
	client           *client.Client
	spn              string
	initiatorOptions KRB5TokenAPREQOptions
	responseToken    gssapi.ContextToken
	authenticator    types.Authenticator
	ticketKey        types.EncryptionKey
	replyKey         types.EncryptionKey
	contextKey       types.EncryptionKey
	sequenceNumber   int64
	offeredMechTypes []asn1.ObjectIdentifier
	requireMechMIC   bool
	preferredMechs   []asn1.ObjectIdentifier
	pendingMechMIC   bool
	dcePending       bool
	context          context.Context
	securityContext  gssapi.Context
	contextSend      uint64
	contextReceive   uint64
	acceptorSubkey   bool
}

// SPNEGOClient configures the SPNEGO mechanism suitable for client side use.
func SPNEGOClient(cl *client.Client, spn string) *SPNEGO {
	return SPNEGOClientWithOptions(cl, spn, KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
	})
}

// SPNEGOClientWithOptions configures a client with explicit GSS context options.
func SPNEGOClientWithOptions(cl *client.Client, spn string, options KRB5TokenAPREQOptions) *SPNEGO {
	s := new(SPNEGO)
	s.client = cl
	s.spn = spn
	s.initiatorOptions = options
	s.serviceSettings = service.NewSettings(nil, service.SName(spn))
	return s
}

// SPNEGOService configures the SPNEGO mechanism suitable for service side use.
func SPNEGOService(kt *keytab.Keytab, options ...func(*service.Settings)) *SPNEGO {
	return SPNEGOServiceWithMechTypes(kt, nil, options...)
}

// SPNEGOServiceWithMechTypes configures the acceptor's mechanism preference order.
// An empty list preserves the initiator's order.
func SPNEGOServiceWithMechTypes(kt *keytab.Keytab, mechTypes []asn1.ObjectIdentifier, options ...func(*service.Settings)) *SPNEGO {
	s := new(SPNEGO)
	s.serviceSettings = service.NewSettings(kt, options...)
	s.preferredMechs = append([]asn1.ObjectIdentifier(nil), mechTypes...)
	return s
}

// OID returns the GSS-API assigned OID for SPNEGO.
func (s *SPNEGO) OID() asn1.ObjectIdentifier {
	return gssapi.OIDSPNEGO.OID()
}

// AcquireCred is the GSS-API method to acquire a client credential via Kerberos for SPNEGO.
func (s *SPNEGO) AcquireCred() error {
	return s.client.AffirmLogin()
}

// InitSecContext is the GSS-API method for the client to a generate a context token to the service via Kerberos.
func (s *SPNEGO) InitSecContext() (gssapi.ContextToken, error) {
	s.securityContext = nil
	tkt, key, err := s.client.GetServiceTicket(s.spn)
	if err != nil {
		return &SPNEGOToken{}, err
	}
	negTokenInit, err := NewNegTokenInitKRB5WithOptions(s.client, tkt, key, s.initiatorOptions)
	if err != nil {
		return &SPNEGOToken{}, fmt.Errorf("could not create NegTokenInit: %v", err)
	}
	mechanismToken := negTokenInit.mechToken.(*KRB5Token)
	s.offeredMechTypes = append([]asn1.ObjectIdentifier(nil), negTokenInit.MechTypes...)
	s.requireMechMIC = len(negTokenInit.MechListMIC) > 0
	s.authenticator = mechanismToken.APReq.Authenticator
	s.ticketKey = key
	s.replyKey = mechanismToken.APReq.Authenticator.SubKey
	if len(s.replyKey.KeyValue) == 0 {
		s.replyKey = key
	}
	if !contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagMutual) &&
		!contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagDCEStyle) {
		s.contextKey = s.replyKey
		s.contextSend = uint64(s.authenticator.SeqNumber)
		s.contextReceive = 0
		s.acceptorSubkey = false
		if err := s.completeSecurityContext(true); err != nil {
			return &SPNEGOToken{}, fmt.Errorf("could not create security context: %v", err)
		}
	}
	if contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagDCEStyle) {
		mechanismToken.raw = true
		return mechanismToken, nil
	}
	return &SPNEGOToken{
		Init:         true,
		NegTokenInit: negTokenInit,
		settings:     s.serviceSettings,
	}, nil
}

// AcceptSecContext is the GSS-API method for the service to verify the context token provided by the client and
// establish a context.
func (s *SPNEGO) AcceptSecContext(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	if s.dcePending {
		return s.ContinueSecContext(ct)
	}
	if s.pendingMechMIC {
		return s.acceptMechListMIC(ct)
	}
	var ctx context.Context
	var mechanismToken *KRB5Token
	var ok bool
	var status gssapi.Status
	switch token := ct.(type) {
	case *SPNEGOToken:
		token.settings = s.serviceSettings
		var oid asn1.ObjectIdentifier
		if token.Init && len(token.NegTokenInit.MechTypes) > 0 {
			oid = s.selectMech(token.NegTokenInit.MechTypes)
		}
		if token.Resp {
			oid = token.NegTokenResp.SupportedMech
		}
		if !isKerberosMech(oid) {
			return false, ctx, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "SPNEGO OID of MechToken is not of type KRB5"}
		}
		ok, status = token.Verify()
		ctx = token.Context()
		if ok {
			var err error
			mechanismToken, err = negotiationKRB5Token(token)
			if err != nil {
				return false, ctx, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
			}
		}
	case *KRB5Token:
		if !token.raw || !token.IsAPReq() {
			return false, ctx, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "raw context token is not a DCE AP_REQ"}
		}
		token.settings = s.serviceSettings
		ok, status = token.Verify()
		ctx = token.Context()
		mechanismToken = token
	default:
		return false, ctx, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "context token is neither SPNEGO nor Kerberos"}
	}
	if !ok {
		return ok, ctx, status
	}
	var offeredMechTypes []asn1.ObjectIdentifier
	var selectedMech = gssapi.OIDKRB5.OID()
	var includeMechMIC bool
	if token, isSPNEGO := ct.(*SPNEGOToken); isSPNEGO && token.Init {
		offeredMechTypes = token.NegTokenInit.MechTypes
		selectedMech = s.selectMech(offeredMechTypes)
		micRequired := len(offeredMechTypes) > 0 && !selectedMech.Equal(offeredMechTypes[0])
		includeMechMIC = len(token.NegTokenInit.MechListMIC) > 0 || micRequired
		if len(token.NegTokenInit.MechListMIC) > 0 {
			if err := token.NegTokenInit.VerifyMechListMIC(mechanismToken.replyKey); err != nil {
				return false, ctx, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
			}
		}
	}
	s.context = ctx
	s.contextReceive = uint64(mechanismToken.APReq.Authenticator.SeqNumber)
	mutual := mechanismToken.checksum.Flags&(gssapi.ContextFlagMutual|gssapi.ContextFlagDCEStyle) != 0 ||
		types.IsFlagSet(&mechanismToken.APReq.APOptions, flags.APOptionMutualRequired)
	if !mutual {
		s.contextKey = mechanismToken.replyKey
		s.contextSend = 0
		s.acceptorSubkey = false
		if includeMechMIC {
			state := NegStateAcceptCompleted
			if micRequiredWithoutInitiatorMIC(ct, selectedMech) {
				state = NegStateRequestMIC
				s.pendingMechMIC = true
				s.offeredMechTypes = append([]asn1.ObjectIdentifier(nil), offeredMechTypes...)
				s.contextKey = mechanismToken.replyKey
			}
			response := NegTokenResp{NegState: asn1.Enumerated(state), SupportedMech: selectedMech}
			if err := response.SetMechListMIC(offeredMechTypes, mechanismToken.replyKey, 0, false); err != nil {
				return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
			}
			s.responseToken = &SPNEGOToken{Resp: true, NegTokenResp: response}
			if state == NegStateRequestMIC {
				return false, ctx, gssapi.Status{Code: gssapi.StatusContinueNeeded}
			}
		} else {
			s.responseToken = nil
		}
		if err := s.completeSecurityContext(false); err != nil {
			return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
		}
		return true, ctx, status
	}
	if len(mechanismToken.replyKey.KeyValue) == 0 {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: "AP_REP reply key is missing"}
	}
	et, err := krbcrypto.GetEtype(mechanismToken.replyKey.KeyType)
	if err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	acceptorSubkey, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	sequenceNumber, err := randomSequenceNumber()
	if err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	dceStyle := mechanismToken.checksum.Flags&gssapi.ContextFlagDCEStyle != 0
	part := messages.EncAPRepPart{Subkey: acceptorSubkey, SequenceNumber: sequenceNumber}
	if dceStyle {
		part.CTime = time.Now().UTC()
		part.Cusec = microseconds(part.CTime)
	} else {
		part.CTime = mechanismToken.APReq.Authenticator.CTime
		part.Cusec = mechanismToken.APReq.Authenticator.Cusec
	}
	reply, err := messages.NewAPRep(part, mechanismToken.replyKey)
	if err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	replyToken := NewKRB5TokenAPREP(reply, dceStyle)
	s.contextKey = acceptorSubkey
	s.sequenceNumber = sequenceNumber
	s.contextSend = uint64(sequenceNumber)
	s.acceptorSubkey = true
	if dceStyle {
		s.dcePending = true
		s.responseToken = &replyToken
		return false, ctx, gssapi.Status{Code: gssapi.StatusContinueNeeded}
	}
	replyBytes, err := replyToken.Marshal()
	if err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	response := NegTokenResp{
		NegState: asn1.Enumerated(NegStateAcceptCompleted), SupportedMech: selectedMech, ResponseToken: replyBytes,
	}
	if micRequiredWithoutInitiatorMIC(ct, selectedMech) {
		response.NegState = asn1.Enumerated(NegStateRequestMIC)
		s.pendingMechMIC = true
		s.offeredMechTypes = append([]asn1.ObjectIdentifier(nil), offeredMechTypes...)
	}
	if includeMechMIC {
		if err := response.SetMechListMIC(offeredMechTypes, s.contextKey, uint64(sequenceNumber), true); err != nil {
			return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
		}
	}
	s.responseToken = &SPNEGOToken{Resp: true, NegTokenResp: response}
	if s.pendingMechMIC {
		return false, ctx, gssapi.Status{Code: gssapi.StatusContinueNeeded}
	}
	if err := s.completeSecurityContext(false); err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	return ok, ctx, status
}

func (s *SPNEGO) selectMech(offered []asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	if len(s.preferredMechs) > 0 {
		for _, preferred := range s.preferredMechs {
			if !isKerberosMech(preferred) {
				continue
			}
			for _, candidate := range offered {
				if preferred.Equal(candidate) {
					return candidate
				}
			}
		}
	}
	for _, candidate := range offered {
		if isKerberosMech(candidate) {
			return candidate
		}
	}
	return nil
}

func micRequiredWithoutInitiatorMIC(ct gssapi.ContextToken, selected asn1.ObjectIdentifier) bool {
	token, ok := ct.(*SPNEGOToken)
	return ok && token.Init && len(token.NegTokenInit.MechTypes) > 0 &&
		!selected.Equal(token.NegTokenInit.MechTypes[0]) && len(token.NegTokenInit.MechListMIC) == 0
}

func (s *SPNEGO) acceptMechListMIC(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	token, ok := ct.(*SPNEGOToken)
	if !ok || !token.Resp || NegState(token.NegTokenResp.NegState) != NegStateAcceptCompleted {
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "expected an accept-completed SPNEGO mechListMIC response"}
	}
	if err := verifyMechListMIC(s.offeredMechTypes, token.NegTokenResp.MechListMIC, s.contextKey, false, keyusage.GSSAPI_INITIATOR_SIGN); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
	}
	s.pendingMechMIC = false
	s.responseToken = nil
	if err := s.completeSecurityContext(false); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	return true, s.context, gssapi.Status{Code: gssapi.StatusComplete}
}

// ResponseToken returns the output token generated by the latest context step.
func (s *SPNEGO) ResponseToken() gssapi.ContextToken {
	return s.responseToken
}

// SecurityContext returns the locally established RFC 4121 per-message security context.
// It returns nil until this peer has authenticated the remote peer and derived the context key.
// A context can therefore be available while a final output token still needs to be delivered.
func (s *SPNEGO) SecurityContext() gssapi.Context {
	return s.securityContext
}

func (s *SPNEGO) completeSecurityContext(initiator bool) error {
	securityContext, err := gssapi.NewSecurityContext(s.contextKey, initiator, s.contextSend, s.contextReceive, s.acceptorSubkey)
	if err != nil {
		return err
	}
	s.securityContext = securityContext
	return nil
}

// ContinueSecContext processes a mutual-authentication response or DCE final leg.
func (s *SPNEGO) ContinueSecContext(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	if s.client != nil && !contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagDCEStyle) {
		return s.continueInitiator(ct)
	}
	mechanismToken, err := contextKRB5Token(ct, s.serviceSettings)
	if err != nil || !mechanismToken.IsAPRep() {
		if err == nil {
			err = errors.New("continuation token is not an AP_REP")
		}
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}
	if s.client != nil {
		dceStyle := contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagDCEStyle)
		if dceStyle {
			err = mechanismToken.APRep.VerifyDCE(s.replyKey, -1, false, s.serviceSettings.MaxClockSkew())
		} else {
			err = mechanismToken.APRep.Verify(s.authenticator, s.replyKey)
		}
		if err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		s.contextKey = mechanismToken.APRep.DecryptedEncPart.Subkey
		if len(s.contextKey.KeyValue) == 0 {
			s.contextKey = s.replyKey
		}
		s.sequenceNumber = mechanismToken.APRep.DecryptedEncPart.SequenceNumber
		s.contextSend = uint64(s.authenticator.SeqNumber)
		s.contextReceive = uint64(s.sequenceNumber)
		s.acceptorSubkey = len(mechanismToken.APRep.DecryptedEncPart.Subkey.KeyValue) > 0
		if spnegoToken, ok := ct.(*SPNEGOToken); ok {
			if len(spnegoToken.NegTokenResp.MechListMIC) > 0 {
				if err := spnegoToken.NegTokenResp.VerifyMechListMIC(s.offeredMechTypes, s.contextKey); err != nil {
					return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
				}
			} else if s.requireMechMIC {
				return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: "acceptor did not return a required mechListMIC"}
			}
		}
		if !dceStyle {
			if err := s.completeSecurityContext(true); err != nil {
				return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
			}
			s.responseToken = nil
			return true, s.context, gssapi.Status{Code: gssapi.StatusComplete}
		}
		now := time.Now().UTC()
		finalReply, err := messages.NewAPRep(messages.EncAPRepPart{
			CTime: now, Cusec: microseconds(now), SequenceNumber: s.sequenceNumber,
		}, s.contextKey)
		if err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
		}
		finalToken := NewKRB5TokenAPREP(finalReply, true)
		if err := s.completeSecurityContext(true); err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
		}
		s.responseToken = &finalToken
		return true, s.context, gssapi.Status{Code: gssapi.StatusComplete}
	}
	if !s.dcePending {
		return false, s.context, gssapi.Status{Code: gssapi.StatusNoContext, Message: "no DCE context continuation is pending"}
	}
	if err := mechanismToken.APRep.VerifyDCE(s.contextKey, s.sequenceNumber, true, s.serviceSettings.MaxClockSkew()); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}
	s.dcePending = false
	s.responseToken = nil
	if err := s.completeSecurityContext(false); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	return true, s.context, gssapi.Status{Code: gssapi.StatusComplete}
}

func (s *SPNEGO) continueInitiator(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	token, ok := ct.(*SPNEGOToken)
	if !ok || !token.Resp {
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "continuation token is not a NegTokenResp"}
	}
	state := NegState(token.NegTokenResp.NegState)
	if state == NegStateReject {
		return false, s.context, gssapi.Status{Code: gssapi.StatusBadMech, Message: "SPNEGO negotiation was rejected"}
	}
	if len(token.NegTokenResp.SupportedMech) > 0 && !containsMech(s.offeredMechTypes, token.NegTokenResp.SupportedMech) {
		return false, s.context, gssapi.Status{Code: gssapi.StatusBadMech, Message: "acceptor selected a mechanism that was not offered"}
	}

	usesAcceptorSubkey := false
	if len(token.NegTokenResp.ResponseToken) > 0 {
		mechanismToken, err := contextKRB5Token(token, s.serviceSettings)
		if err != nil || !mechanismToken.IsAPRep() {
			if err == nil {
				err = errors.New("continuation token is not an AP_REP")
			}
			return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		verifiedKey, err := s.verifyInitiatorAPRep(&mechanismToken.APRep)
		if err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		s.contextKey = mechanismToken.APRep.DecryptedEncPart.Subkey
		usesAcceptorSubkey = len(s.contextKey.KeyValue) > 0
		if !usesAcceptorSubkey {
			s.contextKey = verifiedKey
		}
		s.sequenceNumber = mechanismToken.APRep.DecryptedEncPart.SequenceNumber
	} else {
		if contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagMutual) {
			return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "acceptor did not return the required AP_REP"}
		}
		s.contextKey = s.replyKey
	}
	s.contextSend = uint64(s.authenticator.SeqNumber)
	s.contextReceive = uint64(s.sequenceNumber)
	s.acceptorSubkey = usesAcceptorSubkey

	if len(token.NegTokenResp.MechListMIC) > 0 {
		if err := token.NegTokenResp.VerifyMechListMIC(s.offeredMechTypes, s.contextKey); err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
		}
	} else if state == NegStateRequestMIC || s.requireMechMIC {
		return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: "acceptor did not return a required mechListMIC"}
	}

	if state == NegStateRequestMIC {
		mic, err := makeMechListMIC(s.offeredMechTypes, s.contextKey, initiatorMICFlags(usesAcceptorSubkey), uint64(s.authenticator.SeqNumber), keyusage.GSSAPI_INITIATOR_SIGN)
		if err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
		}
		s.responseToken = &SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{
			NegState: asn1.Enumerated(NegStateAcceptCompleted), MechListMIC: mic,
		}}
		if err := s.completeSecurityContext(true); err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
		}
		return false, s.context, gssapi.Status{Code: gssapi.StatusContinueNeeded}
	}

	if err := s.completeSecurityContext(true); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	s.responseToken = nil
	return true, s.context, gssapi.Status{Code: gssapi.StatusComplete}
}

func (s *SPNEGO) verifyInitiatorAPRep(reply *messages.APRep) (types.EncryptionKey, error) {
	if err := reply.Verify(s.authenticator, s.replyKey); err == nil {
		return s.replyKey, nil
	} else if len(s.ticketKey.KeyValue) == 0 {
		return types.EncryptionKey{}, err
	} else {
		subkeyErr := err
		if err := reply.Verify(s.authenticator, s.ticketKey); err == nil {
			return s.ticketKey, nil
		} else {
			return types.EncryptionKey{}, fmt.Errorf("verify AP_REP with authenticator subkey: %v; verify with ticket session key: %w", subkeyErr, err)
		}
	}
}

func containsMech(mechTypes []asn1.ObjectIdentifier, candidate asn1.ObjectIdentifier) bool {
	for _, mechType := range mechTypes {
		if mechType.Equal(candidate) {
			return true
		}
	}
	return false
}

func initiatorMICFlags(acceptorSubkey bool) byte {
	if acceptorSubkey {
		return gssapi.MICTokenFlagAcceptorSubkey
	}
	return 0
}

func negotiationKRB5Token(token *SPNEGOToken) (*KRB5Token, error) {
	if token.Init && token.NegTokenInit.mechToken != nil {
		mechanismToken, ok := token.NegTokenInit.mechToken.(*KRB5Token)
		if ok {
			return mechanismToken, nil
		}
	}
	if token.Resp && token.NegTokenResp.mechToken != nil {
		mechanismToken, ok := token.NegTokenResp.mechToken.(*KRB5Token)
		if ok {
			return mechanismToken, nil
		}
	}
	return nil, errors.New("SPNEGO token has no Kerberos mechanism token")
}

func contextKRB5Token(token gssapi.ContextToken, settings *service.Settings) (*KRB5Token, error) {
	if mechanismToken, ok := token.(*KRB5Token); ok {
		return mechanismToken, nil
	}
	spnegoToken, ok := token.(*SPNEGOToken)
	if !ok {
		return nil, errors.New("context token is neither SPNEGO nor Kerberos")
	}
	if spnegoToken.NegTokenResp.mechToken == nil {
		mechanismToken := new(KRB5Token)
		mechanismToken.settings = settings
		if err := mechanismToken.Unmarshal(spnegoToken.NegTokenResp.ResponseToken); err != nil {
			return nil, err
		}
		spnegoToken.NegTokenResp.mechToken = mechanismToken
	}
	return negotiationKRB5Token(spnegoToken)
}

func randomSequenceNumber() (int64, error) {
	var encoded [4]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint32(encoded[:]) & 0x3fffffff), nil
}

func microseconds(t time.Time) int {
	return int((t.UnixNano() / int64(time.Microsecond)) - t.Unix()*1e6)
}

func contextFlagSet(contextFlags []int, flag int) bool {
	for _, candidate := range contextFlags {
		if candidate == flag {
			return true
		}
	}
	return false
}

// Log will write to the service's logger if it is configured.
func (s *SPNEGO) Log(format string, v ...interface{}) {
	if s.serviceSettings.Logger() != nil {
		s.serviceSettings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// SPNEGOToken is a GSS-API context token
type SPNEGOToken struct {
	Init         bool
	Resp         bool
	NegTokenInit NegTokenInit
	NegTokenResp NegTokenResp
	settings     *service.Settings
	context      context.Context
}

// Marshal SPNEGO context token
func (s *SPNEGOToken) Marshal() ([]byte, error) {
	var b []byte
	if s.Init {
		hb, _ := asn1.Marshal(gssapi.OIDSPNEGO.OID())
		tb, err := s.NegTokenInit.Marshal()
		if err != nil {
			return b, fmt.Errorf("could not marshal NegTokenInit: %v", err)
		}
		b = append(hb, tb...)
		return asn1tools.AddASNAppTag(b, 0), nil
	}
	if s.Resp {
		b, err := s.NegTokenResp.Marshal()
		if err != nil {
			return b, fmt.Errorf("could not marshal NegTokenResp: %v", err)
		}
		return b, nil
	}
	return b, errors.New("SPNEGO cannot be marshalled. It contains neither a NegTokenInit or NegTokenResp")
}

// Unmarshal SPNEGO context token
func (s *SPNEGOToken) Unmarshal(b []byte) error {
	var r []byte
	var err error
	// We need some data in the array
	if len(b) < 1 {
		return fmt.Errorf("provided byte array is empty")
	}
	if b[0] != byte(161) {
		// Not a NegTokenResp/Targ could be a NegTokenInit
		var oid asn1.ObjectIdentifier
		r, err = asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
		if err != nil {
			return fmt.Errorf("not a valid SPNEGO token: %v", err)
		}
		// Check the OID is the SPNEGO OID value
		SPNEGOOID := gssapi.OIDSPNEGO.OID()
		if !oid.Equal(SPNEGOOID) {
			return fmt.Errorf("OID %s does not match SPNEGO OID %s", oid.String(), SPNEGOOID.String())
		}
	} else {
		// Could be a NegTokenResp/Targ
		r = b
	}

	_, nt, err := UnmarshalNegToken(r)
	if err != nil {
		return err
	}
	switch v := nt.(type) {
	case NegTokenInit:
		s.Init = true
		s.NegTokenInit = v
		s.NegTokenInit.settings = s.settings
	case NegTokenResp:
		s.Resp = true
		s.NegTokenResp = v
		s.NegTokenResp.settings = s.settings
	default:
		return errors.New("unknown choice type for NegotiationToken")
	}
	return nil
}

// Verify the SPNEGOToken
func (s *SPNEGOToken) Verify() (bool, gssapi.Status) {
	if (!s.Init && !s.Resp) || (s.Init && s.Resp) {
		return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "invalid SPNEGO token, unclear if NegTokenInit or NegTokenResp"}
	}
	if s.Init {
		s.NegTokenInit.settings = s.settings
		ok, status := s.NegTokenInit.Verify()
		if ok {
			s.context = s.NegTokenInit.Context()
		}
		return ok, status
	}
	if s.Resp {
		s.NegTokenResp.settings = s.settings
		ok, status := s.NegTokenResp.Verify()
		if ok {
			s.context = s.NegTokenResp.Context()
		}
		return ok, status
	}
	// should not be possible to get here
	return false, gssapi.Status{Code: gssapi.StatusFailure, Message: "unable to verify SPNEGO token"}
}

// Context returns the SPNEGO context which will contain any verify user identity information.
func (s *SPNEGOToken) Context() context.Context {
	return s.context
}
