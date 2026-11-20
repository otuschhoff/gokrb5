// Package spnego implements the Simple and Protected GSSAPI Negotiation Mechanism for Kerberos authentication.
package spnego

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
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
	contextSend      int64
	contextReceive   int64
	acceptorSubkey   bool
}

// SPNEGOClient configures the SPNEGO mechanism suitable for client side use.
//
//nolint:revive // Preserve the published constructor name.
func SPNEGOClient(cl *client.Client, spn string) *SPNEGO {
	return SPNEGOClientWithOptions(cl, spn, defaultKerberosTokenOptions())
}

// SPNEGOClientWithOptions configures a client with explicit GSS context options.
//
//nolint:revive // Preserve the published constructor name.
func SPNEGOClientWithOptions(cl *client.Client, spn string, options KRB5TokenAPREQOptions) *SPNEGO {
	s := new(SPNEGO)
	s.client = cl
	s.spn = spn
	s.initiatorOptions = options
	s.serviceSettings = service.NewSettings(nil, service.SName(spn))
	return s
}

// SPNEGOService configures the SPNEGO mechanism suitable for service side use.
//
//nolint:revive // Preserve the published constructor name.
func SPNEGOService(kt *keytab.Keytab, options ...func(*service.Settings)) *SPNEGO {
	return SPNEGOServiceWithMechTypes(kt, nil, options...)
}

// SPNEGOServiceWithMechTypes configures the acceptor's mechanism preference order.
// An empty list preserves the initiator's order.
//
//nolint:revive // Preserve the published constructor name.
func SPNEGOServiceWithMechTypes(
	kt *keytab.Keytab,
	mechTypes []asn1.ObjectIdentifier,
	options ...func(*service.Settings),
) *SPNEGO {
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
	if err := s.client.AffirmLogin(); err != nil {
		return fmt.Errorf("acquire SPNEGO initiator credentials: %w", err)
	}
	return nil
}

// InitSecContext is the GSS-API method for the client to a generate a context token to the service via Kerberos.
//
//nolint:ireturn // Implements gssapi.Mechanism and returns either a SPNEGO token or a raw Kerberos token.
func (s *SPNEGO) InitSecContext() (gssapi.ContextToken, error) {
	s.securityContext = nil
	tkt, key, err := s.client.GetServiceTicket(s.spn)
	if err != nil {
		return &SPNEGOToken{}, fmt.Errorf("obtain SPNEGO service ticket: %w", err)
	}
	negTokenInit, err := NewNegTokenInitKRB5WithOptions(s.client, tkt, key, s.initiatorOptions)
	if err != nil {
		return &SPNEGOToken{}, fmt.Errorf("could not create NegTokenInit: %w", err)
	}
	mechanismToken, ok := negTokenInit.mechToken.(*KRB5Token)
	if !ok || mechanismToken == nil {
		return &SPNEGOToken{}, errors.New("could not create NegTokenInit: mechanism token is not a Kerberos token")
	}
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
		s.contextSend = s.authenticator.SeqNumber
		s.contextReceive = 0
		s.acceptorSubkey = false
		if err := s.completeSecurityContext(true); err != nil {
			return &SPNEGOToken{}, fmt.Errorf("could not create security context: %w", err)
		}
	}
	if contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagDCEStyle) {
		mechanismToken.raw = true
		return mechanismToken, nil
	}
	token := new(SPNEGOToken)
	token.Init = true
	token.NegTokenInit = negTokenInit
	token.settings = s.serviceSettings
	return token, nil
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
	mechanismToken, ctx, ok, status := s.verifyInitialToken(ct)
	if !ok {
		return false, ctx, status
	}
	if mechanismToken == nil {
		return false, ctx, gssapi.Status{
			Code:    gssapi.StatusDefectiveToken,
			Message: "verified SPNEGO token has no Kerberos mechanism token",
		}
	}
	selection, err := s.acceptorSelection(ct, mechanismToken.replyKey)
	if err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
	}
	s.context = ctx
	s.contextReceive = mechanismToken.APReq.Authenticator.SeqNumber
	mutual := mechanismToken.checksum.Flags&(gssapi.ContextFlagMutual|gssapi.ContextFlagDCEStyle) != 0 ||
		types.IsFlagSet(&mechanismToken.APReq.APOptions, flags.APOptionMutualRequired)
	var established bool
	if mutual {
		established, err = s.acceptMutual(mechanismToken, selection)
	} else {
		established, err = s.acceptWithoutMutual(mechanismToken.replyKey, selection)
	}
	if err != nil {
		return false, ctx, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	if !established {
		return false, ctx, gssapi.Status{Code: gssapi.StatusContinueNeeded, Message: ""}
	}
	return true, ctx, status
}

// ResponseToken returns the output token generated by the latest context step.
//
//nolint:ireturn // The output may be a SPNEGO token or a raw Kerberos token.
func (s *SPNEGO) ResponseToken() gssapi.ContextToken {
	return s.responseToken
}

// SecurityContext returns the locally established RFC 4121 per-message security context.
// It returns nil until this peer has authenticated the remote peer and derived the context key.
// A context can therefore be available while a final output token still needs to be delivered.
//
//nolint:ireturn // Preserve the published return type.
func (s *SPNEGO) SecurityContext() gssapi.Context {
	return s.securityContext
}

// ContinueSecContext processes a mutual-authentication response or DCE final leg.
func (s *SPNEGO) ContinueSecContext(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	if s.client != nil && !contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagDCEStyle) {
		return s.continueInitiator(ct)
	}
	mechanismToken, err := s.continuationAPRep(ct)
	if err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}
	if s.client != nil {
		return s.continueDCEInitiator(ct, &mechanismToken.APRep)
	}
	return s.continueDCEAcceptor(&mechanismToken.APRep)
}

// Log will write to the service's logger if it is configured.
func (s *SPNEGO) Log(format string, v ...any) {
	if s.serviceSettings.Logger() != nil {
		const callerDepth = 2
		_ = s.serviceSettings.Logger().Output(callerDepth, fmt.Sprintf(format, v...)) // Best effort behind this void API.
	}
}

func (s *SPNEGO) verifyInitialToken(ct gssapi.ContextToken) (*KRB5Token, context.Context, bool, gssapi.Status) {
	switch token := ct.(type) {
	case *SPNEGOToken:
		if token == nil {
			return nil, nil, false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "SPNEGO context token is nil"}
		}
		return s.verifyInitialSPNEGO(token)
	case *KRB5Token:
		if token == nil {
			return nil, nil, false, gssapi.Status{
				Code:    gssapi.StatusDefectiveToken,
				Message: "Kerberos context token is nil",
			}
		}
		if !token.raw || !token.IsAPReq() {
			return nil, nil, false, gssapi.Status{
				Code:    gssapi.StatusDefectiveToken,
				Message: "raw context token is not a DCE AP_REQ",
			}
		}
		token.settings = s.serviceSettings
		ok, status := token.Verify()
		return token, token.Context(), ok, status
	default:
		return nil, nil, false, gssapi.Status{
			Code:    gssapi.StatusDefectiveToken,
			Message: "context token is neither SPNEGO nor Kerberos",
		}
	}
}

func (s *SPNEGO) verifyInitialSPNEGO(token *SPNEGOToken) (*KRB5Token, context.Context, bool, gssapi.Status) {
	token.settings = s.serviceSettings
	var oid asn1.ObjectIdentifier
	if token.Init && len(token.NegTokenInit.MechTypes) > 0 {
		oid = s.selectMech(token.NegTokenInit.MechTypes)
	}
	if token.Resp {
		oid = token.NegTokenResp.SupportedMech
	}
	if !isKerberosMech(oid) {
		return nil, nil, false, gssapi.Status{
			Code:    gssapi.StatusDefectiveToken,
			Message: "SPNEGO OID of MechToken is not of type KRB5",
		}
	}
	ok, status := token.Verify()
	ctx := token.Context()
	if !ok {
		return nil, ctx, false, status
	}
	mechanismToken, err := negotiationKRB5Token(token)
	if err != nil {
		return nil, ctx, false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}
	return mechanismToken, ctx, true, status
}

type acceptorSelection struct {
	offered    []asn1.ObjectIdentifier
	mechanism  asn1.ObjectIdentifier
	includeMIC bool
	requestMIC bool
}

func (s *SPNEGO) acceptorSelection(ct gssapi.ContextToken, key types.EncryptionKey) (acceptorSelection, error) {
	var selection acceptorSelection
	selection.mechanism = gssapi.OIDKRB5.OID()
	token, isSPNEGO := ct.(*SPNEGOToken)
	if !isSPNEGO || !token.Init {
		return selection, nil
	}
	selection.offered = token.NegTokenInit.MechTypes
	selection.mechanism = s.selectMech(selection.offered)
	micRequired := len(selection.offered) > 0 && !selection.mechanism.Equal(selection.offered[0])
	if len(token.NegTokenInit.MechListMIC) == 0 {
		selection.includeMIC = micRequired
		selection.requestMIC = micRequired
		return selection, nil
	}
	selection.includeMIC = true
	return selection, token.NegTokenInit.VerifyMechListMIC(key)
}

func (s *SPNEGO) acceptWithoutMutual(key types.EncryptionKey, selection acceptorSelection) (bool, error) {
	s.contextKey = key
	s.contextSend = 0
	s.acceptorSubkey = false
	if !selection.includeMIC {
		s.responseToken = nil
		return true, s.completeSecurityContext(false)
	}
	return s.acceptWithResponse(selection, nil)
}

func (s *SPNEGO) acceptMutual(mechanismToken *KRB5Token, selection acceptorSelection) (bool, error) {
	replyToken, err := s.buildAcceptorReply(mechanismToken)
	if err != nil {
		return false, err
	}
	if replyToken.raw {
		s.dcePending = true
		s.responseToken = &replyToken
		return false, nil
	}
	replyBytes, err := replyToken.Marshal()
	if err != nil {
		return false, err
	}
	return s.acceptWithResponse(selection, replyBytes)
}

func (s *SPNEGO) buildAcceptorReply(mechanismToken *KRB5Token) (KRB5Token, error) {
	if len(mechanismToken.replyKey.KeyValue) == 0 {
		return KRB5Token{}, errors.New("AP_REP reply key is missing")
	}
	et, err := krbcrypto.GetEtype(mechanismToken.replyKey.KeyType)
	if err != nil {
		return KRB5Token{}, fmt.Errorf("%w", err)
	}
	acceptorSubkey, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return KRB5Token{}, fmt.Errorf("%w", err)
	}
	sequenceNumber, err := randomSequenceNumber()
	if err != nil {
		return KRB5Token{}, err
	}
	dceStyle := mechanismToken.checksum.Flags&gssapi.ContextFlagDCEStyle != 0
	part := messages.EncAPRepPart{
		CTime:          mechanismToken.APReq.Authenticator.CTime,
		Cusec:          mechanismToken.APReq.Authenticator.Cusec,
		Subkey:         acceptorSubkey,
		SequenceNumber: sequenceNumber,
	}
	if dceStyle {
		part.CTime = time.Now().UTC()
		part.Cusec = microseconds(part.CTime)
	}
	reply, err := messages.NewAPRep(part, mechanismToken.replyKey)
	if err != nil {
		return KRB5Token{}, fmt.Errorf("%w", err)
	}
	replyToken := NewKRB5TokenAPREP(reply, dceStyle)
	s.contextKey = acceptorSubkey
	s.sequenceNumber = sequenceNumber
	s.contextSend = sequenceNumber
	s.acceptorSubkey = true
	return replyToken, nil
}

func (s *SPNEGO) acceptWithResponse(selection acceptorSelection, reply []byte) (bool, error) {
	response := mechanismResponse(NegStateAcceptCompleted, selection.mechanism, reply)
	if selection.requestMIC {
		response.NegState = asn1.Enumerated(NegStateRequestMIC)
		s.pendingMechMIC = true
		s.offeredMechTypes = append([]asn1.ObjectIdentifier(nil), selection.offered...)
	}
	if selection.includeMIC {
		// #nosec G115 -- contextSend is zero or the generated nonnegative 30-bit sequence number.
		sequenceValue := uint64(s.contextSend)
		if err := response.SetMechListMIC(selection.offered, s.contextKey, sequenceValue, s.acceptorSubkey); err != nil {
			return false, err
		}
	}
	s.setNegotiationResponse(response)
	if s.pendingMechMIC {
		return false, nil
	}
	return true, s.completeSecurityContext(false)
}

func (s *SPNEGO) setNegotiationResponse(response NegTokenResp) {
	s.responseToken = responseNegotiationToken(response)
}

func responseNegotiationToken(response NegTokenResp) *SPNEGOToken {
	token := new(SPNEGOToken)
	token.Resp = true
	token.NegTokenResp = response
	return token
}

func (s *SPNEGO) selectMech(offered []asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	for _, preferred := range s.preferredMechs {
		if !isKerberosMech(preferred) {
			continue
		}
		if i := slices.IndexFunc(offered, preferred.Equal); i >= 0 {
			return offered[i]
		}
	}
	for _, candidate := range offered {
		if isKerberosMech(candidate) {
			return candidate
		}
	}
	return nil
}

func (s *SPNEGO) acceptMechListMIC(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	token, ok := ct.(*SPNEGOToken)
	if !ok || token == nil || !token.Resp || token.NegTokenResp.State() != NegStateAcceptCompleted {
		return false, s.context, gssapi.Status{
			Code:    gssapi.StatusDefectiveToken,
			Message: "expected an accept-completed SPNEGO mechListMIC response",
		}
	}
	err := verifyMechListMIC(
		s.offeredMechTypes,
		token.NegTokenResp.MechListMIC,
		s.contextKey,
		false,
		keyusage.GSSAPI_INITIATOR_SIGN,
	)
	if err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
	}
	s.pendingMechMIC = false
	s.responseToken = nil
	if contextErr := s.completeSecurityContext(false); contextErr != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: contextErr.Error()}
	}
	return true, s.context, gssapi.Status{Code: gssapi.StatusComplete, Message: ""}
}

func (s *SPNEGO) completeSecurityContext(initiator bool) error {
	contextSend, err := sequenceNumberUint64(s.contextSend)
	if err != nil {
		return err
	}
	contextReceive, err := sequenceNumberUint64(s.contextReceive)
	if err != nil {
		return err
	}
	securityContext, err := gssapi.NewSecurityContext(
		s.contextKey,
		initiator,
		contextSend,
		contextReceive,
		s.acceptorSubkey,
	)
	if err != nil {
		return fmt.Errorf("create SPNEGO security context: %w", err)
	}
	s.securityContext = securityContext
	return nil
}

func (s *SPNEGO) continuationAPRep(ct gssapi.ContextToken) (*KRB5Token, error) {
	token, err := contextKRB5Token(ct, s.serviceSettings)
	if err != nil {
		return nil, err
	}
	if token == nil || !token.IsAPRep() {
		return nil, errors.New("continuation token is not an AP_REP")
	}
	return token, nil
}

func (s *SPNEGO) continueDCEInitiator(
	ct gssapi.ContextToken,
	reply *messages.APRep,
) (bool, context.Context, gssapi.Status) {
	if err := reply.VerifyDCE(s.replyKey, -1, false, s.serviceSettings.MaxClockSkew()); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}
	s.useAcceptorReply(&reply.DecryptedEncPart, s.replyKey)
	if token, ok := ct.(*SPNEGOToken); ok {
		if err := s.verifyResponseMIC(&token.NegTokenResp, s.requireMechMIC); err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
		}
	}
	finalToken, err := s.dceFinalReply()
	if err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	s.responseToken = &finalToken
	return true, s.context, gssapi.Status{Code: gssapi.StatusComplete, Message: ""}
}

func (s *SPNEGO) dceFinalReply() (KRB5Token, error) {
	now := time.Now().UTC()
	finalReply, err := messages.NewAPRep(messages.EncAPRepPart{
		CTime:          now,
		Cusec:          microseconds(now),
		Subkey:         types.EncryptionKey{KeyType: 0, KeyValue: nil},
		SequenceNumber: s.sequenceNumber,
	}, s.contextKey)
	if err != nil {
		return KRB5Token{}, fmt.Errorf("%w", err)
	}
	finalToken := NewKRB5TokenAPREP(finalReply, true)
	if contextErr := s.completeSecurityContext(true); contextErr != nil {
		return KRB5Token{}, contextErr
	}
	return finalToken, nil
}

func (s *SPNEGO) continueDCEAcceptor(reply *messages.APRep) (bool, context.Context, gssapi.Status) {
	if !s.dcePending {
		return false, s.context, gssapi.Status{
			Code:    gssapi.StatusNoContext,
			Message: "no DCE context continuation is pending",
		}
	}
	if err := reply.VerifyDCE(s.contextKey, s.sequenceNumber, true, s.serviceSettings.MaxClockSkew()); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}
	s.dcePending = false
	s.responseToken = nil
	if err := s.completeSecurityContext(false); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	return true, s.context, gssapi.Status{Code: gssapi.StatusComplete, Message: ""}
}

func (s *SPNEGO) continueInitiator(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status) {
	token, ok := ct.(*SPNEGOToken)
	if !ok || !isResponseToken(token) {
		return false, s.context, gssapi.Status{
			Code:    gssapi.StatusDefectiveToken,
			Message: "continuation token is not a NegTokenResp",
		}
	}
	response := &token.NegTokenResp
	if err := s.validateInitiatorResponse(response); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusBadMech, Message: err.Error()}
	}
	if err := s.applyInitiatorReply(token); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
	}
	state := response.State()
	if err := s.verifyResponseMIC(response, state == NegStateRequestMIC || s.requireMechMIC); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusBadMIC, Message: err.Error()}
	}
	if state == NegStateRequestMIC {
		if err := s.sendInitiatorMIC(); err != nil {
			return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
		}
		return false, s.context, gssapi.Status{Code: gssapi.StatusContinueNeeded, Message: ""}
	}

	if err := s.completeSecurityContext(true); err != nil {
		return false, s.context, gssapi.Status{Code: gssapi.StatusFailure, Message: err.Error()}
	}
	s.responseToken = nil
	return true, s.context, gssapi.Status{Code: gssapi.StatusComplete, Message: ""}
}

func isResponseToken(token *SPNEGOToken) bool {
	return token != nil && token.Resp
}

func (s *SPNEGO) validateInitiatorResponse(response *NegTokenResp) error {
	if response.State() == NegStateReject {
		return errors.New("SPNEGO negotiation was rejected")
	}
	if len(response.SupportedMech) > 0 && !containsMech(s.offeredMechTypes, response.SupportedMech) {
		return errors.New("acceptor selected a mechanism that was not offered")
	}
	return nil
}

func (s *SPNEGO) applyInitiatorReply(token *SPNEGOToken) error {
	if len(token.NegTokenResp.ResponseToken) == 0 {
		if contextFlagSet(s.initiatorOptions.GSSAPIFlags, gssapi.ContextFlagMutual) {
			return errors.New("acceptor did not return the required AP_REP")
		}
		s.contextKey = s.replyKey
		s.contextSend = s.authenticator.SeqNumber
		s.contextReceive = s.sequenceNumber
		s.acceptorSubkey = false
		return nil
	}
	mechanismToken, err := s.continuationAPRep(token)
	if err != nil {
		return err
	}
	verifiedKey, err := s.verifyInitiatorAPRep(&mechanismToken.APRep)
	if err != nil {
		return err
	}
	s.useAcceptorReply(&mechanismToken.APRep.DecryptedEncPart, verifiedKey)
	return nil
}

func (s *SPNEGO) useAcceptorReply(part *messages.EncAPRepPart, fallback types.EncryptionKey) {
	s.contextKey = part.Subkey
	s.acceptorSubkey = len(part.Subkey.KeyValue) > 0
	if !s.acceptorSubkey {
		s.contextKey = fallback
	}
	s.sequenceNumber = part.SequenceNumber
	s.contextSend = s.authenticator.SeqNumber
	s.contextReceive = s.sequenceNumber
}

func (s *SPNEGO) verifyResponseMIC(response *NegTokenResp, required bool) error {
	if len(response.MechListMIC) > 0 {
		return response.VerifyMechListMIC(s.offeredMechTypes, s.contextKey)
	}
	if required {
		return errors.New("acceptor did not return a required mechListMIC")
	}
	return nil
}

func (s *SPNEGO) sendInitiatorMIC() error {
	mic, err := makeInitiatorMechListMIC(s.offeredMechTypes, s.contextKey, s.acceptorSubkey, s.authenticator.SeqNumber)
	if err != nil {
		return err
	}
	response := mechanismResponse(NegStateAcceptCompleted, nil, nil)
	response.MechListMIC = mic
	s.setNegotiationResponse(response)
	return s.completeSecurityContext(true)
}

func (s *SPNEGO) verifyInitiatorAPRep(reply *messages.APRep) (types.EncryptionKey, error) {
	subkeyErr := reply.Verify(s.authenticator, s.replyKey)
	if subkeyErr == nil {
		return s.replyKey, nil
	}
	if len(s.ticketKey.KeyValue) == 0 {
		return types.EncryptionKey{}, fmt.Errorf("verify AP_REP with authenticator subkey: %w", subkeyErr)
	}
	ticketErr := reply.Verify(s.authenticator, s.ticketKey)
	if ticketErr == nil {
		return s.ticketKey, nil
	}
	return types.EncryptionKey{}, fmt.Errorf(
		"verify AP_REP with authenticator subkey: %w; verify with ticket session key: %w", subkeyErr, ticketErr,
	)
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
	if !ok || spnegoToken == nil {
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

const maxGSSSequence = 0x3fffffff

func sequenceNumberUint64(sequence int64) (uint64, error) {
	if sequence < 0 || sequence > maxGSSSequence {
		return 0, fmt.Errorf("invalid GSSAPI sequence number %d", sequence)
	}
	return uint64(sequence), nil
}

func makeInitiatorMechListMIC(
	mechTypes []asn1.ObjectIdentifier,
	key types.EncryptionKey,
	acceptorSubkey bool,
	sequence int64,
) ([]byte, error) {
	sequenceNumber, err := sequenceNumberUint64(sequence)
	if err != nil {
		return nil, err
	}
	return makeMechListMIC(
		mechTypes,
		key,
		initiatorMICFlags(acceptorSubkey),
		sequenceNumber,
		keyusage.GSSAPI_INITIATOR_SIGN,
	)
}

func randomSequenceNumber() (int64, error) {
	var encoded [4]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return 0, fmt.Errorf("generate SPNEGO sequence number: %w", err)
	}
	return int64(binary.BigEndian.Uint32(encoded[:]) & maxGSSSequence), nil
}

func microseconds(t time.Time) int {
	return int((t.UnixNano() / int64(time.Microsecond)) - t.Unix()*1e6)
}

func contextFlagSet(contextFlags []int, flag int) bool {
	return slices.Contains(contextFlags, flag)
}

// SPNEGOToken is a GSS-API context token
//
//nolint:revive // Preserve the published token type name.
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
			return b, fmt.Errorf("could not marshal NegTokenInit: %w", err)
		}
		hb = append(hb, tb...)
		return asn1tools.AddASNAppTag(hb, 0), nil
	}
	if s.Resp {
		rb, err := s.NegTokenResp.Marshal()
		if err != nil {
			return b, fmt.Errorf("could not marshal NegTokenResp: %w", err)
		}
		return rb, nil
	}
	return b, errors.New("SPNEGO cannot be marshalled. It contains neither a NegTokenInit or NegTokenResp")
}

// Unmarshal SPNEGO context token
func (s *SPNEGOToken) Unmarshal(b []byte) error {
	var r []byte
	var err error
	// We need some data in the array
	if len(b) < 1 {
		return errors.New("provided byte array is empty")
	}
	const negTokenResponseTag = 0xa1
	if b[0] != negTokenResponseTag {
		// Not a NegTokenResp/Targ could be a NegTokenInit
		var oid asn1.ObjectIdentifier
		r, err = asn1.UnmarshalWithParams(b, &oid, "application,explicit,tag:0")
		if err != nil {
			return fmt.Errorf("not a valid SPNEGO token: %w", err)
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
		return false, gssapi.Status{
			Code:    gssapi.StatusDefectiveToken,
			Message: "invalid SPNEGO token, unclear if NegTokenInit or NegTokenResp",
		}
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
