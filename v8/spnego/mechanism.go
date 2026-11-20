package spnego

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

// SPNEGO mechanism negotiation errors.
var (
	// ErrNoMechanisms indicates SPNEGO has no configured mechanisms.
	ErrNoMechanisms = errors.New("SPNEGO has no configured mechanisms")
	// ErrNoCommonMechanism indicates SPNEGO peers share no mechanism.
	ErrNoCommonMechanism  = errors.New("SPNEGO has no mutually supported mechanism")
	ErrUnexpectedSPNEGO   = errors.New("unexpected SPNEGO token")
	ErrMissingMechListMIC = errors.New("SPNEGO mechListMIC is missing")
)

// Negotiator performs byte-oriented SPNEGO negotiation over a configured set
// of GSS mechanisms. Existing Kerberos-specific SPNEGO APIs remain unchanged.
type Negotiator struct {
	mechanisms []gssapi.ContextMechanism
	initiator  *mechanismConversation
	acceptor   *mechanismConversation
}

type mechanismConversation struct {
	initiator     bool
	target        string
	mechanisms    []gssapi.ContextMechanism
	selected      gssapi.ContextMechanism
	context       gssapi.Context
	offered       []asn1.ObjectIdentifier
	step          uint32
	mechanismDone bool
	requireMIC    bool
	waitingMIC    bool
}

// NewNegotiator creates a stateful SPNEGO negotiator in preference order.
func NewNegotiator(mechanisms ...gssapi.ContextMechanism) *Negotiator {
	return &Negotiator{mechanisms: uniqueContextMechanisms(mechanisms), initiator: nil, acceptor: nil}
}

// OID returns the SPNEGO mechanism OID.
func (n *Negotiator) OID() asn1.ObjectIdentifier { return gssapi.OIDSPNEGO.OID() }

// InitSecContext advances an initiator SPNEGO exchange.
//
//nolint:ireturn // Implements gssapi.ContextMechanism for arbitrary configured mechanisms.
func (n *Negotiator) InitSecContext(
	target string,
	input []byte,
	options ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	if n.initiator == nil {
		n.initiator = new(mechanismConversation)
		n.initiator.initiator = true
		n.initiator.target = target
		n.initiator.mechanisms = n.mechanisms
	} else if n.initiator.target != target {
		return nil, nil, false, errors.New("SPNEGO target changed during context establishment")
	}
	return n.initiator.initStep(input, options...)
}

// AcceptSecContext advances an acceptor SPNEGO exchange.
//
//nolint:ireturn // Implements gssapi.ContextMechanism for arbitrary configured mechanisms.
func (n *Negotiator) AcceptSecContext(
	input []byte,
	options ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	if n.acceptor == nil {
		n.acceptor = new(mechanismConversation)
		n.acceptor.mechanisms = n.mechanisms
	}
	return n.acceptor.acceptStep(input, options...)
}

func (c *mechanismConversation) String() string {
	if c.selected == nil {
		return "SPNEGO(unselected)"
	}
	return fmt.Sprintf("SPNEGO(%s)", c.selected.OID().String())
}

//nolint:ireturn // The negotiated context is supplied by the selected mechanism.
func (c *mechanismConversation) initStep(
	input []byte,
	options ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	if c.step == 0 {
		output, err := c.startInitiator(input, options...)
		if c.step == 0 {
			return nil, nil, false, err
		}
		return output, c.context, false, err
	}

	token, err := parseSPNEGOResponse(input)
	if err != nil {
		return nil, c.context, false, err
	}
	response := &token.NegTokenResp
	if selectionErr := c.applyPeerSelection(response); selectionErr != nil {
		return nil, c.context, false, selectionErr
	}
	var output []byte
	if !c.mechanismDone || len(response.ResponseToken) > 0 {
		output, c.context, c.mechanismDone, err = c.selected.InitSecContext(c.target, response.ResponseToken, options...)
		if err != nil {
			return nil, c.context, false, fmt.Errorf("continue SPNEGO initiator mechanism: %w", err)
		}
	}
	if micErr := c.verifyAcceptorMIC(response); micErr != nil {
		return nil, c.context, false, micErr
	}
	c.step++
	output, done, err := c.finishInitiator(response.State(), output)
	return output, c.context, done, err
}

func (c *mechanismConversation) startInitiator(input []byte, options ...gssapi.MechanismOption) ([]byte, error) {
	if len(input) != 0 {
		return nil, ErrUnexpectedSPNEGO
	}
	if len(c.mechanisms) == 0 {
		return nil, ErrNoMechanisms
	}
	c.offered = mechanismOIDs(c.mechanisms)
	c.selected = c.mechanisms[0]
	mechanismToken, ctx, done, err := c.selected.InitSecContext(c.target, nil, options...)
	if err != nil {
		return nil, fmt.Errorf("start SPNEGO initiator mechanism: %w", err)
	}
	c.context, c.mechanismDone, c.step = ctx, done, 1
	var token SPNEGOToken
	token.Init = true
	token.NegTokenInit.MechTypes = c.offered
	token.NegTokenInit.MechTokenBytes = mechanismToken
	return token.Marshal()
}

func (c *mechanismConversation) applyPeerSelection(response *NegTokenResp) error {
	if response.State() == NegStateReject {
		return ErrNoCommonMechanism
	}
	if len(response.SupportedMech) != 0 {
		if err := c.updateSelectedMechanism(response.SupportedMech); err != nil {
			return err
		}
	}
	c.requireMIC = c.requireMIC || !c.selected.OID().Equal(c.offered[0]) || response.State() == NegStateRequestMIC
	return nil
}

func (c *mechanismConversation) updateSelectedMechanism(oid asn1.ObjectIdentifier) error {
	index := findContextMechanism(c.mechanisms, oid)
	if index < 0 || !containsMech(c.offered, oid) {
		return ErrNoCommonMechanism
	}
	selected := c.mechanisms[index]
	if c.step == 1 && !selected.OID().Equal(c.selected.OID()) {
		c.context, c.mechanismDone = nil, false
	}
	c.selected = selected
	return nil
}

func (c *mechanismConversation) verifyAcceptorMIC(response *NegTokenResp) error {
	if len(response.MechListMIC) == 0 {
		if response.State() == NegStateRequestMIC {
			return ErrMissingMechListMIC
		}
		return nil
	}
	if c.context == nil {
		return ErrUnexpectedSPNEGO
	}
	return c.verifyMechanismListMIC(response.MechListMIC, "acceptor")
}

func (c *mechanismConversation) finishInitiator(state NegState, output []byte) ([]byte, bool, error) {
	var response NegTokenResp
	response.NegState = asn1.Enumerated(NegStateAcceptIncomplete)
	response.ResponseToken = output
	if state == NegStateRequestMIC {
		if !c.mechanismDone || c.context == nil {
			return nil, false, ErrUnexpectedSPNEGO
		}
		mic, err := c.signMechanismList("initiator")
		if err != nil {
			return nil, false, err
		}
		response.MechListMIC = mic
		response.NegState = asn1.Enumerated(NegStateAcceptCompleted)
		encoded, marshalErr := marshalMechanismResponse(response)
		return encoded, true, marshalErr
	}
	if c.mechanismDone && state == NegStateAcceptCompleted && len(output) == 0 {
		return nil, true, nil
	}
	encoded, err := marshalMechanismResponse(response)
	return encoded, false, err
}

//nolint:ireturn // The negotiated context is supplied by the selected mechanism.
func (c *mechanismConversation) acceptStep(
	input []byte,
	options ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	if len(input) == 0 {
		return nil, c.context, false, ErrUnexpectedSPNEGO
	}
	if c.step == 0 {
		mechanismInput, err := c.selectOfferedMechanism(input)
		if errors.Is(err, ErrNoCommonMechanism) {
			encoded, marshalErr := marshalMechanismResponse(mechanismResponse(NegStateReject, nil, nil))
			return encoded, nil, false, marshalErr
		}
		if err != nil {
			return nil, nil, false, err
		}
		encoded, done, err := c.acceptMechanismInput(mechanismInput, options...)
		return encoded, c.context, done, err
	}

	token, err := parseSPNEGOResponse(input)
	if err != nil {
		return nil, c.context, false, err
	}
	if c.waitingMIC {
		if micErr := c.finishAcceptorMIC(token.NegTokenResp.MechListMIC); micErr != nil {
			return nil, c.context, false, micErr
		}
		return nil, c.context, true, nil
	}
	c.step++
	encoded, done, err := c.acceptMechanismInput(token.NegTokenResp.ResponseToken, options...)
	return encoded, c.context, done, err
}

func (c *mechanismConversation) selectOfferedMechanism(input []byte) ([]byte, error) {
	token, err := parseSPNEGOInitiator(input)
	if err != nil {
		return nil, err
	}
	c.offered = append([]asn1.ObjectIdentifier(nil), token.NegTokenInit.MechTypes...)
	index := selectContextMechanism(c.mechanisms, c.offered)
	if index < 0 {
		c.selected = nil
		return nil, ErrNoCommonMechanism
	}
	c.selected = c.mechanisms[index]
	c.requireMIC = len(c.offered) > 0 && !c.selected.OID().Equal(c.offered[0])
	c.step = 1
	if c.requireMIC {
		return nil, nil
	}
	return token.NegTokenInit.MechTokenBytes, nil
}

func (c *mechanismConversation) finishAcceptorMIC(mic []byte) error {
	if len(mic) == 0 || c.context == nil {
		return ErrMissingMechListMIC
	}
	if err := c.verifyMechanismListMIC(mic, "initiator"); err != nil {
		return err
	}
	c.waitingMIC = false
	return nil
}

func (c *mechanismConversation) acceptMechanismInput(
	mechanismInput []byte,
	options ...gssapi.MechanismOption,
) ([]byte, bool, error) {
	if len(mechanismInput) == 0 {
		return c.requestMechanismToken()
	}
	mechanismOutput, ctx, done, err := c.selected.AcceptSecContext(mechanismInput, options...)
	if err != nil {
		if c.step != 1 {
			return nil, false, fmt.Errorf("continue SPNEGO acceptor mechanism: %w", err)
		}
		return c.requestMechanismToken()
	}
	c.context, c.mechanismDone = ctx, done
	return c.finishAcceptor(mechanismOutput)
}

func (c *mechanismConversation) requestMechanismToken() ([]byte, bool, error) {
	encoded, err := marshalMechanismResponse(mechanismResponse(NegStateAcceptIncomplete, c.selected.OID(), nil))
	return encoded, false, err
}

func (c *mechanismConversation) finishAcceptor(output []byte) ([]byte, bool, error) {
	response := mechanismResponse(NegStateAcceptIncomplete, c.selected.OID(), output)
	if !c.mechanismDone {
		encoded, err := marshalMechanismResponse(response)
		return encoded, false, err
	}
	if c.requireMIC {
		if c.context == nil {
			return nil, false, ErrUnexpectedSPNEGO
		}
		mic, err := c.signMechanismList("acceptor")
		if err != nil {
			return nil, false, err
		}
		response.MechListMIC = mic
		response.NegState = asn1.Enumerated(NegStateRequestMIC)
		c.waitingMIC = true
		encoded, marshalErr := marshalMechanismResponse(response)
		return encoded, false, marshalErr
	}
	response.NegState = asn1.Enumerated(NegStateAcceptCompleted)
	encoded, err := marshalMechanismResponse(response)
	return encoded, true, err
}

func (c *mechanismConversation) verifyMechanismListMIC(mic []byte, peer string) error {
	mechList, err := MarshalMechTypeList(c.offered)
	if err != nil {
		return err
	}
	if verifyErr := c.context.VerifyMIC(mechList, mic); verifyErr != nil {
		return fmt.Errorf("verify %s mechListMIC: %w", peer, verifyErr)
	}
	return nil
}

func (c *mechanismConversation) signMechanismList(role string) ([]byte, error) {
	mechList, err := MarshalMechTypeList(c.offered)
	if err != nil {
		return nil, err
	}
	mic, err := c.context.GetMIC(mechList)
	if err != nil {
		return nil, fmt.Errorf("generate %s mechListMIC: %w", role, err)
	}
	return mic, nil
}

func parseSPNEGOInitiator(input []byte) (*SPNEGOToken, error) {
	var token SPNEGOToken
	if err := token.Unmarshal(input); err != nil {
		return nil, err
	}
	if !token.Init || len(token.NegTokenInit.MechTypes) == 0 {
		return nil, ErrUnexpectedSPNEGO
	}
	return &token, nil
}

func parseSPNEGOResponse(input []byte) (*SPNEGOToken, error) {
	var token SPNEGOToken
	if err := token.Unmarshal(input); err != nil {
		return nil, err
	}
	if !token.Resp {
		return nil, ErrUnexpectedSPNEGO
	}
	return &token, nil
}

func mechanismResponse(state NegState, oid asn1.ObjectIdentifier, output []byte) NegTokenResp {
	var response NegTokenResp
	response.NegState = asn1.Enumerated(state)
	response.SupportedMech = oid
	response.ResponseToken = output
	return response
}

func marshalMechanismResponse(response NegTokenResp) ([]byte, error) {
	return responseNegotiationToken(response).Marshal()
}

func uniqueContextMechanisms(mechanisms []gssapi.ContextMechanism) []gssapi.ContextMechanism {
	result := make([]gssapi.ContextMechanism, 0, len(mechanisms))
	for _, mechanism := range mechanisms {
		if mechanism == nil || findContextMechanism(result, mechanism.OID()) >= 0 {
			continue
		}
		result = append(result, mechanism)
	}
	return result
}

func mechanismOIDs(mechanisms []gssapi.ContextMechanism) []asn1.ObjectIdentifier {
	oids := make([]asn1.ObjectIdentifier, len(mechanisms))
	for index, mechanism := range mechanisms {
		oids[index] = append(asn1.ObjectIdentifier(nil), mechanism.OID()...)
	}
	return oids
}

func findContextMechanism(mechanisms []gssapi.ContextMechanism, oid asn1.ObjectIdentifier) int {
	for i, mechanism := range mechanisms {
		if mechanism.OID().Equal(oid) {
			return i
		}
	}
	return -1
}

func selectContextMechanism(mechanisms []gssapi.ContextMechanism, offered []asn1.ObjectIdentifier) int {
	for i, mechanism := range mechanisms {
		if containsMech(offered, mechanism.OID()) {
			return i
		}
	}
	return -1
}

var _ gssapi.ContextMechanism = (*Negotiator)(nil)
