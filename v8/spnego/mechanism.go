package spnego

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

var (
	ErrNoMechanisms       = errors.New("SPNEGO has no configured mechanisms")
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
	return &Negotiator{mechanisms: uniqueContextMechanisms(mechanisms)}
}

// OID returns the SPNEGO mechanism OID.
func (n *Negotiator) OID() asn1.ObjectIdentifier { return gssapi.OIDSPNEGO.OID() }

// InitSecContext advances an initiator SPNEGO exchange.
func (n *Negotiator) InitSecContext(target string, input []byte, options ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	if n.initiator == nil {
		n.initiator = &mechanismConversation{initiator: true, target: target, mechanisms: n.mechanisms}
	} else if n.initiator.target != target {
		return nil, nil, false, errors.New("SPNEGO target changed during context establishment")
	}
	return n.initiator.initStep(input, options...)
}

// AcceptSecContext advances an acceptor SPNEGO exchange.
func (n *Negotiator) AcceptSecContext(input []byte, options ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	if n.acceptor == nil {
		n.acceptor = &mechanismConversation{mechanisms: n.mechanisms}
	}
	return n.acceptor.acceptStep(input, options...)
}

func (c *mechanismConversation) initStep(input []byte, options ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	if c.step == 0 {
		if len(input) != 0 {
			return nil, nil, false, ErrUnexpectedSPNEGO
		}
		if len(c.mechanisms) == 0 {
			return nil, nil, false, ErrNoMechanisms
		}
		c.offered = mechanismOIDs(c.mechanisms)
		c.selected = c.mechanisms[0]
		mechanismToken, context, done, err := c.selected.InitSecContext(c.target, nil, options...)
		if err != nil {
			return nil, nil, false, err
		}
		c.context, c.mechanismDone, c.step = context, done, 1
		output, err := marshalSPNEGOToken(&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{
			MechTypes: c.offered, MechTokenBytes: mechanismToken,
		}})
		return output, c.context, false, err
	}

	token, err := parseSPNEGOResponse(input)
	if err != nil {
		return nil, c.context, false, err
	}
	state := token.NegTokenResp.State()
	if state == NegStateReject {
		return nil, c.context, false, ErrNoCommonMechanism
	}
	if len(token.NegTokenResp.SupportedMech) > 0 {
		selected := findContextMechanism(c.mechanisms, token.NegTokenResp.SupportedMech)
		if selected == nil || !containsMech(c.offered, token.NegTokenResp.SupportedMech) {
			return nil, c.context, false, ErrNoCommonMechanism
		}
		if c.step == 1 && !selected.OID().Equal(c.selected.OID()) {
			c.context, c.mechanismDone = nil, false
		}
		c.selected = selected
	}
	c.requireMIC = c.requireMIC || !c.selected.OID().Equal(c.offered[0]) || state == NegStateRequestMIC

	mechanismToken := token.NegTokenResp.ResponseToken
	var output []byte
	if !c.mechanismDone || len(mechanismToken) > 0 {
		output, c.context, c.mechanismDone, err = c.selected.InitSecContext(c.target, mechanismToken, options...)
		if err != nil {
			return nil, c.context, false, err
		}
	}
	if len(token.NegTokenResp.MechListMIC) > 0 {
		if c.context == nil {
			return nil, nil, false, ErrUnexpectedSPNEGO
		}
		mechList, marshalErr := MarshalMechTypeList(c.offered)
		if marshalErr != nil {
			return nil, c.context, false, marshalErr
		}
		if err := c.context.VerifyMIC(mechList, token.NegTokenResp.MechListMIC); err != nil {
			return nil, c.context, false, err
		}
	} else if state == NegStateRequestMIC {
		return nil, c.context, false, ErrMissingMechListMIC
	}
	c.step++

	response := NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptIncomplete), ResponseToken: output}
	if state == NegStateRequestMIC {
		if !c.mechanismDone || c.context == nil {
			return nil, c.context, false, ErrUnexpectedSPNEGO
		}
		mechList, marshalErr := MarshalMechTypeList(c.offered)
		if marshalErr != nil {
			return nil, c.context, false, marshalErr
		}
		response.MechListMIC, err = c.context.GetMIC(mechList)
		if err != nil {
			return nil, c.context, false, err
		}
		response.NegState = asn1.Enumerated(NegStateAcceptCompleted)
		encoded, marshalErr := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: response})
		return encoded, c.context, true, marshalErr
	}
	if c.mechanismDone && state == NegStateAcceptCompleted && len(output) == 0 {
		return nil, c.context, true, nil
	}
	encoded, marshalErr := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: response})
	return encoded, c.context, false, marshalErr
}

func (c *mechanismConversation) acceptStep(input []byte, options ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	if len(input) == 0 {
		return nil, c.context, false, ErrUnexpectedSPNEGO
	}
	var mechanismInput []byte
	if c.step == 0 {
		token, err := parseSPNEGOInitiator(input)
		if err != nil {
			return nil, nil, false, err
		}
		c.offered = append([]asn1.ObjectIdentifier(nil), token.NegTokenInit.MechTypes...)
		c.selected = selectContextMechanism(c.mechanisms, c.offered)
		if c.selected == nil {
			return marshalReject()
		}
		c.requireMIC = len(c.offered) > 0 && !c.selected.OID().Equal(c.offered[0])
		if !c.requireMIC {
			mechanismInput = token.NegTokenInit.MechTokenBytes
		}
		c.step = 1
	} else {
		token, err := parseSPNEGOResponse(input)
		if err != nil {
			return nil, c.context, false, err
		}
		if c.waitingMIC {
			if len(token.NegTokenResp.MechListMIC) == 0 || c.context == nil {
				return nil, c.context, false, ErrMissingMechListMIC
			}
			mechList, marshalErr := MarshalMechTypeList(c.offered)
			if marshalErr != nil {
				return nil, c.context, false, marshalErr
			}
			if err := c.context.VerifyMIC(mechList, token.NegTokenResp.MechListMIC); err != nil {
				return nil, c.context, false, err
			}
			c.waitingMIC = false
			return nil, c.context, true, nil
		}
		mechanismInput = token.NegTokenResp.ResponseToken
		c.step++
	}

	if len(mechanismInput) == 0 {
		response := NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptIncomplete), SupportedMech: c.selected.OID()}
		encoded, err := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: response})
		return encoded, c.context, false, err
	}
	mechanismOutput, context, done, err := c.selected.AcceptSecContext(mechanismInput, options...)
	if err != nil {
		if c.step != 1 {
			return nil, c.context, false, err
		}
		response := NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptIncomplete), SupportedMech: c.selected.OID()}
		encoded, marshalErr := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: response})
		return encoded, c.context, false, marshalErr
	}
	c.context, c.mechanismDone = context, done
	response := NegTokenResp{SupportedMech: c.selected.OID(), ResponseToken: mechanismOutput}
	if !done {
		response.NegState = asn1.Enumerated(NegStateAcceptIncomplete)
		encoded, marshalErr := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: response})
		return encoded, c.context, false, marshalErr
	}
	if c.requireMIC {
		if c.context == nil {
			return nil, nil, false, ErrUnexpectedSPNEGO
		}
		mechList, marshalErr := MarshalMechTypeList(c.offered)
		if marshalErr != nil {
			return nil, c.context, false, marshalErr
		}
		response.MechListMIC, err = c.context.GetMIC(mechList)
		if err != nil {
			return nil, c.context, false, err
		}
		response.NegState = asn1.Enumerated(NegStateRequestMIC)
		c.waitingMIC = true
		encoded, marshalErr := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: response})
		return encoded, c.context, false, marshalErr
	}
	response.NegState = asn1.Enumerated(NegStateAcceptCompleted)
	encoded, marshalErr := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: response})
	return encoded, c.context, true, marshalErr
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

func marshalSPNEGOToken(token *SPNEGOToken) ([]byte, error) { return token.Marshal() }

func marshalReject() ([]byte, gssapi.Context, bool, error) {
	encoded, err := marshalSPNEGOToken(&SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{NegState: asn1.Enumerated(NegStateReject)}})
	return encoded, nil, false, err
}

func uniqueContextMechanisms(mechanisms []gssapi.ContextMechanism) []gssapi.ContextMechanism {
	result := make([]gssapi.ContextMechanism, 0, len(mechanisms))
	for _, mechanism := range mechanisms {
		if mechanism == nil || findContextMechanism(result, mechanism.OID()) != nil {
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

func findContextMechanism(mechanisms []gssapi.ContextMechanism, oid asn1.ObjectIdentifier) gssapi.ContextMechanism {
	for _, mechanism := range mechanisms {
		if mechanism.OID().Equal(oid) {
			return mechanism
		}
	}
	return nil
}

func selectContextMechanism(mechanisms []gssapi.ContextMechanism, offered []asn1.ObjectIdentifier) gssapi.ContextMechanism {
	for _, mechanism := range mechanisms {
		if containsMech(offered, mechanism.OID()) {
			return mechanism
		}
	}
	return nil
}

func (c *mechanismConversation) String() string {
	if c.selected == nil {
		return "SPNEGO(unselected)"
	}
	return fmt.Sprintf("SPNEGO(%s)", c.selected.OID().String())
}

var _ gssapi.ContextMechanism = (*Negotiator)(nil)
