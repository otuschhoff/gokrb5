package spnego

import (
	"context"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// https://msdn.microsoft.com/en-us/library/ms995330.aspx

// Negotiation state values.
const (
	NegStateAcceptCompleted  NegState = 0
	NegStateAcceptIncomplete NegState = 1
	NegStateReject           NegState = 2
	NegStateRequestMIC       NegState = 3
)

// NegState is a type to indicate the SPNEGO negotiation state.
type NegState int

// NegTokenInit implements Negotiation Token of type Init.
type NegTokenInit struct {
	MechTypes      []asn1.ObjectIdentifier
	ReqFlags       asn1.BitString
	MechTokenBytes []byte
	NegHints       *NegHints
	MechListMIC    []byte
	mechToken      gssapi.ContextToken
	settings       *service.Settings
}

// NegHints contains the optional hints carried by a NegTokenInit2 token.
type NegHints struct {
	HintName    string `asn1:"generalstring,explicit,optional,tag:0"`
	HintAddress []byte `asn1:"explicit,optional,omitempty,tag:1"`
}

type marshalNegTokenInit struct {
	MechTypes      []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags       asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechTokenBytes []byte                  `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC    []byte                  `asn1:"explicit,optional,omitempty,tag:3"`
}

type marshalNegTokenInit2 struct {
	MechTypes      []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	ReqFlags       asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechTokenBytes []byte                  `asn1:"explicit,optional,omitempty,tag:2"`
	NegHints       NegHints                `asn1:"explicit,optional,tag:3"`
	MechListMIC    []byte                  `asn1:"explicit,optional,omitempty,tag:4"`
}

// NegTokenResp implements Negotiation Token of type Resp/Targ
type NegTokenResp struct {
	NegState      asn1.Enumerated
	SupportedMech asn1.ObjectIdentifier
	ResponseToken []byte
	MechListMIC   []byte
	mechToken     gssapi.ContextToken
	settings      *service.Settings
}

type marshalNegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,omitempty,tag:3"`
}

// NegTokenTarg implements Negotiation Token of type Resp/Targ
type NegTokenTarg NegTokenResp

// MarshalMechTypeList returns the DER encoding protected by mechListMIC.
func MarshalMechTypeList(mechTypes []asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(mechTypes)
}

func makeMechListMIC(mechTypes []asn1.ObjectIdentifier, key types.EncryptionKey, flags byte, sequenceNumber uint64, keyUsage uint32) ([]byte, error) {
	payload, err := MarshalMechTypeList(mechTypes)
	if err != nil {
		return nil, fmt.Errorf("could not marshal MechTypeList: %v", err)
	}
	token := gssapi.MICToken{Flags: flags, SndSeqNum: sequenceNumber, Payload: payload}
	if err := token.SetChecksum(key, keyUsage); err != nil {
		return nil, fmt.Errorf("could not sign MechTypeList: %v", err)
	}
	return token.Marshal()
}

func verifyMechListMIC(mechTypes []asn1.ObjectIdentifier, mic []byte, key types.EncryptionKey, expectFromAcceptor bool, keyUsage uint32) error {
	if len(mic) == 0 {
		return errors.New("mechListMIC is missing")
	}
	var token gssapi.MICToken
	if err := token.Unmarshal(mic, expectFromAcceptor); err != nil {
		return fmt.Errorf("invalid mechListMIC token: %v", err)
	}
	payload, err := MarshalMechTypeList(mechTypes)
	if err != nil {
		return fmt.Errorf("could not marshal MechTypeList: %v", err)
	}
	token.Payload = payload
	verified, err := token.Verify(key, keyUsage)
	if err != nil {
		return fmt.Errorf("could not verify mechListMIC: %v", err)
	}
	if !verified {
		return errors.New("mechListMIC verification failed")
	}
	return nil
}

// SetMechListMIC signs this initiator's DER-encoded MechTypeList.
func (n *NegTokenInit) SetMechListMIC(key types.EncryptionKey, sequenceNumber uint64) error {
	return n.setMechListMIC(key, sequenceNumber, false)
}

func (n *NegTokenInit) setMechListMIC(key types.EncryptionKey, sequenceNumber uint64, acceptorSubkey bool) error {
	var flags byte
	if acceptorSubkey {
		flags = gssapi.MICTokenFlagAcceptorSubkey
	}
	mic, err := makeMechListMIC(n.MechTypes, key, flags, sequenceNumber, keyusage.GSSAPI_INITIATOR_SIGN)
	if err != nil {
		return err
	}
	n.MechListMIC = mic
	return nil
}

// VerifyMechListMIC verifies this initiator's protected mechanism list.
func (n *NegTokenInit) VerifyMechListMIC(key types.EncryptionKey) error {
	return verifyMechListMIC(n.MechTypes, n.MechListMIC, key, false, keyusage.GSSAPI_INITIATOR_SIGN)
}

// SetMechListMIC signs the initiator's DER-encoded MechTypeList for an acceptor response.
func (n *NegTokenResp) SetMechListMIC(mechTypes []asn1.ObjectIdentifier, key types.EncryptionKey, sequenceNumber uint64, acceptorSubkey bool) error {
	flags := byte(gssapi.MICTokenFlagSentByAcceptor)
	if acceptorSubkey {
		flags |= gssapi.MICTokenFlagAcceptorSubkey
	}
	mic, err := makeMechListMIC(mechTypes, key, flags, sequenceNumber, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil {
		return err
	}
	n.MechListMIC = mic
	return nil
}

// VerifyMechListMIC verifies an acceptor's MIC over the initiator's mechanism list.
func (n *NegTokenResp) VerifyMechListMIC(mechTypes []asn1.ObjectIdentifier, key types.EncryptionKey) error {
	return verifyMechListMIC(mechTypes, n.MechListMIC, key, true, keyusage.GSSAPI_ACCEPTOR_SIGN)
}

// Marshal an Init negotiation token
func (n *NegTokenInit) Marshal() ([]byte, error) {
	var b []byte
	var err error
	if n.NegHints != nil {
		b, err = asn1.Marshal(marshalNegTokenInit2{
			MechTypes: n.MechTypes, ReqFlags: n.ReqFlags, MechTokenBytes: n.MechTokenBytes,
			NegHints: *n.NegHints, MechListMIC: n.MechListMIC,
		})
	} else {
		b, err = asn1.Marshal(marshalNegTokenInit{
			MechTypes: n.MechTypes, ReqFlags: n.ReqFlags, MechTokenBytes: n.MechTokenBytes, MechListMIC: n.MechListMIC,
		})
	}
	if err != nil {
		return nil, err
	}
	nt := asn1.RawValue{
		Tag:        0,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}
	nb, err := asn1.Marshal(nt)
	if err != nil {
		return nil, err
	}
	return nb, nil
}

// Unmarshal an Init negotiation token
func (n *NegTokenInit) Unmarshal(b []byte) error {
	init, nt, err := UnmarshalNegToken(b)
	if err != nil {
		return err
	}
	if !init {
		return errors.New("bytes were not that of a NegTokenInit")
	}
	nInit := nt.(NegTokenInit)
	n.MechTokenBytes = nInit.MechTokenBytes
	n.NegHints = nInit.NegHints
	n.MechListMIC = nInit.MechListMIC
	n.MechTypes = nInit.MechTypes
	n.ReqFlags = nInit.ReqFlags
	return nil
}

// Verify an Init negotiation token
func (n *NegTokenInit) Verify() (bool, gssapi.Status) {
	// Check if supported mechanisms are in the MechTypeList
	var mtSupported bool
	for _, m := range n.MechTypes {
		if m.Equal(gssapi.OIDKRB5.OID()) || m.Equal(gssapi.OIDMSLegacyKRB5.OID()) {
			if n.mechToken == nil && n.MechTokenBytes == nil {
				return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
			}
			mtSupported = true
			break
		}
	}
	if !mtSupported {
		return false, gssapi.Status{Code: gssapi.StatusBadMech, Message: "no supported mechanism specified in negotiation"}
	}
	// There should be some mechtoken bytes for a KRB5Token (other mech types are not supported)
	mt := new(KRB5Token)
	mt.settings = n.settings
	if n.mechToken == nil {
		err := mt.Unmarshal(n.MechTokenBytes)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		n.mechToken = mt
	} else {
		var ok bool
		mt, ok = n.mechToken.(*KRB5Token)
		if !ok {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "MechToken is not a KRB5 token as expected"}
		}
	}
	mt.settings = n.settings
	// Verify the mechtoken
	return n.mechToken.Verify()
}

// Context returns the SPNEGO context which will contain any verify user identity information.
func (n *NegTokenInit) Context() context.Context {
	if n.mechToken != nil {
		mt, ok := n.mechToken.(*KRB5Token)
		if !ok {
			return nil
		}
		return mt.Context()
	}
	return nil
}

// Marshal a Resp/Targ negotiation token
func (n *NegTokenResp) Marshal() ([]byte, error) {
	m := marshalNegTokenResp{
		NegState:      n.NegState,
		SupportedMech: n.SupportedMech,
		ResponseToken: n.ResponseToken,
		MechListMIC:   n.MechListMIC,
	}
	b, err := asn1.Marshal(m)
	if err != nil {
		return nil, err
	}
	nt := asn1.RawValue{
		Tag:        1,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}
	nb, err := asn1.Marshal(nt)
	if err != nil {
		return nil, err
	}
	return nb, nil
}

// Unmarshal a Resp/Targ negotiation token
func (n *NegTokenResp) Unmarshal(b []byte) error {
	init, nt, err := UnmarshalNegToken(b)
	if err != nil {
		return err
	}
	if init {
		return errors.New("bytes were not that of a NegTokenResp")
	}
	nResp := nt.(NegTokenResp)
	n.MechListMIC = nResp.MechListMIC
	n.NegState = nResp.NegState
	n.ResponseToken = nResp.ResponseToken
	n.SupportedMech = nResp.SupportedMech
	return nil
}

// Verify a Resp/Targ negotiation token
func (n *NegTokenResp) Verify() (bool, gssapi.Status) {
	if n.SupportedMech.Equal(gssapi.OIDKRB5.OID()) || n.SupportedMech.Equal(gssapi.OIDMSLegacyKRB5.OID()) {
		if n.mechToken == nil && n.ResponseToken == nil {
			return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
		}
		mt := new(KRB5Token)
		mt.settings = n.settings
		if n.mechToken == nil {
			err := mt.Unmarshal(n.ResponseToken)
			if err != nil {
				return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
			}
			n.mechToken = mt
		} else {
			var ok bool
			mt, ok = n.mechToken.(*KRB5Token)
			if !ok {
				return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "MechToken is not a KRB5 token as expected"}
			}
		}
		if mt == nil {
			return false, gssapi.Status{Code: gssapi.StatusContinueNeeded}
		}
		mt.settings = n.settings
		// Verify the mechtoken
		return mt.Verify()
	}
	return false, gssapi.Status{Code: gssapi.StatusBadMech, Message: "no supported mechanism specified in negotiation"}
}

// State returns the negotiation state of the negotiation response.
func (n *NegTokenResp) State() NegState {
	return NegState(n.NegState)
}

// Context returns the SPNEGO context which will contain any verify user identity information.
func (n *NegTokenResp) Context() context.Context {
	if n.mechToken != nil {
		mt, ok := n.mechToken.(*KRB5Token)
		if !ok {
			return nil
		}
		return mt.Context()
	}
	return nil
}

// UnmarshalNegToken umarshals and returns either a NegTokenInit or a NegTokenResp.
//
// The boolean indicates if the response is a NegTokenInit.
// If error is nil and the boolean is false the response is a NegTokenResp.
func UnmarshalNegToken(b []byte) (bool, interface{}, error) {
	var a asn1.RawValue
	_, err := asn1.Unmarshal(b, &a)
	if err != nil {
		return false, nil, fmt.Errorf("error unmarshalling NegotiationToken: %v", err)
	}
	switch a.Tag {
	case 0:
		if isNegTokenInit2(a.Bytes) {
			var n marshalNegTokenInit2
			if _, err = asn1.Unmarshal(a.Bytes, &n); err != nil {
				return false, nil, fmt.Errorf("error unmarshalling NegotiationToken type %d (Init2): %v", a.Tag, err)
			}
			nt := NegTokenInit{
				MechTypes: n.MechTypes, ReqFlags: n.ReqFlags, MechTokenBytes: n.MechTokenBytes,
				NegHints: &n.NegHints, MechListMIC: n.MechListMIC,
			}
			return true, nt, nil
		}
		var n marshalNegTokenInit
		_, err = asn1.Unmarshal(a.Bytes, &n)
		if err != nil {
			return false, nil, fmt.Errorf("error unmarshalling NegotiationToken type %d (Init): %v", a.Tag, err)
		}
		nt := NegTokenInit{
			MechTypes:      n.MechTypes,
			ReqFlags:       n.ReqFlags,
			MechTokenBytes: n.MechTokenBytes,
			MechListMIC:    n.MechListMIC,
		}
		return true, nt, nil
	case 1:
		var n marshalNegTokenResp
		_, err = asn1.Unmarshal(a.Bytes, &n)
		if err != nil {
			return false, nil, fmt.Errorf("error unmarshalling NegotiationToken type %d (Resp/Targ): %v", a.Tag, err)
		}
		nt := NegTokenResp{
			NegState:      n.NegState,
			SupportedMech: n.SupportedMech,
			ResponseToken: n.ResponseToken,
			MechListMIC:   n.MechListMIC,
		}
		return false, nt, nil
	default:
		return false, nil, errors.New("unknown choice type for NegotiationToken")
	}

}

func isNegTokenInit2(encoded []byte) bool {
	var sequence asn1.RawValue
	if _, err := asn1.Unmarshal(encoded, &sequence); err != nil {
		return false
	}
	remaining := sequence.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return false
		}
		if field.Class == 2 && field.Tag == 4 {
			return true
		}
		if field.Class == 2 && field.Tag == 3 && len(field.Bytes) > 0 && field.Bytes[0] == 0x30 {
			return true
		}
	}
	return false
}

// NewNegTokenInitKRB5 creates new Init negotiation token for Kerberos 5
func NewNegTokenInitKRB5(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey) (NegTokenInit, error) {
	return NewNegTokenInitKRB5WithOptions(cl, tkt, sessionKey, KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
	})
}

// NewNegTokenInitKRB5WithOptions creates a Kerberos NegTokenInit with explicit context options.
func NewNegTokenInitKRB5WithOptions(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, options KRB5TokenAPREQOptions) (NegTokenInit, error) {
	mt, err := NewKRB5TokenAPREQWithOptions(cl, tkt, sessionKey, options)
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("error getting KRB5 token; %v", err)
	}
	mtb, err := mt.Marshal()
	if err != nil {
		return NegTokenInit{}, fmt.Errorf("error marshalling KRB5 token; %v", err)
	}
	mechTypes := append([]asn1.ObjectIdentifier(nil), options.MechTypes...)
	if len(mechTypes) == 0 {
		mechTypes = []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}
	}
	for _, oid := range mechTypes {
		if !isKerberosMech(oid) {
			return NegTokenInit{}, fmt.Errorf("unsupported SPNEGO mechanism %s", oid.String())
		}
	}
	return NegTokenInit{
		MechTypes:      mechTypes,
		MechTokenBytes: mtb,
		mechToken:      &mt,
	}, nil
}

func isKerberosMech(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(gssapi.OIDKRB5.OID()) || oid.Equal(gssapi.OIDMSLegacyKRB5.OID())
}
