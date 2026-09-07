package spnego

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/negoex"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type testMechanismContext struct {
	negoExKey types.EncryptionKey
}

func (*testMechanismContext) Wrap(message []byte, _ bool) ([]byte, error) {
	return append([]byte(nil), message...), nil
}
func (*testMechanismContext) Unwrap(token []byte) ([]byte, bool, error) {
	return append([]byte(nil), token...), false, nil
}
func (*testMechanismContext) GetMIC(message []byte) ([]byte, error) {
	return append([]byte("MIC:"), message...), nil
}
func (*testMechanismContext) VerifyMIC(message, token []byte) error {
	if !bytes.Equal(token, append([]byte("MIC:"), message...)) {
		return errors.New("invalid test MIC")
	}
	return nil
}
func (c *testMechanismContext) NegoExKey() (types.EncryptionKey, bool) {
	return c.negoExKey, len(c.negoExKey.KeyValue) > 0
}
func (c *testMechanismContext) NegoExVerifyKey() (types.EncryptionKey, bool) {
	return c.negoExKey, len(c.negoExKey.KeyValue) > 0
}

type testContextMechanism struct {
	oid         asn1.ObjectIdentifier
	name        string
	context     *testMechanismContext
	acceptCalls int
}

func newTestContextMechanism(lastOID int, name string) *testContextMechanism {
	return &testContextMechanism{
		oid:     asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, lastOID},
		name:    name,
		context: new(testMechanismContext),
	}
}

func (m *testContextMechanism) OID() asn1.ObjectIdentifier { return m.oid }

func (m *testContextMechanism) InitSecContext(_ string, input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	if len(input) == 0 {
		return []byte(m.name + "-init"), m.context, false, nil
	}
	if string(input) == m.name+"-challenge" {
		return nil, m.context, true, nil
	}
	return nil, m.context, false, errors.New("unexpected initiator token")
}

func (m *testContextMechanism) AcceptSecContext(input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	m.acceptCalls++
	if string(input) != m.name+"-init" {
		return nil, m.context, false, errors.New("unexpected acceptor token")
	}
	return []byte(m.name + "-challenge"), m.context, true, nil
}

func TestNegotiatorDirectMechanism(t *testing.T) {
	initiator := NewNegotiator(newTestContextMechanism(1, "first"))
	acceptor := NewNegotiator(newTestContextMechanism(1, "first"))

	initial, _, done, err := initiator.InitSecContext("host/server", nil)
	if err != nil || done {
		t.Fatalf("initial initiator step: done=%v err=%v", done, err)
	}
	response, _, done, err := acceptor.AcceptSecContext(initial)
	if err != nil || !done {
		t.Fatalf("acceptor step: done=%v err=%v", done, err)
	}
	output, _, done, err := initiator.InitSecContext("host/server", response)
	if err != nil || !done || len(output) != 0 {
		t.Fatalf("final initiator step: output=%x done=%v err=%v", output, done, err)
	}
}

func TestNegotiatorUnsupportedOptimisticFallback(t *testing.T) {
	firstInitiator := newTestContextMechanism(1, "first")
	secondInitiator := newTestContextMechanism(2, "second")
	secondAcceptor := newTestContextMechanism(2, "second")
	initiator := NewNegotiator(firstInitiator, secondInitiator)
	acceptor := NewNegotiator(secondAcceptor)

	initiatorToken, _, _, err := initiator.InitSecContext("host/server", nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptorToken, _, done, err := acceptor.AcceptSecContext(initiatorToken)
	if err != nil || done {
		t.Fatalf("selection step: done=%v err=%v", done, err)
	}
	if secondAcceptor.acceptCalls != 0 {
		t.Fatalf("acceptor processed unsupported optimistic token %d times", secondAcceptor.acceptCalls)
	}

	initiatorToken, _, done, err = initiator.InitSecContext("host/server", acceptorToken)
	if err != nil || done {
		t.Fatalf("fallback initiator step: done=%v err=%v", done, err)
	}
	acceptorToken, _, done, err = acceptor.AcceptSecContext(initiatorToken)
	if err != nil || done {
		t.Fatalf("MIC request step: done=%v err=%v", done, err)
	}
	initiatorToken, _, done, err = initiator.InitSecContext("host/server", acceptorToken)
	if err != nil || !done {
		t.Fatalf("initiator MIC step: done=%v err=%v", done, err)
	}
	acceptorToken, _, done, err = acceptor.AcceptSecContext(initiatorToken)
	if err != nil || !done || len(acceptorToken) != 0 {
		t.Fatalf("final acceptor step: output=%x done=%v err=%v", acceptorToken, done, err)
	}
}

func TestNegotiatorRejectsNoCommonMechanism(t *testing.T) {
	initiator := NewNegotiator(newTestContextMechanism(1, "first"))
	acceptor := NewNegotiator(newTestContextMechanism(2, "second"))
	initial, _, _, err := initiator.InitSecContext("host/server", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, _, done, err := acceptor.AcceptSecContext(initial)
	if err != nil || done {
		t.Fatalf("reject response: done=%v err=%v", done, err)
	}
	if _, _, _, err := initiator.InitSecContext("host/server", response); !errors.Is(err, ErrNoCommonMechanism) {
		t.Fatalf("error = %v", err)
	}
}

func TestNegotiatorLifecycleGuardsAndHelpers(t *testing.T) {
	empty := NewNegotiator(nil)
	if !empty.OID().Equal(gssapi.OIDSPNEGO.OID()) {
		t.Fatalf("negotiator OID = %v", empty.OID())
	}
	if _, _, _, err := empty.InitSecContext("host/server", []byte("unexpected")); !errors.Is(err, ErrUnexpectedSPNEGO) {
		t.Fatalf("unexpected initial input error = %v", err)
	}
	empty = NewNegotiator()
	if _, _, _, err := empty.InitSecContext("host/server", nil); !errors.Is(err, ErrNoMechanisms) {
		t.Fatalf("empty mechanism error = %v", err)
	}
	if _, _, _, err := empty.AcceptSecContext(nil); !errors.Is(err, ErrUnexpectedSPNEGO) {
		t.Fatalf("empty acceptor input error = %v", err)
	}

	mechanism := newTestContextMechanism(1, "first")
	negotiator := NewNegotiator(nil, mechanism, mechanism)
	if len(negotiator.mechanisms) != 1 {
		t.Fatalf("unique mechanisms = %d", len(negotiator.mechanisms))
	}
	if _, _, _, err := negotiator.InitSecContext("host/server", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := negotiator.InitSecContext("other/server", nil); err == nil || !strings.Contains(err.Error(), "target changed") {
		t.Fatalf("target change error = %v", err)
	}

	initBytes, err := marshalSPNEGOToken(&SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{MechTypes: []asn1.ObjectIdentifier{mechanism.OID()}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSPNEGOResponse(initBytes); !errors.Is(err, ErrUnexpectedSPNEGO) {
		t.Fatalf("initiator-as-response error = %v", err)
	}
	responseBytes, err := marshalSPNEGOToken(&SPNEGOToken{Resp: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseSPNEGOInitiator(responseBytes); !errors.Is(err, ErrUnexpectedSPNEGO) {
		t.Fatalf("response-as-initiator error = %v", err)
	}

	conversation := &mechanismConversation{}
	if conversation.String() != "SPNEGO(unselected)" {
		t.Fatalf("unselected string = %q", conversation.String())
	}
	conversation.selected = mechanism
	if !strings.Contains(conversation.String(), mechanism.OID().String()) {
		t.Fatalf("selected string = %q", conversation.String())
	}
}

type testNegoExScheme struct {
	id      negoex.AuthScheme
	context *testMechanismContext
}

func newTestNegoExScheme() *testNegoExScheme {
	return &testNegoExScheme{
		id: negoex.AuthScheme{1, 2, 3, 4},
		context: &testMechanismContext{negoExKey: types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: []byte("0123456789abcdef0123456789abcdef"),
		}},
	}
}

func (m *testNegoExScheme) AuthScheme() negoex.AuthScheme { return m.id }

func (m *testNegoExScheme) InitSecContext(_ string, input []byte) ([]byte, gssapi.Context, bool, error) {
	if len(input) == 0 {
		return []byte("request"), m.context, false, nil
	}
	if string(input) == "challenge" {
		return []byte("finish"), m.context, true, nil
	}
	return nil, m.context, false, errors.New("unexpected NEGOEX initiator token")
}

func (m *testNegoExScheme) AcceptSecContext(input []byte) ([]byte, gssapi.Context, bool, error) {
	switch string(input) {
	case "request":
		return []byte("challenge"), m.context, false, nil
	case "finish":
		return nil, m.context, true, nil
	default:
		return nil, m.context, false, errors.New("unexpected NEGOEX acceptor token")
	}
}

func TestNegotiatorCarriesNegoEx(t *testing.T) {
	initiator := NewNegotiator(negoex.New(newTestNegoExScheme()))
	acceptor := NewNegotiator(negoex.New(newTestNegoExScheme()))

	initiatorToken, _, _, err := initiator.InitSecContext("host/server", nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptorToken, _, done, err := acceptor.AcceptSecContext(initiatorToken)
	if err != nil || done {
		t.Fatalf("initial acceptor step: done=%v err=%v", done, err)
	}
	initiatorToken, _, done, err = initiator.InitSecContext("host/server", acceptorToken)
	if err != nil || done {
		t.Fatalf("NEGOEX initiator step: done=%v err=%v", done, err)
	}
	acceptorToken, _, done, err = acceptor.AcceptSecContext(initiatorToken)
	if err != nil || !done {
		t.Fatalf("NEGOEX acceptor completion: done=%v err=%v", done, err)
	}
	output, _, done, err := initiator.InitSecContext("host/server", acceptorToken)
	if err != nil || !done || len(output) != 0 {
		t.Fatalf("SPNEGO initiator completion: output=%x done=%v err=%v", output, done, err)
	}
}
