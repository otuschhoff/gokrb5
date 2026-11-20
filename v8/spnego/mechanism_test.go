package spnego

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/negoex"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type testMechanismContext struct {
	negoExKey types.EncryptionKey
	verifyErr error
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

func (c *testMechanismContext) VerifyMIC(message, token []byte) error {
	if c.verifyErr != nil {
		return c.verifyErr
	}
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
	stepErr     error
}

func newTestContextMechanism(lastOID int, name string) *testContextMechanism {
	m := new(testContextMechanism)
	m.oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, lastOID}
	m.name = name
	m.context = new(testMechanismContext)
	return m
}

func (m *testContextMechanism) OID() asn1.ObjectIdentifier { return m.oid }

//nolint:ireturn // Implements gssapi.ContextMechanism for the test fixture.
func (m *testContextMechanism) InitSecContext(
	_ string,
	input []byte,
	_ ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	if m.stepErr != nil {
		return nil, nil, false, m.stepErr
	}
	if len(input) == 0 {
		return []byte(m.name + "-init"), m.context, false, nil
	}
	if string(input) == m.name+"-challenge" {
		return nil, m.context, true, nil
	}
	return nil, m.context, false, errors.New("unexpected initiator token")
}

//nolint:ireturn // Implements gssapi.ContextMechanism for the test fixture.
func (m *testContextMechanism) AcceptSecContext(
	input []byte,
	_ ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	m.acceptCalls++
	if m.stepErr != nil {
		return nil, nil, false, m.stepErr
	}
	if string(input) != m.name+"-init" {
		return nil, m.context, false, errors.New("unexpected acceptor token")
	}
	return []byte(m.name + "-challenge"), m.context, true, nil
}

func TestNegotiatorInitiatorRetainsMechanismErrors(t *testing.T) {
	t.Parallel()

	const target = "host/server"
	cause := errors.New("injected mechanism error")
	mech := newTestContextMechanism(1, "first")
	mech.stepErr = cause
	initiator := NewNegotiator(mech)
	output, context, done, err := initiator.InitSecContext(target, nil)
	require.Nil(t, output)
	require.Nil(t, context)
	require.False(t, done)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "start SPNEGO initiator mechanism:")

	mech.stepErr = nil
	initial, _, _, err := initiator.InitSecContext(target, nil)
	require.NoError(t, err)
	acceptor := NewNegotiator(newTestContextMechanism(1, "first"))
	reply, _, _, err := acceptor.AcceptSecContext(initial)
	require.NoError(t, err)
	mech.stepErr = cause
	output, _, done, err = initiator.InitSecContext(target, reply)
	require.Nil(t, output)
	require.False(t, done)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "continue SPNEGO initiator mechanism:")
}

func TestNegotiatorOptimisticFailureFallsBack(t *testing.T) {
	t.Parallel()

	const target = "host/server"
	cause := errors.New("injected mechanism error")
	mech := newTestContextMechanism(1, "first")
	mech.stepErr = cause
	initiator := NewNegotiator(newTestContextMechanism(1, "first"))
	acceptor := NewNegotiator(mech)
	initial, _, _, err := initiator.InitSecContext(target, nil)
	require.NoError(t, err)

	reply, context, done, err := acceptor.AcceptSecContext(initial)
	require.NoError(t, err)
	require.Nil(t, context)
	require.False(t, done)
	token, err := parseSPNEGOResponse(reply)
	require.NoError(t, err)
	require.Equal(t, NegStateAcceptIncomplete, token.NegTokenResp.State())
	require.Equal(t, mech.OID(), token.NegTokenResp.SupportedMech)

	next, _, _, err := initiator.InitSecContext(target, reply)
	require.NoError(t, err)
	output, _, done, err := acceptor.AcceptSecContext(next)
	require.Nil(t, output)
	require.False(t, done)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "continue SPNEGO acceptor mechanism:")
}

func TestNegotiatorMICVerificationRetainsCause(t *testing.T) {
	t.Parallel()

	const target = "host/server"
	backup := newTestContextMechanism(2, "backup")
	acceptorMech := newTestContextMechanism(2, "backup")
	initiator := NewNegotiator(newTestContextMechanism(1, "first"), backup)
	acceptor := NewNegotiator(acceptorMech)
	initial, _, _, err := initiator.InitSecContext(target, nil)
	require.NoError(t, err)
	selection, _, _, err := acceptor.AcceptSecContext(initial)
	require.NoError(t, err)
	next, _, _, err := initiator.InitSecContext(target, selection)
	require.NoError(t, err)
	micRequest, _, _, err := acceptor.AcceptSecContext(next)
	require.NoError(t, err)

	cause := errors.New("injected MIC verifier failure")
	backup.context.verifyErr = cause
	output, _, done, err := initiator.InitSecContext(target, micRequest)
	require.Nil(t, output)
	require.False(t, done)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "verify acceptor mechListMIC:")

	backup.context.verifyErr = nil
	micReply, _, done, err := initiator.InitSecContext(target, micRequest)
	require.NoError(t, err)
	require.True(t, done)
	acceptorMech.context.verifyErr = cause
	output, _, done, err = acceptor.AcceptSecContext(micReply)
	require.Nil(t, output)
	require.False(t, done)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "verify initiator mechListMIC:")

	acceptorMech.context.verifyErr = nil
	_, _, done, err = acceptor.AcceptSecContext(micReply)
	require.NoError(t, err)
	require.True(t, done)
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
	require.NoError(t, err)
	acceptorToken, _, done, err := acceptor.AcceptSecContext(initiatorToken)
	require.NoError(t, err)
	require.False(t, done)
	require.Equal(t, 0, secondAcceptor.acceptCalls)

	initiatorToken, _, done, err = initiator.InitSecContext("host/server", acceptorToken)
	require.NoError(t, err)
	require.False(t, done)
	acceptorToken, _, done, err = acceptor.AcceptSecContext(initiatorToken)
	require.NoError(t, err)
	require.False(t, done)
	initiatorToken, _, done, err = initiator.InitSecContext("host/server", acceptorToken)
	require.NoError(t, err)
	require.True(t, done)
	acceptorToken, _, done, err = acceptor.AcceptSecContext(initiatorToken)
	require.NoError(t, err)
	require.True(t, done)
	require.Equal(t, 0, len(acceptorToken))
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
	require.True(t, empty.OID().Equal(gssapi.OIDSPNEGO.OID()))
	{
		_, _, _, err := empty.InitSecContext("host/server", []byte("unexpected"))
		require.True(t, errors.Is(err, ErrUnexpectedSPNEGO))
	}
	empty = NewNegotiator()
	{
		_, _, _, err := empty.InitSecContext("host/server", nil)
		require.True(t, errors.Is(err, ErrNoMechanisms))
	}
	{
		_, _, _, err := empty.AcceptSecContext(nil)
		require.True(t, errors.Is(err, ErrUnexpectedSPNEGO))
	}

	mechanism := newTestContextMechanism(1, "first")
	negotiator := NewNegotiator(nil, mechanism, mechanism)
	require.Equal(t, 1, len(negotiator.mechanisms))
	{
		_, _, _, err := negotiator.InitSecContext("host/server", nil)
		require.NoError(t, err)
	}
	{
		_, _, _, err := negotiator.InitSecContext("other/server", nil)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "target changed"))
	}

	init := new(SPNEGOToken)
	init.Init = true
	init.NegTokenInit.MechTypes = []asn1.ObjectIdentifier{mechanism.OID()}
	initBytes, err := init.Marshal()
	require.NoError(t, err)
	{
		_, ierr := parseSPNEGOResponse(initBytes)
		require.True(t, errors.Is(ierr, ErrUnexpectedSPNEGO))
	}
	responseBytes, err := marshalMechanismResponse(mechanismResponse(NegStateAcceptCompleted, nil, nil))
	require.NoError(t, err)
	{
		_, err := parseSPNEGOInitiator(responseBytes)
		require.True(t, errors.Is(err, ErrUnexpectedSPNEGO))
	}

	var conversation mechanismConversation
	require.Equal(t, "SPNEGO(unselected)", conversation.String())
	conversation.selected = mechanism
	require.True(t, strings.Contains(conversation.String(), mechanism.OID().String()))
}

type testNegoExScheme struct {
	id      negoex.AuthScheme
	context *testMechanismContext
}

func newTestNegoExScheme() *testNegoExScheme {
	return &testNegoExScheme{
		id: negoex.AuthScheme{1, 2, 3, 4},
		context: &testMechanismContext{
			negoExKey: types.EncryptionKey{
				KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
				KeyValue: []byte("0123456789abcdef0123456789abcdef"),
			},
			verifyErr: nil,
		},
	}
}

func (m *testNegoExScheme) AuthScheme() negoex.AuthScheme { return m.id }

//nolint:ireturn // Implements the NEGOEX authentication scheme contract.
func (m *testNegoExScheme) InitSecContext(_ string, input []byte) ([]byte, gssapi.Context, bool, error) {
	if len(input) == 0 {
		return []byte("request"), m.context, false, nil
	}
	if string(input) == "challenge" {
		return []byte("finish"), m.context, true, nil
	}
	return nil, m.context, false, errors.New("unexpected NEGOEX initiator token")
}

//nolint:ireturn // Implements the NEGOEX authentication scheme contract.
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
	require.NoError(t, err)
	acceptorToken, _, done, err := acceptor.AcceptSecContext(initiatorToken)
	require.NoError(t, err)
	require.False(t, done)
	initiatorToken, _, done, err = initiator.InitSecContext("host/server", acceptorToken)
	require.NoError(t, err)
	require.False(t, done)
	acceptorToken, _, done, err = acceptor.AcceptSecContext(initiatorToken)
	require.NoError(t, err)
	require.True(t, done)
	output, _, done, err := initiator.InitSecContext("host/server", acceptorToken)
	require.NoError(t, err)
	require.True(t, done)
	require.Equal(t, 0, len(output))
}
