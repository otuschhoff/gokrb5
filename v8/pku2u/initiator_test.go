package pku2u

import (
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

func TestInitiatorRejectsAcceptorRole(t *testing.T) {
	t.Parallel()

	var mechanism gssapi.ContextMechanism = NewInitiator(nil, nil)
	output, context, done, err := mechanism.AcceptSecContext(nil)
	const want = "PKU2U initiator cannot accept a security context"
	if err == nil || err.Error() != want {
		t.Fatalf("AcceptSecContext error = %v, want %q", err, want)
	}
	if output != nil || context != nil || done {
		t.Fatalf("AcceptSecContext returned (%x, %v, %t), want (nil, nil, false)", output, context, done)
	}
}

func TestInitiatorHandshakeTransitions(t *testing.T) {
	t.Parallel()

	client, server := newTestASExchangeSettings(t)
	initiator := NewInitiator(client.identity, client.roots)
	acceptor := NewAcceptor(server.identity, server.roots)

	requireInitiatorRejection(t, initiator, []byte{0}, "unexpected PKU2U input before AS request")
	asRequest := requireInitiatorToken(t, initiator, nil)
	asReply, _, _, err := acceptor.AcceptSecContext(asRequest)
	if err != nil {
		t.Fatal(err)
	}

	requireInitiatorRejection(t, initiator, []byte{0x6b}, "decode PKU2U AS reply:")
	apRequest := requireInitiatorToken(t, initiator, asReply)
	apReply, _, _, err := acceptor.AcceptSecContext(apRequest)
	if err != nil {
		t.Fatal(err)
	}

	requireInitiatorRejection(t, initiator, []byte{0x6f}, "decode PKU2U AP reply:")
	output, context, done, err := initiator.InitSecContext(asTestTarget, apReply)
	if err != nil {
		t.Fatal(err)
	}
	if output != nil || context == nil || !done {
		t.Fatal("expected a context and no output token after the AP reply")
	}
	requireInitiatorRejection(t, initiator, apReply, "PKU2U initiator context is already established")
}

func requireInitiatorToken(t *testing.T, initiator *Initiator, input []byte) []byte {
	t.Helper()

	output, context, done, err := initiator.InitSecContext(asTestTarget, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) == 0 || context != nil || done {
		t.Fatal("expected an output token but no context before completing the handshake")
	}
	return output
}

func requireInitiatorRejection(t *testing.T, initiator gssapi.ContextMechanism, input []byte, want string) {
	t.Helper()

	output, context, done, err := initiator.InitSecContext(asTestTarget, input)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("want error starting with %q, got %v", want, err)
	}
	if output != nil || context != nil || done {
		t.Fatal("rejection returned output, a context, or completion")
	}
}
