package negoex

import (
	"errors"
	"testing"
)

func TestConversationWrapsInitialMechanismFailure(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(testScheme())
	scheme.initErr = errors.New("injected mechanism failure")
	initiator := mustNewInitiator(t, "host/initial", scheme)
	output, done, err := initiator.Step(nil)
	requireWrappedError(t, err, scheme.initErr, "initialize NEGOEX mechanism:")
	if output != nil || done || initiator.Context() != nil {
		t.Fatal("initial failure emitted a token or published a context")
	}
}

func TestConversationContinuationErrorToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		errorToken string
	}{
		{name: "terminal failure", errorToken: ""},
		{name: "token for peer", errorToken: "mechanism failure token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			schemeID := testScheme()
			receiver := newTestScheme(schemeID)
			initiator := mustNewInitiator(t, "host/continuation", newTestScheme(schemeID))
			acceptor := mustNewAcceptor(t, receiver)
			request := mustConversationToken(t, initiator, nil)
			challenge := mustConversationToken(t, acceptor, request)
			response := mustConversationToken(t, initiator, challenge)

			receiver.acceptErr = errors.New("injected continuation failure")
			receiver.acceptErrorToken = []byte(tt.errorToken)
			output, done, err := acceptor.Step(response)
			if done {
				t.Fatal("failed mechanism completed the conversation")
			}
			if tt.errorToken == "" {
				requireWrappedError(t, err, receiver.acceptErr, "continue NEGOEX mechanism:")
				if output != nil {
					t.Fatal("terminal failure emitted a token")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			messages, err := Unmarshal(output)
			if err != nil {
				t.Fatal(err)
			}
			token := findExchange(messages, MessageTypeChallenge, schemeID)
			if token == nil || string(token.Exchange) != tt.errorToken {
				t.Fatal("mechanism error token was not forwarded to the peer")
			}
		})
	}
}

func TestConversationRecoversFromOptimisticFailure(t *testing.T) {
	t.Parallel()

	schemeID := testScheme()
	receiver := newTestScheme(schemeID)
	receiver.acceptErr = errors.New("injected optimistic failure")
	initiator := mustNewInitiator(t, "host/optimistic", newTestScheme(schemeID))
	acceptor := mustNewAcceptor(t, receiver)
	request := mustConversationToken(t, initiator, nil)
	response := mustConversationToken(t, acceptor, request)
	messages, err := Unmarshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if findNego(messages, MessageTypeAcceptorNego) == nil {
		t.Fatal("optimistic failure prevented acceptor negotiation")
	}
	if findExchange(messages, MessageTypeChallenge, schemeID) != nil || acceptor.Context() != nil {
		t.Fatal("optimistic failure emitted a challenge or published a context")
	}
}

func mustConversationToken(t *testing.T, conversation *Conversation, input []byte) []byte {
	t.Helper()
	output, _, err := conversation.Step(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) == 0 {
		t.Fatal("expected a negotiation token")
	}
	return output
}
