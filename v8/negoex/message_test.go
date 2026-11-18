package negoex

import "testing"

func TestMessageEncodingPreservesCause(t *testing.T) {
	t.Parallel()

	message := &ExchangeMessage{Header: testHeader(MessageTypeVerify, 0), AuthScheme: testScheme(), Exchange: []byte{1}}
	output, err := Marshal(message)
	requireWrappedError(t, err, ErrInvalidMessageType, "marshal NEGOEX message type")
	if output != nil {
		t.Fatal("marshal failure returned a token")
	}

	var conversation Conversation
	output, done, err := conversation.emit([]Message{message}, false)
	requireWrappedError(t, err, ErrInvalidMessageType, "marshal NEGOEX message type")
	if output != nil || done {
		t.Fatal("emit failure returned a token or completed the conversation")
	}
	if conversation.sequence != 0 || len(conversation.transcript) != 0 {
		t.Fatal("failed message was committed to the transcript")
	}
}
