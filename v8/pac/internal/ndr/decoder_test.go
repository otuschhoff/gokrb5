package ndr

import (
	"bytes"
	"testing"
)

func TestDecoderTracksCompleteInput(t *testing.T) {
	input := bytes.Repeat([]byte{0x01}, 5000)
	dec := NewDecoder(bytes.NewReader(input))

	if dec.size != len(input) {
		t.Fatalf("decoder input size = %d, want %d", dec.size, len(input))
	}
	if dec.r.Buffered() != len(input) {
		t.Fatalf("buffered input = %d, want %d", dec.r.Buffered(), len(input))
	}
}

func TestReadBytesRejectsUnavailableLength(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte{0x01}))

	if _, err := dec.readBytes(2); err == nil {
		t.Fatal("readBytes accepted a length larger than the remaining input")
	}
}
