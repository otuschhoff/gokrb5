package negoex

import "testing"

func FuzzNegoExUnmarshal(f *testing.F) {
	seed, err := (&NegoMessage{
		Header:      testHeader(MessageTypeInitiatorNego, 0),
		AuthSchemes: []AuthScheme{testScheme()},
	}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte("NEGOEXTS"))
	f.Fuzz(func(t *testing.T, data []byte) {
		messages, err := Unmarshal(data)
		if err != nil {
			return
		}
		if _, err := Marshal(messages...); err != nil {
			t.Fatalf("decoded messages cannot be re-encoded: %v", err)
		}
	})
}
