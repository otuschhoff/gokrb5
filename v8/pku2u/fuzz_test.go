package pku2u

import "testing"

func FuzzTrustedCertifiersUnmarshal(f *testing.F) {
	seed, err := (TrustedCertifiers{{SubjectName: []byte{1, 2, 3}}}).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		var metadata TrustedCertifiers
		if err := metadata.Unmarshal(data); err != nil {
			return
		}
		encoded, err := metadata.Marshal()
		if err != nil {
			t.Fatalf("re-encode trusted certifiers: %v", err)
		}
		var decoded TrustedCertifiers
		if err := decoded.Unmarshal(encoded); err != nil {
			t.Fatalf("decode re-encoded trusted certifiers: %v", err)
		}
	})
}
