package pku2u

import "testing"

func FuzzTrustedCertifiersUnmarshal(f *testing.F) {
	seed, _ := (TrustedCertifiers{{SubjectName: []byte{1, 2, 3}}}).Marshal()
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		var metadata TrustedCertifiers
		_ = metadata.Unmarshal(data)
	})
}
