package pkinit

import "testing"

func FuzzCMS(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = VerifySignedData(data, OIDPKINITAuthData)
	})
}
