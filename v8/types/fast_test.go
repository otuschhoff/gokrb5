package types

import (
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"
)

func TestFASTArmoredChoiceDERCompatibility(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		cipher []byte
	}{
		{name: "empty", cipher: nil},
		{name: "short", cipher: []byte{1, 2, 3}},
		{name: "long", cipher: make([]byte, 256)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := EncryptedData{EType: 18, KVNO: 0, Cipher: tt.cipher}
			var request PAFXFastRequest
			request.ArmoredData.EncFastReq = encrypted
			var reply PAFXFastReply
			reply.ArmoredData.EncFastRep = encrypted

			for _, choice := range []struct {
				name  string
				inner func() ([]byte, error)
				outer func() ([]byte, error)
			}{
				{name: "request", inner: request.ArmoredData.Marshal, outer: request.Marshal},
				{name: "reply", inner: reply.ArmoredData.Marshal, outer: reply.Marshal},
			} {
				t.Run(choice.name, func(t *testing.T) {
					inner, err := choice.inner()
					require.NoError(t, err)
					raw := asn1.RawValue{
						Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner, FullBytes: nil,
					}
					want, err := asn1.Marshal(raw)
					require.NoError(t, err)
					got, err := choice.outer()
					require.NoError(t, err)
					require.Equal(t, want, got)
				})
			}
		})
	}
}
