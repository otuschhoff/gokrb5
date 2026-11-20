package pku2u

import (
	"crypto/x509"
	"slices"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
)

func TestASExchangeOwnsEnctypeOffer(t *testing.T) {
	t.Parallel()

	root, rootKey := newPKU2URoot(t)
	cert, key := newPKU2ULeaf(t, root, rootKey, "Offer test", nil, upnSAN(t, "offer@example.com"))
	identity, err := pkinit.NewIdentity(cert, []*x509.Certificate{root}, key, false)
	if err != nil {
		t.Fatal(err)
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	cfg := newSettings(identity, anchors, nil)
	want := []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.AES128_CTS_HMAC_SHA256_128,
	}

	for range 2 {
		wire, state, buildErr := beginASExchange(cfg, "host/server.example.com")
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		var decoded messages.ASReq
		if decodeErr := decoded.Unmarshal(wire); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if !slices.Equal(want, decoded.ReqBody.EType) || !slices.Equal(want, state.request.ReqBody.EType) {
			t.Fatalf("wire offer = %v, state offer = %v; want %v", decoded.ReqBody.EType, state.request.ReqBody.EType, want)
		}

		// Editing one request must not affect membership or the next request.
		state.request.ReqBody.EType[0] = 0
		if !isPKU2UEType(want[0]) || isPKU2UEType(0) {
			t.Fatal("editing the request changed subkey validation")
		}
	}
}

func TestPKU2USubkeyEnctypePolicy(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		id   int32
		want bool
	}{
		{name: "aes256 sha1", id: etypeID.AES256_CTS_HMAC_SHA1_96, want: true},
		{name: "aes128 sha1", id: etypeID.AES128_CTS_HMAC_SHA1_96, want: true},
		{name: "aes256 sha384", id: etypeID.AES256_CTS_HMAC_SHA384_192, want: true},
		{name: "aes128 sha256", id: etypeID.AES128_CTS_HMAC_SHA256_128, want: true},
		{name: "rc4", id: etypeID.RC4_HMAC, want: false},
		{name: "triple des", id: etypeID.DES3_CBC_SHA1_KD, want: false},
		{name: "unknown", id: -1, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isPKU2UEType(tt.id); got != tt.want {
				t.Fatalf("isPKU2UEType(%d) = %t, want %t", tt.id, got, tt.want)
			}
		})
	}
}
