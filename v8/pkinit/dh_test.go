package pkinit

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"
)

func TestDHAgreementAndSPKIRoundTrip(t *testing.T) {
	alice, err := GenerateDHKey(MODPGroup14, 2048, bytes.NewReader(bytes.Repeat([]byte{0x11}, 512)))
	require.NoError(t, err)
	bob, err := GenerateDHKey(MODPGroup14, 2048, bytes.NewReader(bytes.Repeat([]byte{0x22}, 512)))
	require.NoError(t, err)
	alicePublic, err := alice.PublicKey()
	require.NoError(t, err)
	bobPublic, err := bob.PublicKey()
	require.NoError(t, err)

	der, err := asn1.Marshal(alicePublic)
	require.NoError(t, err)
	var decoded SubjectPublicKeyInfo
	require.NoError(t, strictUnmarshal(der, &decoded))
	aliceSecret, err := alice.SharedSecret(bobPublic)
	require.NoError(t, err)
	bobSecret, err := bob.SharedSecret(decoded)
	require.NoError(t, err)
	require.Equal(t, 256, len(aliceSecret))
	require.Equal(t, aliceSecret, bobSecret)
}

func TestDHRejectsWeakGroupByDefault(t *testing.T) {
	_, err := GenerateDHKey(MODPGroup2, 2048, bytes.NewReader(bytes.Repeat([]byte{1}, 256)))
	require.ErrorContains(t, err, "below policy minimum")
}

func TestDHGroup16AndSelection(t *testing.T) {
	key, err := GenerateDHKey(MODPGroup16, 4096, bytes.NewReader(bytes.Repeat([]byte{0x44}, 1024)))
	require.NoError(t, err)
	public, err := key.PublicKey()
	require.NoError(t, err)
	group, err := SelectDHGroup(TDDHParameters{public.Algorithm}, 3072)
	require.NoError(t, err)
	require.Equal(t, MODPGroup16, group)
}

func TestDHRejectsInvalidPeerPublicValue(t *testing.T) {
	key, err := GenerateDHKey(MODPGroup14, 2048, bytes.NewReader(bytes.Repeat([]byte{0x33}, 512)))
	require.NoError(t, err)
	peer, err := key.PublicKey()
	require.NoError(t, err)
	invalid, err := asn1.Marshal(big.NewInt(1))
	require.NoError(t, err)
	peer.SubjectPublicKey = asn1.BitString{Bytes: invalid, BitLength: len(invalid) * 8}
	_, err = key.SharedSecret(peer)
	require.ErrorContains(t, err, "outside the valid range")
}
