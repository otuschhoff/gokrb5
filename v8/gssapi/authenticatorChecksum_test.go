package gssapi

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChannelBindingsMD5Hash(t *testing.T) {
	bindings := ChannelBindings{
		InitiatorAddress: ChannelBindingAddress{AddressType: 2, Address: []byte{127, 0, 0, 1}},
		AcceptorAddress:  ChannelBindingAddress{AddressType: 2, Address: []byte{127, 0, 0, 2}},
		ApplicationData:  []byte("tls-server-end-point:test"),
	}
	got := bindings.MD5Hash()
	want, err := hex.DecodeString("ea865cf8a6583ce11690cc9d416760ca")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, want, got[:])
	assert.Len(t, got, md5.Size)
}

func TestAuthenticatorChecksumRoundTrip(t *testing.T) {
	bindings := ChannelBindings{ApplicationData: []byte("binding")}
	want := NewAuthenticatorChecksum(&bindings, ContextFlagDeleg, ContextFlagMutual, ContextFlagInteg)
	want.DelegationOption = 1
	want.Deleg = []byte{1, 2, 3, 4}
	want.Exts = []AuthenticatorChecksumExtension{{Type: 7, Data: []byte("ext")}}
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got AuthenticatorChecksum
	if err := got.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, want, got)
}

func TestAuthenticatorChecksumRejectsTruncation(t *testing.T) {
	checksum := NewAuthenticatorChecksum(nil, ContextFlagDeleg)
	b, err := checksum.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assert.Error(t, new(AuthenticatorChecksum).Unmarshal(b[:len(b)-1]))
	assert.Error(t, new(AuthenticatorChecksum).Unmarshal(make([]byte, 23)))
}

func TestAuthenticatorChecksumRejectsInvalidValues(t *testing.T) {
	_, err := (AuthenticatorChecksum{Deleg: make([]byte, 1<<16), Flags: ContextFlagDeleg}).Marshal()
	assert.Error(t, err)
	_, err = (AuthenticatorChecksum{Deleg: []byte{1}}).Marshal()
	assert.Error(t, err)

	badBindingLength := make([]byte, 24)
	binary.LittleEndian.PutUint32(badBindingLength[:4], 15)
	assert.Error(t, new(AuthenticatorChecksum).Unmarshal(badBindingLength))

	truncatedDeleg := make([]byte, 28)
	binary.LittleEndian.PutUint32(truncatedDeleg[:4], authenticatorChecksumBindingLength)
	binary.LittleEndian.PutUint32(truncatedDeleg[20:24], ContextFlagDeleg)
	binary.LittleEndian.PutUint16(truncatedDeleg[26:28], 1)
	assert.Error(t, new(AuthenticatorChecksum).Unmarshal(truncatedDeleg))

	truncatedExtensionHeader := make([]byte, 25)
	binary.LittleEndian.PutUint32(truncatedExtensionHeader[:4], authenticatorChecksumBindingLength)
	assert.Error(t, new(AuthenticatorChecksum).Unmarshal(truncatedExtensionHeader))

	truncatedExtensionData := make([]byte, 32)
	binary.LittleEndian.PutUint32(truncatedExtensionData[:4], authenticatorChecksumBindingLength)
	binary.LittleEndian.PutUint32(truncatedExtensionData[28:32], 1)
	assert.Error(t, new(AuthenticatorChecksum).Unmarshal(truncatedExtensionData))
}
