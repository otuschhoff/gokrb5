package pac

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestNTLMSupplementalCredUnmarshal(t *testing.T) {
	lm := bytes.Repeat([]byte{0x11}, 16)
	nt := bytes.Repeat([]byte{0x22}, 16)
	const supplementalFlags = 1<<24 | 1<<25
	data := binary.LittleEndian.AppendUint32(nil, 0)
	data = binary.LittleEndian.AppendUint32(data, supplementalFlags)
	data = append(data, lm...)
	data = append(data, nt...)

	var credential NTLMSupplementalCred
	if err := credential.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if credential.Flags != supplementalFlags ||
		!bytes.Equal(credential.LMPassword, lm) || !bytes.Equal(credential.NTPassword, nt) {
		t.Fatal("supplemental credential fixture did not round-trip")
	}

	tests := []struct {
		name  string
		data  []byte
		want  string
		cause error
	}{
		{name: "missing version", data: nil, want: "read supplemental credential version", cause: io.EOF},
		{name: "nonzero version", data: []byte{1, 0, 0, 0}, want: "version is not zero", cause: nil},
		{name: "missing flags", data: make([]byte, 4), want: "read supplemental credential flags", cause: io.EOF},
		{
			name: "short lm field", data: append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, make([]byte, 15)...),
			want: "read supplemental LM credential", cause: io.ErrUnexpectedEOF,
		},
		{
			name: "short nt field", data: append([]byte{0, 0, 0, 0, 0, 0, 0, 2}, make([]byte, 15)...),
			want: "read supplemental NT credential", cause: io.ErrUnexpectedEOF,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := new(NTLMSupplementalCred).Unmarshal(test.data)
			requireCredentialError(t, err, test.want, test.cause)
		})
	}
	if isFlagSet(0, NTLMSupCredLMOWF) || !isFlagSet(1<<24, NTLMSupCredLMOWF) {
		t.Fatal("supplemental credential flag decoding failed")
	}
}

func TestCredentialInfoFailurePaths(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{1}, 16)}
	tests := []struct {
		name  string
		data  []byte
		want  string
		cause error
	}{
		{name: "missing version", data: nil, want: "read PAC credentials version", cause: io.EOF},
		{name: "nonzero version", data: []byte{1, 0, 0, 0}, want: "version is not zero", cause: nil},
		{name: "missing etype", data: make([]byte, 4), want: "read PAC credentials enctype", cause: io.EOF},
		{name: "partial etype", data: make([]byte, 7), want: "read PAC credentials enctype", cause: io.ErrUnexpectedEOF},
		{name: "wrong key type", data: []byte{0, 0, 0, 0, 23, 0, 0, 0}, want: "not the correct type", cause: nil},
		{name: "invalid ciphertext", data: []byte{0, 0, 0, 0, 17, 0, 0, 0, 1}, want: "decrypting", cause: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := new(CredentialsInfo).Unmarshal(test.data, key)
			requireCredentialError(t, err, test.want, test.cause)
		})
	}

	var info CredentialsInfo
	info.EType = uint32(etypeID.RC4_HMAC)
	if err := info.DecryptEncPart(key); err == nil || !strings.Contains(err.Error(), "not the correct type") {
		t.Fatalf("key type error = %v", err)
	}
	if err := new(CredentialData).Unmarshal([]byte{1}); err == nil || !strings.Contains(err.Error(), "unmarshaling") {
		t.Fatalf("credential data error = %v", err)
	}
	if err := new(SECPKGSupplementalCred).Unmarshal([]byte{1}); err == nil ||
		!strings.Contains(err.Error(), "unmarshaling") {
		t.Fatalf("supplemental credential error = %v", err)
	}
}

func requireCredentialError(t *testing.T, err error, context string, cause error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), context) {
		t.Fatalf("want contextual failure %q, got %v", context, err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Errorf("error lost cause %v: %v", cause, err)
	}
}

func TestCredentialInfoReadsFullOpaquePayload(t *testing.T) {
	t.Parallel()

	const headerLength = 8
	payload := make([]byte, headerLength+8192)
	binary.LittleEndian.PutUint32(payload[4:], uint32(etypeID.AES128_CTS_HMAC_SHA1_96))
	payload[headerLength] = 1
	var info CredentialsInfo
	var missingKey types.EncryptionKey
	if err := info.Unmarshal(payload, missingKey); err == nil || !strings.Contains(err.Error(), "not the correct type") {
		t.Fatalf("expected key rejection after reading the payload, got %v", err)
	}
	if !bytes.Equal(info.PACCredentialDataEncrypted, payload[headerLength:]) {
		t.Fatal("credential payload was truncated")
	}
	payload[headerLength] = 2
	if info.PACCredentialDataEncrypted[0] != 1 {
		t.Fatal("credential payload aliases input")
	}
}
