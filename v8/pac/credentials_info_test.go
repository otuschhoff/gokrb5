package pac

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestNTLMSupplementalCredUnmarshal(t *testing.T) {
	lm := bytes.Repeat([]byte{0x11}, 16)
	nt := bytes.Repeat([]byte{0x22}, 16)
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, uint32(0))
	binary.Write(buffer, binary.LittleEndian, uint32(1<<24|1<<25))
	buffer.Write(lm)
	buffer.Write(nt)

	var credential NTLMSupplementalCred
	if err := credential.Unmarshal(buffer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if credential.Flags != 1<<24|1<<25 || !bytes.Equal(credential.LMPassword, lm) || !bytes.Equal(credential.NTPassword, nt) {
		t.Fatalf("NTLM credential = %+v", credential)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"missing version", nil},
		{"nonzero version", []byte{1, 0, 0, 0}},
		{"missing flags", []byte{0, 0, 0, 0}},
		{"short LM password", append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, make([]byte, 15)...)},
		{"short NT password", append([]byte{0, 0, 0, 0, 0, 0, 0, 2}, make([]byte, 15)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := new(NTLMSupplementalCred).Unmarshal(test.data); err == nil {
				t.Fatal("malformed credential was accepted")
			}
		})
	}
	if isFlagSet(0, NTLMSupCredLMOWF) || !isFlagSet(1<<24, NTLMSupCredLMOWF) {
		t.Fatal("supplemental credential flag decoding failed")
	}
}

func TestCredentialInfoFailurePaths(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{1}, 16)}
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"missing version", nil, "EOF"},
		{"nonzero version", []byte{1, 0, 0, 0}, "version is not zero"},
		{"missing etype", []byte{0, 0, 0, 0}, "EOF"},
		{"wrong key type", []byte{0, 0, 0, 0, 23, 0, 0, 0}, "not the correct type"},
		{"invalid ciphertext", []byte{0, 0, 0, 0, 17, 0, 0, 0, 1}, "decrypting"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := new(CredentialsInfo).Unmarshal(test.data, key); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}

	info := CredentialsInfo{EType: uint32(etypeID.RC4_HMAC)}
	if err := info.DecryptEncPart(key); err == nil || !strings.Contains(err.Error(), "not the correct type") {
		t.Fatalf("key type error = %v", err)
	}
	if err := new(CredentialData).Unmarshal([]byte{1}); err == nil || !strings.Contains(err.Error(), "unmarshaling") {
		t.Fatalf("credential data error = %v", err)
	}
	if err := new(SECPKGSupplementalCred).Unmarshal([]byte{1}); err == nil || !strings.Contains(err.Error(), "unmarshaling") {
		t.Fatalf("supplemental credential error = %v", err)
	}
}
