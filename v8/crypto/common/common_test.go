package common_test

import (
	"bytes"
	"testing"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/common"
)

func TestZeroPad(t *testing.T) {
	original := []byte{1, 2, 3}
	padded, err := common.ZeroPad(append([]byte(nil), original...), 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded, []byte{1, 2, 3, 0}) {
		t.Fatalf("padded = %v", padded)
	}
	aligned, err := common.ZeroPad([]byte{1, 2, 3, 4}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aligned, []byte{1, 2, 3, 4}) {
		t.Fatalf("aligned = %v", aligned)
	}
	for _, test := range []struct {
		name  string
		input []byte
		block int
	}{
		{name: "invalid block", input: []byte{1}, block: 0},
		{name: "empty", input: nil, block: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := common.ZeroPad(test.input, test.block); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPKCS7PadAndUnpad(t *testing.T) {
	for _, input := range [][]byte{{1, 2, 3}, {1, 2, 3, 4}} {
		padded, err := common.PKCS7Pad(input, 4)
		if err != nil {
			t.Fatal(err)
		}
		unpadded, err := common.PKCS7Unpad(padded, 4)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(unpadded, input) {
			t.Fatalf("round trip = %v, want %v", unpadded, input)
		}
	}

	invalid := []struct {
		name  string
		input []byte
		block int
	}{
		{name: "invalid block", input: []byte{1}, block: 0},
		{name: "empty", input: nil, block: 4},
		{name: "unaligned", input: []byte{1, 2, 3}, block: 4},
		{name: "zero length", input: []byte{1, 2, 3, 0}, block: 4},
		{name: "oversized length", input: []byte{1, 2, 3, 5}, block: 4},
		{name: "inconsistent", input: []byte{1, 2, 3, 2}, block: 4},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := common.PKCS7Unpad(test.input, test.block); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := common.PKCS7Pad(nil, 4); err == nil {
		t.Fatal("expected empty padding error")
	}
	if _, err := common.PKCS7Pad([]byte{1}, 0); err == nil {
		t.Fatal("expected invalid block padding error")
	}
}

func TestChecksumAndUsageHelpers(t *testing.T) {
	etype := krbcrypto.Aes128CtsHmacSha256128{}
	key := bytes.Repeat([]byte{0x42}, etype.GetKeyByteSize())
	message := []byte("integrity protected")
	const usage = uint32(0x01020304)

	checksum, err := common.GetChecksumHash(message, key, usage, etype)
	if err != nil {
		t.Fatal(err)
	}
	if len(checksum) != etype.GetHMACBitLength()/8 {
		t.Fatalf("checksum length = %d", len(checksum))
	}
	if !common.VerifyChecksum(key, checksum, message, usage, etype) {
		t.Fatal("valid checksum rejected")
	}
	checksum[0] ^= 0xff
	if common.VerifyChecksum(key, checksum, message, usage, etype) {
		t.Fatal("tampered checksum accepted")
	}
	integrity, err := common.GetIntegrityHash(message, key, usage, etype)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(integrity, checksum) {
		t.Fatal("integrity and checksum usages produced the same hash")
	}

	if got := common.GetUsageKc(usage); !bytes.Equal(got, []byte{1, 2, 3, 4, 0x99}) {
		t.Fatalf("Kc usage = %x", got)
	}
	if got := common.GetUsageKe(usage); !bytes.Equal(got, []byte{1, 2, 3, 4, 0xaa}) {
		t.Fatalf("Ke usage = %x", got)
	}
	if got := common.GetUsageKi(usage); !bytes.Equal(got, []byte{1, 2, 3, 4, 0x55}) {
		t.Fatalf("Ki usage = %x", got)
	}
	if got := common.IterationsToS2Kparams(32768); got != "00008000" {
		t.Fatalf("S2K params = %q", got)
	}
}
