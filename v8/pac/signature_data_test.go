package pac

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestPAC_SignatureData_Unmarshal_Server_Signature(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_Server_Signature)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k SignatureData
	bz, err := k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	sig, _ := hex.DecodeString("1e251d98d552be7df384f550")
	zeroed, _ := hex.DecodeString("10000000000000000000000000000000")
	assert.Equal(t, uint32(chksumtype.HMAC_SHA1_96_AES256), k.SignatureType, "Server signature type not as expected")
	assert.Equal(t, sig, k.Signature, "Server signature not as expected")
	assert.Equal(t, uint16(0), k.RODCIdentifier, "RODC Identifier not as expected")
	assert.Equal(t, zeroed, bz, "Returned bytes with zeroed signature not as expected")
}

func TestSignatureDataStrictMarshal(t *testing.T) {
	b := make([]byte, 22)
	binary.LittleEndian.PutUint32(b, chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED)
	var signature SignatureData
	if _, err := signature.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if !signature.HasRODCIdentifier {
		t.Fatal("zero-valued RODC identifier presence was lost")
	}
	roundTrip, err := signature.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, b, roundTrip)

	unknown := make([]byte, 4)
	binary.LittleEndian.PutUint32(unknown, 12345)
	if _, err := (&SignatureData{}).Unmarshal(unknown); err == nil {
		t.Fatal("unknown checksum type was accepted")
	}
	for _, size := range []int{0, 3, 15, 17, 19} {
		malformed := make([]byte, size)
		if size >= 4 {
			binary.LittleEndian.PutUint32(malformed, uint32(chksumtype.HMAC_SHA1_96_AES128))
		}
		if zeroed, err := (&SignatureData{}).Unmarshal(malformed); err == nil || zeroed != nil {
			t.Fatalf("signature length %d returned zeroed data %x, error %v", size, zeroed, err)
		}
	}
	if _, err := (&SignatureData{SignatureType: uint32(chksumtype.HMAC_SHA1_96_AES128)}).Marshal(); err == nil {
		t.Fatal("invalid signature length was accepted")
	}
}

func TestPAC_SignatureData_Unmarshal_KDC_Signature(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_KDC_Signature)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k SignatureData
	bz, err := k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	sig, _ := hex.DecodeString("340be28b48765d0519ee9346cf53d822")
	zeroed, _ := hex.DecodeString("76ffffff00000000000000000000000000000000")
	assert.Equal(t, chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED, k.SignatureType, "Server signature type not as expected")
	assert.Equal(t, sig, k.Signature, "Server signature not as expected")
	assert.Equal(t, uint16(0), k.RODCIdentifier, "RODC Identifier not as expected")
	assert.Equal(t, zeroed, bz, "Returned bytes with zeroed signature not as expected")
}
