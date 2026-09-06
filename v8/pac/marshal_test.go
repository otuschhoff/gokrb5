package pac

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestPACMarshalAlignmentAndPreservation(t *testing.T) {
	pac := minimalPAC()
	data, err := pac.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decoded PACType
	if err := decoded.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if decoded.CBuffers != 1 || decoded.Buffers[0].Offset%8 != 0 {
		t.Fatalf("unexpected buffer table: %+v", decoded.Buffers)
	}
	if got := data[decoded.Buffers[0].Offset : decoded.Buffers[0].Offset+uint64(decoded.Buffers[0].CBBufferSize)]; !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("payload = %x", got)
	}
	again, err := decoded.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, again) {
		t.Fatal("marshal is not deterministic")
	}
}

func TestPACSignFullChecksumOrder(t *testing.T) {
	serverKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x11}, 16)}
	kdcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x22}, 32)}
	data, err := minimalPAC().Sign(serverKey, kdcKey, SignOptions{IncludeFullChecksum: true})
	if err != nil {
		t.Fatal(err)
	}
	buffers := readTestBuffers(t, data)

	fullInput := append([]byte(nil), data...)
	zeroTestSignature(t, fullInput, buffers, infoTypePACServerSignatureData)
	zeroTestSignature(t, fullInput, buffers, infoTypePACKDCSignatureData)
	zeroTestSignature(t, fullInput, buffers, infoTypePACFullChecksum)
	verifyTestSignature(t, data, buffers, infoTypePACFullChecksum, kdcKey, fullInput)

	serverInput := append([]byte(nil), data...)
	zeroTestSignature(t, serverInput, buffers, infoTypePACServerSignatureData)
	zeroTestSignature(t, serverInput, buffers, infoTypePACKDCSignatureData)
	verifyTestSignature(t, data, buffers, infoTypePACServerSignatureData, serverKey, serverInput)

	serverSignature, err := signatureBytes(data, buffers, infoTypePACServerSignatureData)
	if err != nil {
		t.Fatal(err)
	}
	verifyTestSignature(t, data, buffers, infoTypePACKDCSignatureData, kdcKey, serverSignature)

	tampered := append([]byte(nil), serverInput...)
	payloadOffset := binary.LittleEndian.Uint64(data[16:])
	tampered[int(payloadOffset)] ^= 0xff
	serverSignatureData := signatureDataForTest(t, data, buffers, infoTypePACServerSignatureData)
	etype, _ := crypto.GetChksumEtype(int32(serverSignatureData.SignatureType))
	if etype.VerifyChecksum(serverKey.KeyValue, tampered, serverSignatureData.Signature, keyusage.KERB_NON_KERB_CKSUM_SALT) {
		t.Fatal("server checksum accepted tampered PAC")
	}
}

func TestPACSignTicketChecksum(t *testing.T) {
	serverKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x33}, 16)}
	kdcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x44}, 32)}
	ticketData := []byte("DER EncTicketPart with one-byte PAC placeholder")
	data, err := minimalPAC().Sign(serverKey, kdcKey, SignOptions{TicketData: ticketData})
	if err != nil {
		t.Fatal(err)
	}
	buffers := readTestBuffers(t, data)
	verifyTestSignature(t, data, buffers, infoTypePACTicketChecksum, kdcKey, ticketData)
}

func minimalPAC() *PACType {
	data := make([]byte, 27)
	copy(data[24:], []byte{1, 2, 3})
	return &PACType{
		Version: 0,
		Buffers: []InfoBuffer{{ULType: 99, CBBufferSize: 3, Offset: 24}},
		Data:    data,
	}
}

func readTestBuffers(t *testing.T, data []byte) []pacBuffer {
	t.Helper()
	count := int(binary.LittleEndian.Uint32(data))
	buffers := make([]pacBuffer, count)
	for i := range buffers {
		header := 8 + i*16
		buffers[i].typeID = binary.LittleEndian.Uint32(data[header:])
		length := binary.LittleEndian.Uint32(data[header+4:])
		offset := binary.LittleEndian.Uint64(data[header+8:])
		buffers[i].data = data[int(offset) : int(offset)+int(length)]
	}
	return buffers
}

func signatureDataForTest(t *testing.T, data []byte, buffers []pacBuffer, typeID uint32) SignatureData {
	t.Helper()
	index := findBuffer(buffers, typeID)
	if index < 0 {
		t.Fatalf("missing signature buffer %d", typeID)
	}
	var signature SignatureData
	if _, err := signature.Unmarshal(buffers[index].data); err != nil {
		t.Fatal(err)
	}
	return signature
}

func zeroTestSignature(t *testing.T, data []byte, buffers []pacBuffer, typeID uint32) {
	t.Helper()
	index := findBuffer(buffers, typeID)
	if index < 0 {
		t.Fatalf("missing signature buffer %d", typeID)
	}
	header := 8 + index*16
	offset := binary.LittleEndian.Uint64(data[header+8:])
	length := binary.LittleEndian.Uint32(data[header+4:])
	for i := int(offset) + 4; i < int(offset)+int(length); i++ {
		data[i] = 0
	}
}

func verifyTestSignature(t *testing.T, data []byte, buffers []pacBuffer, typeID uint32, key types.EncryptionKey, input []byte) {
	t.Helper()
	signature := signatureDataForTest(t, data, buffers, typeID)
	etype, err := crypto.GetChksumEtype(int32(signature.SignatureType))
	if err != nil {
		t.Fatal(err)
	}
	if !etype.VerifyChecksum(key.KeyValue, input, signature.Signature, keyusage.KERB_NON_KERB_CKSUM_SALT) {
		t.Fatalf("signature buffer %d did not verify", typeID)
	}
}
