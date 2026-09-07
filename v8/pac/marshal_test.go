package pac

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
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

func TestPACMarshalReencodesTypedBuffers(t *testing.T) {
	signature := &SignatureData{
		SignatureType: uint32(chksumtype.HMAC_SHA1_96_AES128),
		Signature:     bytes.Repeat([]byte{0x5a}, 12),
	}
	requestor := &Requestor{SID: mstypes.RPCSID{
		Revision: 1, SubAuthorityCount: 1,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{500},
	}}
	pac := PACType{
		AttributesInfo: &AttributesInfo{Flags: PACWasRequested},
		Requestor:      requestor,
		ClientInfo:     &ClientInfo{Name: "alice"},
		UPNDNSInfo:     &UPNDNSInfo{UPN: "alice@example.org", DNSDomain: "EXAMPLE.ORG"},
		ServerChecksum: signature,
		KDCChecksum:    signature,
		TicketChecksum: signature,
		FullChecksum:   signature,
	}
	typeIDs := []uint32{
		infoTypePACServerSignatureData, infoTypePACKDCSignatureData,
		infoTypePACTicketChecksum, infoTypePACFullChecksum,
		infoTypePACAttributesInfo, infoTypePACRequestor,
		infoTypePACClientInfo, infoTypeUPNDNSInfo, 99,
	}
	placeholders := make([]pacBuffer, len(typeIDs))
	for i, typeID := range typeIDs {
		placeholders[i] = pacBuffer{typeID: typeID, data: []byte{byte(i)}}
	}
	raw, err := marshalPACBuffers(0, placeholders)
	if err != nil {
		t.Fatal(err)
	}
	if err := pac.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	encoded, err := pac.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, buffer := range readTestBuffers(t, encoded) {
		if buffer.typeID == 99 {
			if !bytes.Equal(buffer.data, []byte{8}) {
				t.Fatalf("unknown buffer payload = %x", buffer.data)
			}
			continue
		}
		if len(buffer.data) <= 1 {
			t.Fatalf("typed buffer %d was not re-encoded: %x", buffer.typeID, buffer.data)
		}
	}
}

func TestPACMarshalRejectsInvalidMetadata(t *testing.T) {
	tests := map[string]*PACType{
		"version": {Version: 1, Buffers: []InfoBuffer{{}}},
		"empty":   {},
		"duplicate": {
			Buffers: []InfoBuffer{{ULType: 1, Offset: 40}, {ULType: 1, Offset: 40}},
			Data:    make([]byte, 40),
		},
		"out of bounds": {
			Buffers: []InfoBuffer{{ULType: 1, CBBufferSize: 2, Offset: 24}},
			Data:    make([]byte, 24),
		},
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := value.Marshal(); err == nil {
				t.Fatal("invalid PAC metadata was accepted")
			}
		})
	}

	raw, err := marshalPACBuffers(0, []pacBuffer{{typeID: infoTypePACAttributesInfo, data: []byte{1}}})
	if err != nil {
		t.Fatal(err)
	}
	var value PACType
	if err := value.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	value.AttributesInfo = &AttributesInfo{FlagsLength: 1}
	if _, err := value.Marshal(); err == nil {
		t.Fatal("typed buffer marshal failure was ignored")
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
