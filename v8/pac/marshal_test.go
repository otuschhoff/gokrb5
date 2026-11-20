package pac

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
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
	if ierr := decoded.Unmarshal(data); ierr != nil {
		t.Fatal(ierr)
	}
	if decoded.CBuffers != 1 || decoded.Buffers[0].Offset%8 != 0 {
		t.Fatalf("unexpected buffer table: %+v", decoded.Buffers)
	}
	info := decoded.Buffers[0]
	if got := data[info.Offset : info.Offset+uint64(info.CBBufferSize)]; !bytes.Equal(got, []byte{1, 2, 3}) {
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
		SignatureType:     uint32(chksumtype.HMAC_SHA1_96_AES128),
		Signature:         bytes.Repeat([]byte{0x5a}, 12),
		RODCIdentifier:    0,
		HasRODCIdentifier: false,
	}
	requestor := &Requestor{SID: mstypes.RPCSID{
		Revision: 1, SubAuthorityCount: 1,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{500},
	}}
	var pac PACType
	pac.AttributesInfo = &AttributesInfo{FlagsLength: 0, Flags: PACWasRequested}
	pac.Requestor = requestor
	pac.ClientInfo = new(ClientInfo)
	pac.ClientInfo.Name = "alice"
	pac.UPNDNSInfo = new(UPNDNSInfo)
	pac.UPNDNSInfo.UPN = "alice@example.org"
	pac.UPNDNSInfo.DNSDomain = "EXAMPLE.ORG"
	pac.ServerChecksum = signature
	pac.KDCChecksum = signature
	pac.TicketChecksum = signature
	pac.FullChecksum = signature
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
	if ierr := pac.Unmarshal(raw); ierr != nil {
		t.Fatal(ierr)
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
	var version, duplicate, outOfBounds PACType
	version.Version = 1
	version.Buffers = make([]InfoBuffer, 1)
	duplicate.Buffers = []InfoBuffer{
		{ULType: 1, CBBufferSize: 0, Offset: 40},
		{ULType: 1, CBBufferSize: 0, Offset: 40},
	}
	duplicate.Data = make([]byte, 40)
	outOfBounds.Buffers = []InfoBuffer{{ULType: 1, CBBufferSize: 2, Offset: 24}}
	outOfBounds.Data = make([]byte, 24)
	tests := map[string]*PACType{
		"version":       &version,
		"empty":         new(PACType),
		"duplicate":     &duplicate,
		"out of bounds": &outOfBounds,
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
	value.AttributesInfo = &AttributesInfo{FlagsLength: 1, Flags: 0}
	if _, err := value.Marshal(); err == nil {
		t.Fatal("typed buffer marshal failure was ignored")
	}
}

func TestPACSignPreservesEnctypeLookupError(t *testing.T) {
	t.Parallel()

	var key types.EncryptionKey
	key.KeyType = 12345
	encoded, err := minimalPAC().Sign(key, key)
	if encoded != nil || err == nil || !strings.HasPrefix(err.Error(), "server key: select PAC signing enctype:") {
		t.Fatalf("want contextual signing key error with no output, got %v", err)
	}
	cause := errors.Unwrap(errors.Unwrap(err))
	if cause == nil || !strings.Contains(cause.Error(), "unsupported EType") {
		t.Fatalf("signing enctype lookup cause was lost: %v", err)
	}
}

func TestPACSignFullChecksumOrder(t *testing.T) {
	serverKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x11}, 16)}
	kdcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x22}, 32)}
	data, err := minimalPAC().Sign(serverKey, kdcKey, SignOptions{IncludeFullChecksum: true, TicketData: nil})
	if err != nil {
		t.Fatal(err)
	}
	buffers := readTestBuffers(t, data)

	fullInput := append([]byte(nil), data...)
	zeroTestSignature(t, fullInput, buffers, infoTypePACServerSignatureData)
	zeroTestSignature(t, fullInput, buffers, infoTypePACKDCSignatureData)
	zeroTestSignature(t, fullInput, buffers, infoTypePACFullChecksum)
	verifyTestSignature(t, buffers, infoTypePACFullChecksum, kdcKey, fullInput)

	serverInput := append([]byte(nil), data...)
	zeroTestSignature(t, serverInput, buffers, infoTypePACServerSignatureData)
	zeroTestSignature(t, serverInput, buffers, infoTypePACKDCSignatureData)
	verifyTestSignature(t, buffers, infoTypePACServerSignatureData, serverKey, serverInput)

	serverSignature, err := signatureBytes(data, buffers, infoTypePACServerSignatureData)
	if err != nil {
		t.Fatal(err)
	}
	verifyTestSignature(t, buffers, infoTypePACKDCSignatureData, kdcKey, serverSignature)

	tampered := append([]byte(nil), serverInput...)
	payloadOffset := binary.LittleEndian.Uint64(data[16:])
	tampered[mustPACInt(t, payloadOffset)] ^= 0xff
	serverSignatureData := signatureDataForTest(t, buffers, infoTypePACServerSignatureData)
	etype, err := crypto.GetChksumEtype(mustPACInt32(t, serverSignatureData.SignatureType))
	if err != nil {
		t.Fatal(err)
	}
	if etype == nil {
		t.Fatal("checksum encryption type is nil")
	}
	if etype.VerifyChecksum(
		serverKey.KeyValue, tampered, serverSignatureData.Signature, keyusage.KERB_NON_KERB_CKSUM_SALT,
	) {
		t.Fatal("server checksum accepted tampered PAC")
	}
}

func TestPACSignTicketChecksum(t *testing.T) {
	serverKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x33}, 16)}
	kdcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x44}, 32)}
	ticketData := []byte("DER EncTicketPart with one-byte PAC placeholder")
	data, err := minimalPAC().Sign(serverKey, kdcKey, SignOptions{IncludeFullChecksum: false, TicketData: ticketData})
	if err != nil {
		t.Fatal(err)
	}
	buffers := readTestBuffers(t, data)
	verifyTestSignature(t, buffers, infoTypePACTicketChecksum, kdcKey, ticketData)
}

func minimalPAC() *PACType {
	data := make([]byte, 27)
	copy(data[24:], []byte{1, 2, 3})
	var pac PACType
	pac.Buffers = []InfoBuffer{{ULType: 99, CBBufferSize: 3, Offset: 24}}
	pac.Data = data
	return &pac
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
		buffers[i].data = data[mustPACInt(t, offset) : mustPACInt(t, offset)+int(length)]
	}
	return buffers
}

func signatureDataForTest(t *testing.T, buffers []pacBuffer, typeID uint32) SignatureData {
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
	for i := mustPACInt(t, offset) + 4; i < mustPACInt(t, offset)+int(length); i++ {
		data[i] = 0
	}
}

func verifyTestSignature(t *testing.T, buffers []pacBuffer, typeID uint32, key types.EncryptionKey, input []byte) {
	t.Helper()
	signature := signatureDataForTest(t, buffers, typeID)
	etype, err := crypto.GetChksumEtype(mustPACInt32(t, signature.SignatureType))
	if err != nil {
		t.Fatal(err)
	}
	if !etype.VerifyChecksum(key.KeyValue, input, signature.Signature, keyusage.KERB_NON_KERB_CKSUM_SALT) {
		t.Fatalf("signature buffer %d did not verify", typeID)
	}
}
