package pac

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"reflect"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func processingPAC(t *testing.T, buffers ...pacBuffer) PACType {
	t.Helper()
	data, err := marshalPACBuffers(0, buffers)
	if err != nil {
		t.Fatal(err)
	}
	var value PACType
	if err := value.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	return value
}

func seedProcessedPAC(value *PACType) {
	fields := reflect.ValueOf(value).Elem()
	for i := 0; i < fields.NumField(); i++ {
		field := fields.Field(i)
		if field.Kind() == reflect.Pointer {
			field.Set(reflect.New(field.Type().Elem()))
		}
	}
}

func TestPACProcessingValidationBeforeReset(t *testing.T) {
	value := processingPAC(t)
	seedProcessedPAC(&value)
	value.CBuffers++
	before := value
	err := value.ProcessPACInfoBuffersWithCredentialKey(types.EncryptionKey{}, types.EncryptionKey{}, nil)
	if !errors.Is(err, ErrPACMalformed) || !reflect.DeepEqual(value, before) {
		t.Fatalf("validation changed prior state: error=%v, before=%+v, after=%+v", err, before, value)
	}
}

func TestPACProcessingResetAndMetadata(t *testing.T) {
	value := processingPAC(t, pacBuffer{typeID: 99, data: []byte{7}})
	expected := value
	seedProcessedPAC(&value)
	value.ZeroSigData = bytes.Repeat([]byte{0xff}, len(value.Data)+16)
	var logged bytes.Buffer
	err := value.ProcessPACInfoBuffersWithCredentialKey(types.EncryptionKey{}, types.EncryptionKey{}, log.New(&logged, "", 0))
	if err == nil || err.Error() != "PAC Info Buffers does not contain a KerbValidationInfo" {
		t.Fatalf("verification error = %v", err)
	}
	if !reflect.DeepEqual(value, expected) || logged.Len() != 0 {
		t.Fatalf("reset/metadata/log mismatch: value=%+v, log=%q", value, logged.String())
	}
	value.ZeroSigData[0] ^= 0xff
	if !bytes.Equal(value.Data, expected.Data) {
		t.Fatal("ZeroSigData aliases Data")
	}
}

func TestPACProcessingSkippedDuplicates(t *testing.T) {
	tests := []struct {
		name   string
		typeID uint32
		data   []byte
		want   string
	}{
		{"credentials without key", infoTypeCredentials, []byte{1}, "PAC is malformed: duplicate buffer type 2"},
		{"empty client claims", infoTypePACClientClaimsInfo, nil, "PAC is malformed: duplicate buffer type 13"},
		{"unknown types", 99, []byte{1}, "PAC Info Buffers does not contain a KerbValidationInfo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := processingPAC(t, pacBuffer{typeID: tt.typeID, data: tt.data}, pacBuffer{typeID: tt.typeID, data: tt.data})
			err := value.ProcessPACInfoBuffers(types.EncryptionKey{}, nil)
			if err == nil || err.Error() != tt.want || value.CredentialsInfo != nil || value.ClientClaimsInfo != nil {
				t.Fatalf("error=%v, credentials=%+v, claims=%+v", err, value.CredentialsInfo, value.ClientClaimsInfo)
			}
		})
	}
}

func processingErrorChain(err error) []string {
	var chain []string
	for err != nil {
		chain = append(chain, err.Error())
		err = errors.Unwrap(err)
	}
	return chain
}

func TestPACProcessingDecoderErrorChains(t *testing.T) {
	key := types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{1}, 16)}
	tests := []struct {
		name   string
		typeID uint32
		decode func([]byte) error
	}{
		{"KerbValidationInfo", infoTypeKerbValidationInfo, new(KerbValidationInfo).Unmarshal},
		{"CredentialsInfo", infoTypeCredentials, func(b []byte) error { return new(CredentialsInfo).Unmarshal(b, key) }},
		{"ClientInfo", infoTypePACClientInfo, new(ClientInfo).Unmarshal},
		{"S4U_DelegationInfo", infoTypeS4UDelegationInfo, new(S4UDelegationInfo).Unmarshal},
		{"UPN_DNSInfo", infoTypeUPNDNSInfo, new(UPNDNSInfo).Unmarshal},
		{"ClientClaimsInfo", infoTypePACClientClaimsInfo, new(ClientClaimsInfo).Unmarshal},
		{"DeviceInfo", infoTypePACDeviceInfo, new(DeviceInfo).Unmarshal},
		{"DeviceClaimsInfo", infoTypePACDeviceClaimsInfo, new(DeviceClaimsInfo).Unmarshal},
		{"AttributesInfo", infoTypePACAttributesInfo, new(AttributesInfo).Unmarshal},
		{"Requestor", infoTypePACRequestor, new(Requestor).Unmarshal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte{1}
			value := processingPAC(t, pacBuffer{typeID: tt.typeID, data: payload})
			expected := value
			seedProcessedPAC(&value)
			cause := tt.decode(payload)
			if cause == nil {
				t.Fatal("malformed fixture decoded successfully")
			}
			want := processingErrorChain(fmt.Errorf("error processing %s: %w", tt.name, cause))
			err := value.ProcessPACInfoBuffersWithCredentialKey(types.EncryptionKey{}, key, nil)
			if !reflect.DeepEqual(processingErrorChain(err), want) || !reflect.DeepEqual(value, expected) {
				t.Fatalf("error chain=%q, want=%q; partial state=%+v", processingErrorChain(err), want, value)
			}
		})
	}
}

func TestPACProcessingSignatureOrder(t *testing.T) {
	tests := []struct {
		name   string
		typeID uint32
		field  string
	}{
		{"ServerChecksum", infoTypePACServerSignatureData, "ServerChecksum"},
		{"KDCChecksum", infoTypePACKDCSignatureData, "KDCChecksum"},
		{"TicketChecksum", infoTypePACTicketChecksum, "TicketChecksum"},
		{"FullChecksum", infoTypePACFullChecksum, "FullChecksum"},
	}
	signature := SignatureData{SignatureType: 15, Signature: bytes.Repeat([]byte{0x5a}, 12), RODCIdentifier: 42, HasRODCIdentifier: true}
	payload, err := signature.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := processingPAC(t, pacBuffer{typeID: tt.typeID, data: payload}, pacBuffer{typeID: tt.typeID, data: []byte{1}})
			original := append([]byte(nil), value.Data...)
			wantZero := append([]byte(nil), original...)
			offset := value.Buffers[0].Offset
			clear(wantZero[offset+4 : offset+16])
			err := value.ProcessPACInfoBuffers(types.EncryptionKey{}, nil)
			wantErr := fmt.Sprintf("PAC is malformed: duplicate buffer type %d", tt.typeID)
			decoded := reflect.ValueOf(value).FieldByName(tt.field).Interface()
			if err == nil || err.Error() != wantErr || !errors.Is(err, ErrPACMalformed) || !reflect.DeepEqual(decoded, &signature) {
				t.Fatalf("duplicate error=%v, signature=%+v", err, decoded)
			}
			if !bytes.Equal(value.ZeroSigData, wantZero) || !bytes.Equal(value.Data, original) {
				t.Fatal("signature copy timing or Data preservation changed")
			}
		})
		t.Run(tt.name+" decoder failure", func(t *testing.T) {
			value := processingPAC(t, pacBuffer{typeID: tt.typeID, data: []byte{1}})
			expected := value
			_, cause := new(SignatureData).Unmarshal([]byte{1})
			want := processingErrorChain(fmt.Errorf("error processing %s: %w", tt.name, cause))
			err := value.ProcessPACInfoBuffers(types.EncryptionKey{}, nil)
			if !reflect.DeepEqual(processingErrorChain(err), want) || !reflect.DeepEqual(value, expected) {
				t.Fatalf("failed signature decode changed state: error=%v, state=%+v", err, value)
			}
		})
	}
}

func TestPACProcessingEarlierMutationSurvivesError(t *testing.T) {
	client, err := hex.DecodeString(testdata.MarshaledPAC_Client_Info)
	if err != nil {
		t.Fatal(err)
	}
	value := processingPAC(t, pacBuffer{typeID: infoTypePACClientInfo, data: client}, pacBuffer{typeID: infoTypePACRequestor, data: []byte{1}})
	var expected ClientInfo
	if err = expected.Unmarshal(client); err != nil {
		t.Fatal(err)
	}
	err = value.ProcessPACInfoBuffers(types.EncryptionKey{}, nil)
	if err == nil || !bytes.HasPrefix([]byte(err.Error()), []byte("error processing Requestor: ")) || !reflect.DeepEqual(value.ClientInfo, &expected) || value.Requestor != nil {
		t.Fatalf("error=%v, client=%+v, requestor=%+v", err, value.ClientInfo, value.Requestor)
	}
}

func processingEmptyNDR() []byte {
	data := make([]byte, 64)
	data[0], data[1] = 1, 0x10
	binary.LittleEndian.PutUint16(data[2:], 8)
	binary.LittleEndian.PutUint32(data[8:], 48)
	binary.LittleEndian.PutUint32(data[16:], 1)
	return data
}

func TestPACProcessingSuccessfulDecoders(t *testing.T) {
	tests := []struct {
		name   string
		typeID uint32
		hex    string
		value  interface{ Unmarshal([]byte) error }
	}{
		{"KerbValidationInfo", infoTypeKerbValidationInfo, testdata.MarshaledPAC_Kerb_Validation_Info_MS, new(KerbValidationInfo)},
		{"ClientInfo", infoTypePACClientInfo, testdata.MarshaledPAC_Client_Info, new(ClientInfo)},
		{"S4UDelegationInfo", infoTypeS4UDelegationInfo, hex.EncodeToString(processingEmptyNDR()), new(S4UDelegationInfo)},
		{"UPNDNSInfo", infoTypeUPNDNSInfo, testdata.MarshaledPAC_UPN_DNS_Info, new(UPNDNSInfo)},
		{"ClientClaimsInfo", infoTypePACClientClaimsInfo, testdata.MarshaledPAC_ClientClaimsInfoStr, new(ClientClaimsInfo)},
		{"DeviceInfo", infoTypePACDeviceInfo, hex.EncodeToString(processingEmptyNDR()), new(DeviceInfo)},
		{"DeviceClaimsInfo", infoTypePACDeviceClaimsInfo, testdata.MarshaledPAC_ClientClaimsInfoStr, new(DeviceClaimsInfo)},
		{"AttributesInfo", infoTypePACAttributesInfo, "0200000001000000", new(AttributesInfo)},
		{"Requestor", infoTypePACRequestor, "0101000000000005f4010000", new(Requestor)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := hex.DecodeString(tt.hex)
			if err != nil {
				t.Fatal(err)
			}
			if err = tt.value.Unmarshal(payload); err != nil {
				t.Fatal(err)
			}
			value := processingPAC(t, pacBuffer{typeID: tt.typeID, data: payload}, pacBuffer{typeID: tt.typeID, data: []byte{1}})
			err = value.ProcessPACInfoBuffers(types.EncryptionKey{}, nil)
			want := fmt.Sprintf("PAC is malformed: duplicate buffer type %d", tt.typeID)
			got := reflect.ValueOf(value).FieldByName(tt.name).Interface()
			if err == nil || err.Error() != want || !errors.Is(err, ErrPACMalformed) || !reflect.DeepEqual(got, tt.value) {
				t.Fatalf("error=%v, decoded=%+v, want=%+v", err, got, tt.value)
			}
		})
	}
}

func TestPACProcessingCredentialDecryptionFailureState(t *testing.T) {
	key := types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{1}, 16)}
	plain := processingEmptyNDR()
	_, encrypted, err := (crypto.Aes128CtsHmacSha96{}).EncryptMessage(key.KeyValue, plain, keyusage.KERB_NON_KERB_SALT)
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 8)
	binary.LittleEndian.PutUint32(payload[4:], 17)
	payload = append(payload, encrypted...)
	value := processingPAC(t, pacBuffer{typeID: infoTypeCredentials, data: payload})
	expected := value
	seedProcessedPAC(&value)
	cause := new(CredentialsInfo).Unmarshal(payload, key)
	if cause == nil || cause.Error() != "error unmarshaling PAC credential data: missing conformant array maximum" {
		t.Fatalf("credential fixture error = %v", cause)
	}
	err = value.ProcessPACInfoBuffersWithCredentialKey(types.EncryptionKey{}, key, nil)
	want := processingErrorChain(fmt.Errorf("error processing CredentialsInfo: %w", cause))
	if !reflect.DeepEqual(processingErrorChain(err), want) || !reflect.DeepEqual(value, expected) {
		t.Fatalf("error=%v, credentials=%+v", err, value.CredentialsInfo)
	}
}

func FuzzPACProcessingInfoBuffers(f *testing.F) {
	for _, typeID := range []uint32{
		infoTypeKerbValidationInfo, infoTypeCredentials, infoTypePACServerSignatureData,
		infoTypePACKDCSignatureData, infoTypePACClientInfo, infoTypeS4UDelegationInfo,
		infoTypeUPNDNSInfo, infoTypePACClientClaimsInfo, infoTypePACDeviceInfo,
		infoTypePACDeviceClaimsInfo, infoTypePACTicketChecksum, infoTypePACAttributesInfo,
		infoTypePACRequestor, infoTypePACFullChecksum, 99,
	} {
		f.Add(typeID, []byte{1}, false, true)
		f.Add(typeID, []byte{}, true, false)
	}
	for _, seed := range []struct {
		typeID uint32
		hex    string
	}{
		{infoTypeKerbValidationInfo, testdata.MarshaledPAC_Kerb_Validation_Info_MS},
		{infoTypePACClientInfo, testdata.MarshaledPAC_Client_Info},
		{infoTypeUPNDNSInfo, testdata.MarshaledPAC_UPN_DNS_Info},
		{infoTypePACClientClaimsInfo, testdata.MarshaledPAC_ClientClaimsInfoStr},
		{infoTypePACDeviceClaimsInfo, testdata.MarshaledPAC_ClientClaimsInfoStr},
		{infoTypePACServerSignatureData, testdata.MarshaledPAC_Server_Signature},
		{infoTypePACKDCSignatureData, testdata.MarshaledPAC_KDC_Signature},
		{infoTypePACTicketChecksum, testdata.MarshaledPAC_Server_Signature},
		{infoTypePACFullChecksum, testdata.MarshaledPAC_KDC_Signature},
		{infoTypeS4UDelegationInfo, hex.EncodeToString(processingEmptyNDR())},
		{infoTypePACDeviceInfo, hex.EncodeToString(processingEmptyNDR())},
		{infoTypePACAttributesInfo, "0200000001000000"},
		{infoTypePACRequestor, "0101000000000005f4010000"},
	} {
		data, err := hex.DecodeString(seed.hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(seed.typeID, data, true, true)
	}
	f.Fuzz(func(t *testing.T, typeID uint32, payload []byte, duplicate, withKey bool) {
		buffers := []pacBuffer{{typeID: typeID, data: payload}}
		if duplicate {
			buffers = append(buffers, buffers[0])
		}
		value := processingPAC(t, buffers...)
		original := append([]byte(nil), value.Data...)
		key := types.EncryptionKey{}
		if withKey {
			key = types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{1}, 16)}
		}
		_ = value.ProcessPACInfoBuffersWithCredentialKey(types.EncryptionKey{}, key, nil)
		if !bytes.Equal(value.Data, original) || len(value.ZeroSigData) != len(original) {
			t.Fatal("processing mutated Data or changed ZeroSigData length")
		}
	})
}
