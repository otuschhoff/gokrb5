package types

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/iana/patype"
)

func TestASN1DecodeErrorContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		context string
		decode  func([]byte) error
	}{
		{name: "authenticator", context: "decode authenticator:", decode: new(Authenticator).Unmarshal},
		{name: "kdc issued", context: "ADKDCIssued:", decode: new(ADKDCIssued).Unmarshal},
		{name: "authorization data", context: "AuthorizationData:", decode: new(AuthorizationData).Unmarshal},
		{name: "authorization entry", context: "AuthorizationDataEntry:", decode: new(AuthorizationDataEntry).Unmarshal},
		{name: "encrypted data", context: "EncryptedData:", decode: new(EncryptedData).Unmarshal},
		{name: "key", context: "EncryptionKey:", decode: new(EncryptionKey).Unmarshal},
		{name: "checksum", context: "Checksum:", decode: new(Checksum).Unmarshal},
		{name: "preauth data", context: "PAData:", decode: new(PAData).Unmarshal},
		{name: "preauth sequence", context: "PADataSequence:", decode: new(PADataSequence).Unmarshal},
		{name: "reply checksum", context: "PAReqEncPARep:", decode: new(PAReqEncPARep).Unmarshal},
		{name: "encrypted timestamp", context: "PAEncTimestamp:", decode: new(PAEncTimestamp).Unmarshal},
		{name: "timestamp", context: "PAEncTSEnc:", decode: new(PAEncTSEnc).Unmarshal},
		{name: "enctype info", context: "ETypeInfo:", decode: new(ETypeInfo).Unmarshal},
		{name: "enctype info entry", context: "ETypeInfoEntry:", decode: new(ETypeInfoEntry).Unmarshal},
		{name: "enctype info 2", context: "ETypeInfo2:", decode: new(ETypeInfo2).Unmarshal},
		{name: "enctype info 2 entry", context: "ETypeInfo2Entry:", decode: new(ETypeInfo2Entry).Unmarshal},
		{name: "typed data", context: "TypedDataSequence:", decode: new(TypedDataSequence).Unmarshal},
		{name: "pac request", context: "KerbPAPACRequest:", decode: new(KerbPAPACRequest).Unmarshal},
		{name: "fast request", context: "PA-FX-FAST-REQUEST wrapper:", decode: new(PAFXFastRequest).Unmarshal},
		{name: "fast reply", context: "PA-FX-FAST-REPLY wrapper:", decode: new(PAFXFastReply).Unmarshal},
		{name: "fast error", context: "PA-FX-ERROR wrapper:", decode: new(PAFXError).Unmarshal},
		{name: "kdc proxy", context: "decode KDC-PROXY-MESSAGE:", decode: new(KDCProxyMessage).Unmarshal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.decode(nil)
			checkASN1ErrorContext[asn1.SyntaxError](t, err, tt.context)
		})
	}
}

func TestPADataETypeInfoErrorContext(t *testing.T) {
	t.Parallel()

	pa := PAData{PADataType: patype.PA_ETYPE_INFO, PADataValue: []byte{0x30}}
	info, err := pa.GetETypeInfo()
	if info != nil {
		t.Fatal("malformed input returned enctype info")
	}
	checkASN1ErrorContext[asn1.SyntaxError](t, err, "ETypeInfo:")

	pa.PADataType = patype.PA_ETYPE_INFO2
	info2, err := pa.GetETypeInfo2()
	if info2 != nil {
		t.Fatal("malformed input returned enctype info 2")
	}
	checkASN1ErrorContext[asn1.SyntaxError](t, err, "ETypeInfo2:")
}

func TestASN1TrailingDataPolicy(t *testing.T) {
	t.Parallel()

	want := PAData{PADataType: patype.PA_ETYPE_INFO, PADataValue: []byte{0x30, 0x00}}
	b, err := asn1.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var pa PAData
	if decodeErr := pa.Unmarshal(append(b, 0)); decodeErr != nil {
		t.Fatalf("PAData rejected a valid prefix: %v", decodeErr)
	}
	if pa.PADataType != want.PADataType || !bytes.Equal(pa.PADataValue, want.PADataValue) {
		t.Fatalf("decoded PAData = %+v, want %+v", pa, want)
	}

	request := KerbPAPACRequest{IncludePAC: true}
	b, err = request.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	err = new(KerbPAPACRequest).Unmarshal(append(b, 0))
	if err == nil || err.Error() != "trailing ASN.1 data: 1 bytes" {
		t.Fatalf("KerbPAPACRequest.Unmarshal = %v, want trailing ASN.1 data error", err)
	}
}

func TestMSKILEMarshalErrorContext(t *testing.T) {
	t.Parallel()

	var pkg KerbDMSAKeyPackage
	pkg.ExpirationInterval = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	b, err := pkg.Marshal()
	if b != nil {
		t.Fatal("marshal failure returned bytes")
	}
	checkASN1ErrorContext[asn1.StructuralError](t, err, "types.KerbDMSAKeyPackage:")
}

func checkASN1ErrorContext[E error](t *testing.T, err error, context string) {
	t.Helper()
	if _, ok := errors.AsType[E](err); !ok {
		t.Fatalf("error %v does not retain the ASN.1 cause", err)
	}
	if !strings.Contains(err.Error(), context) {
		t.Fatalf("error %q lacks context %q", err, context)
	}
}
