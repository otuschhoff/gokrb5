package messages

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestKRBErrorMethodData(t *testing.T) {
	want := types.PADataSequence{{PADataType: patype.PA_FX_COOKIE, PADataValue: []byte("cookie")}}
	b, err := asn1.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	k := KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED, EData: b}
	got, err := k.MethodData()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MethodData = %#v, want %#v", got, want)
	}
	k.ErrorCode = errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
	if _, err := k.MethodData(); err != nil {
		t.Fatalf("KDC_ERR_MORE_PREAUTH_DATA_REQUIRED METHOD-DATA: %v", err)
	}
	k.ErrorCode = errorcode.KRB_ERR_GENERIC
	if _, err := k.MethodData(); err == nil {
		t.Fatal("non-preauth KRB-ERROR accepted as METHOD-DATA")
	}
	k.ErrorCode = errorcode.KDC_ERR_PREAUTH_REQUIRED
	k.EData = append(b, 0)
	if _, err := k.MethodData(); err == nil {
		t.Fatal("METHOD-DATA with trailing bytes was accepted")
	}
}

func TestKRBErrorNTStatus(t *testing.T) {
	k := KRBError{ErrorCode: errorcode.KDC_ERR_CLIENT_REVOKED, EData: mustDecodeHex(t, testdata.MSKILEKerbErrorDataAccountDisabled)}
	status, ok := k.NTStatus()
	if !ok || status != ntstatus.STATUS_ACCOUNT_DISABLED {
		t.Fatalf("NTStatus = %v, %v", status, ok)
	}
	if !bytes.Contains([]byte(k.Error()), []byte("STATUS_ACCOUNT_DISABLED")) {
		t.Fatalf("Error text does not include NTSTATUS: %s", k.Error())
	}
	k.EData = []byte{0x30, 0x00}
	if _, ok := k.NTStatus(); ok {
		t.Fatal("invalid KERB-ERROR-DATA returned an NTSTATUS")
	}
}

func TestWrappedKRBErrorExposesNTStatus(t *testing.T) {
	want := KRBError{ErrorCode: errorcode.KDC_ERR_CLIENT_REVOKED, EData: mustDecodeHex(t, testdata.MSKILEKerbErrorDataAccountDisabled)}
	wrapped := krberror.Errorf(want, krberror.KDCError, "KDC rejected request")
	var got KRBError
	if !errors.As(wrapped, &got) {
		t.Fatal("wrapped KRBError was not discoverable with errors.As")
	}
	status, ok := wrapped.NTStatus()
	if !ok || status != ntstatus.STATUS_ACCOUNT_DISABLED {
		t.Fatalf("wrapped NTStatus = %v, %v", status, ok)
	}
	if !bytes.Contains([]byte(wrapped.Error()), []byte("STATUS_ACCOUNT_DISABLED")) {
		t.Fatalf("wrapped error text does not include NTSTATUS: %s", wrapped.Error())
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnmarshalMarshalKRBError(t *testing.T) {
	t.Parallel()
	var a KRBError
	b, err := hex.DecodeString(testdata.MarshaledKRB5error)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")
	assert.Equal(t, "krb5data", a.EText, "EText not as expected")
	assert.Equal(t, []byte("krb5data"), a.EData, "EData not as expected")

	b2, err := a.Marshal()
	if err != nil {
		t.Errorf("error marshalling KRBError: %v", err)
	}
	assert.Equal(t, b, b2, "marshalled bytes not as expected")
}

func TestUnmarshalMarshalKRBError_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a KRBError
	b, err := hex.DecodeString(testdata.MarshaledKRB5errorOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO is not as expected")
	assert.Equal(t, msgtype.KRB_ERROR, a.MsgType, "Message type is not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.STime, "STime not as expected")
	assert.Equal(t, 123456, a.Susec, "Service microseconds not as expected")
	assert.Equal(t, errorcode.KRB_ERR_GENERIC, a.ErrorCode, "Error code not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "Ticket SName name string entries not as expected")

	b2, err := a.Marshal()
	if err != nil {
		t.Errorf("error marshalling KRBError: %v", err)
	}
	assert.Equal(t, b, b2, "marshalled bytes not as expected")
}
