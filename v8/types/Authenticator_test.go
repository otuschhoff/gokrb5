package types

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

const authenticatorTestRealm = "EXAMPLE.ORG"

func TestAuthenticatorSequenceReadError(t *testing.T) {
	// rand.Reader is process-wide; keep this test sequential and restore it before parallel tests run.
	cause := errors.New("test random reader failure")
	reader := rand.Reader
	t.Cleanup(func() { rand.Reader = reader })
	rand.Reader = iotest.ErrReader(cause)

	var zero Authenticator
	auth, createErr := NewAuthenticator(authenticatorTestRealm, NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"))
	want := zero
	want.SeqNumber = 23
	want.SubKey = EncryptionKey{KeyType: 17, KeyValue: []byte{1}}
	existing := want
	existing.SubKey.KeyValue = bytes.Clone(want.SubKey.KeyValue)
	updateErr := existing.GenerateSeqNumberAndSubKey(18, 32)
	if !reflect.DeepEqual(auth, zero) || !reflect.DeepEqual(existing, want) {
		t.Fatal("sequence read failure published authenticator state")
	}
	for _, err := range []error{createErr, updateErr} {
		if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "generate authenticator sequence number:") {
			t.Errorf("error = %v, want sequence generation context and original read cause", err)
		}
	}
}

func TestAuthenticatorMarshalErrorContext(t *testing.T) {
	t.Parallel()

	var auth Authenticator
	auth.CTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	b, err := auth.Marshal()
	if b != nil {
		t.Fatal("marshal failure returned bytes")
	}
	checkASN1ErrorContext[asn1.StructuralError](t, err, "encode authenticator:")
}

func unmarshalAuthenticatorTest(t *testing.T, v string) Authenticator {
	var a Authenticator
	// t.Logf("Starting unmarshal tests of %s", v)
	b, err := hex.DecodeString(v)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	return a
}

func TestUnmarshalAuthenticator(t *testing.T) {
	t.Parallel()
	a := unmarshalAuthenticatorTest(t, testdata.MarshaledKRB5authenticator)
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.AVNO, "Authenticator version number not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t,
		len(testdata.TEST_PRINCIPALNAME_NAMESTRING),
		len(a.CName.NameString),
		"CName does not have the expected number of NameStrings",
	)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, int32(1), a.Cksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.Cksum.Checksum, "Checsum not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.CTime, "Client time not as expected")
	assert.Equal(t, int32(1), a.SubKey.KeyType, "Subkey type not as expected")
	assert.Equal(t, []byte("12345678"), a.SubKey.KeyValue, "Subkey value not as expected")
	assert.Equal(t, 2, len(a.AuthorizationData), "Number of Authorization data items not as expected")
	for i, entry := range a.AuthorizationData {
		assert.Equal(t, adtype.ADIfRelevant, entry.ADType, fmt.Sprintf("Authorization type of entry %d not as expected", i+1))
		assert.Equal(t,
			[]byte(testdata.TEST_AUTHORIZATION_DATA_VALUE),
			entry.ADData,
			fmt.Sprintf("Authorization data of entry %d not as expected", i+1),
		)
	}
}

func TestUnmarshalAuthenticator_optionalsempty(t *testing.T) {
	t.Parallel()
	a := unmarshalAuthenticatorTest(t, testdata.MarshaledKRB5authenticatorOptionalsEmpty)
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.AVNO, "Authenticator version number not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t,
		len(testdata.TEST_PRINCIPALNAME_NAMESTRING),
		len(a.CName.NameString),
		"CName does not have the expected number of NameStrings",
	)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.CTime, "Client time not as expected")
}

func TestUnmarshalAuthenticator_optionalsNULL(t *testing.T) {
	t.Parallel()
	a := unmarshalAuthenticatorTest(t, testdata.MarshaledKRB5authenticatorOptionalsNULL)
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.AVNO, "Authenticator version number not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t,
		len(testdata.TEST_PRINCIPALNAME_NAMESTRING),
		len(a.CName.NameString),
		"CName does not have the expected number of NameStrings",
	)
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, tt, a.CTime, "Client time not as expected")
}

func TestMarshalAuthenticator(t *testing.T) {
	t.Parallel()
	var a Authenticator
	b, err := hex.DecodeString(testdata.MarshaledKRB5authenticator)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of Authenticator not as expected")
}

func TestNewAuthenticatorAndGenerateSubKey(t *testing.T) {
	principal := NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	authenticator, err := NewAuthenticator(authenticatorTestRealm, principal)
	if err != nil {
		t.Fatal(err)
	}
	checkNewAuthenticator(t, authenticator, principal)
	if err := authenticator.GenerateSeqNumberAndSubKey(17, 16); err != nil {
		t.Fatal(err)
	}

	if authenticator.SubKey.KeyType != 17 || len(authenticator.SubKey.KeyValue) != 16 || authenticator.SeqNumber < 0 {
		t.Fatalf("generated sequence/subkey = %d/%+v", authenticator.SeqNumber, authenticator.SubKey)
	}
}

func checkNewAuthenticator(t *testing.T, authenticator Authenticator, principal PrincipalName) {
	t.Helper()
	if authenticator.AVNO != iana.PVNO ||
		authenticator.CRealm != authenticatorTestRealm ||
		!authenticator.CName.Equal(principal) ||
		authenticator.CTime.IsZero() ||
		authenticator.Cusec < 0 ||
		authenticator.Cusec >= 1000000 {
		t.Fatalf("authenticator = %+v", authenticator)
	}
}
