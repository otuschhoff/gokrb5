package types

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func mustMarshalAuthorizationData(t *testing.T, a AuthorizationData) []byte {
	t.Helper()
	b, err := asn1.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAuthorizationDataEntriesOfType(t *testing.T) {
	want := AuthorizationDataEntry{ADType: adtype.ADWin2KPAC, ADData: []byte("pac")}
	nested := AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: mustMarshalAuthorizationData(t, AuthorizationData{want})}}
	entries, err := nested.EntriesOfType(adtype.ADWin2KPAC)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !reflect.DeepEqual(entries[0], want) {
		t.Fatalf("entries = %#v, want %#v", entries, []AuthorizationDataEntry{want})
	}
}

func TestAuthorizationDataWalkDepthLimit(t *testing.T) {
	a := AuthorizationData{{ADType: adtype.ADWin2KPAC}}
	for i := 0; i <= maxAuthorizationDataDepth; i++ {
		a = AuthorizationData{{ADType: adtype.ADIfRelevant, ADData: mustMarshalAuthorizationData(t, a)}}
	}
	if err := a.Walk(func(int, AuthorizationDataEntry) error { return nil }); !errors.Is(err, ErrAuthorizationDataDepth) {
		t.Fatalf("Walk error = %v, want ErrAuthorizationDataDepth", err)
	}
}

func TestUnmarshalAuthorizationData(t *testing.T) {
	t.Parallel()
	var a AuthorizationData
	b, err := hex.DecodeString(testdata.MarshaledKRB5authorization_data)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 2, len(a), "Number of authorization data entries not as expected")
	for i, entry := range a {
		assert.Equal(t, adtype.ADIfRelevant, entry.ADType, fmt.Sprintf("Authorization data type of entry %d not as expected", i+1))
		assert.Equal(t, []byte("foobar"), entry.ADData, fmt.Sprintf("Authorization data of entry %d not as expected", i+1))
	}
}

func TestUnmarshalAuthorizationData_kdcissued(t *testing.T) {
	t.Parallel()
	var a ADKDCIssued
	b, err := hex.DecodeString(testdata.MarshaledKRB5ad_kdcissued)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, int32(1), a.ADChecksum.CksumType, "Checksum type not as expected")
	assert.Equal(t, []byte("1234"), a.ADChecksum.Checksum, "Checksum not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.IRealm, "Issuing realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Isname.NameType, "Issuing name type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Isname.NameString, "Issuing name string entries not as expected")
	assert.Equal(t, 2, len(a.Elements), "Number of authorization data elements not as expected")
	for i, ele := range a.Elements {
		assert.Equal(t, adtype.ADIfRelevant, ele.ADType, fmt.Sprintf("Authorization data type of element %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData, fmt.Sprintf("Authorization data of element %d not as expected", i+1))
	}
}
