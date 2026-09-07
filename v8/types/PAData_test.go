package types

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalPADataSequence(t *testing.T) {
	t.Parallel()
	var a PADataSequence
	b, err := hex.DecodeString(testdata.MarshaledKRB5padata_sequence)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 2, len(a), "Number of PAData items in the sequence not as expected")
	for i, pa := range a {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
}

func TestUnmarshalPADataSequence_empty(t *testing.T) {
	t.Parallel()
	var a PADataSequence
	b, err := hex.DecodeString(testdata.MarshaledKRB5padataSequenceEmpty)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 0, len(a), "Number of PAData items in the sequence not as expected")
}

func TestUnmarshalPAEncTSEnc(t *testing.T) {
	t.Parallel()
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc
	b, err := hex.DecodeString(testdata.MarshaledKRB5pa_enc_ts)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5pa_enc_ts", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5pa_enc_ts", err)
	}
	assert.Equal(t, tt, a.PATimestamp, "PA timestamp not as expected")
	assert.Equal(t, 123456, a.PAUSec, "PA microseconds not as expected")
}

func TestUnmarshalPAEncTSEnc_nousec(t *testing.T) {
	t.Parallel()
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	var a PAEncTSEnc
	b, err := hex.DecodeString(testdata.MarshaledKRB5pa_enc_tsNoUsec)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, tt, a.PATimestamp, "PA timestamp not as expected")
	assert.Equal(t, 0, a.PAUSec, "PA microseconds not as expected")
}

func TestUnmarshalETypeInfo(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5etype_info", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5etype_info", err)
	}
	assert.Equal(t, 3, len(a), "Number of EType info entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info entry not as expected")
	assert.Equal(t, []byte("Morton's #0"), a[0].Salt, "Salt of first etype info entry not as expected")
	assert.Equal(t, int32(1), a[1].EType, "Etype of second etype info entry not as expected")
	assert.Equal(t, 0, len(a[1].Salt), "Salt of second etype info entry not as expected")
	assert.Equal(t, int32(2), a[2].EType, "Etype of third etype info entry not as expected")
	assert.Equal(t, []byte("Morton's #2"), a[2].Salt, "Salt of third etype info entry not as expected")
}

func TestUnmarshalETypeInfo_only1(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_infoOnly1)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 1, len(a), "Number of EType info entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info entry not as expected")
	assert.Equal(t, []byte("Morton's #0"), a[0].Salt, "Salt of first etype info entry not as expected")
}

func TestUnmarshalETypeInfo_noinfo(t *testing.T) {
	t.Parallel()
	var a ETypeInfo
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_infoNoInfo)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5etype_infoNoInfo", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5etype_infoNoInfo", err)
	}
	assert.Equal(t, 0, len(a), "Number of EType info entries not as expected")
}

func TestUnmarshalETypeInfo2(t *testing.T) {
	t.Parallel()
	var a ETypeInfo2
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info2)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, 3, len(a), "Number of EType info2 entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info2 entry not as expected")
	assert.Equal(t, "Morton's #0", a[0].Salt, "Salt of first etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 0"), a[0].S2KParams, "String to key params of first etype info2 entry not as expected")
	assert.Equal(t, int32(1), a[1].EType, "Etype of second etype info2 entry not as expected")
	assert.Equal(t, 0, len(a[1].Salt), "Salt of second etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 1"), a[1].S2KParams, "String to key params of second etype info2 entry not as expected")
	assert.Equal(t, int32(2), a[2].EType, "Etype of third etype info2 entry not as expected")
	assert.Equal(t, "Morton's #2", a[2].Salt, "Salt of third etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 2"), a[2].S2KParams, "String to key params of third etype info2 entry not as expected")
}

func TestUnmarshalETypeInfo2_only1(t *testing.T) {
	t.Parallel()
	var a ETypeInfo2
	b, err := hex.DecodeString(testdata.MarshaledKRB5etype_info2Only1)
	if err != nil {
		t.Fatalf("Test vector read error of %s: %v\n", "MarshaledKRB5etype_info2Only1", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error of %s: %v\n", "MarshaledKRB5etype_info2Only1", err)
	}
	assert.Equal(t, 1, len(a), "Number of EType info2 entries not as expected")
	assert.Equal(t, int32(0), a[0].EType, "Etype of first etype info2 entry not as expected")
	assert.Equal(t, "Morton's #0", a[0].Salt, "Salt of first etype info2 entry not as expected")
	assert.Equal(t, []byte("s2k: 0"), a[0].S2KParams, "String to key params of first etype info2 entry not as expected")
}

func TestPADataAccessorsAndUnmarshalMethods(t *testing.T) {
	fixedTime := time.Date(2026, time.September, 7, 12, 34, 56, 123456000, time.FixedZone("offset", 3600))
	timestampBytes, err := GetPAEncTSEncAsnMarshalledAt(fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	var timestamp PAEncTSEnc
	if err := timestamp.Unmarshal(timestampBytes); err != nil {
		t.Fatal(err)
	}
	if !timestamp.PATimestamp.Equal(fixedTime.UTC().Truncate(time.Second)) || timestamp.PAUSec != 123456 {
		t.Fatalf("timestamp = %v/%d", timestamp.PATimestamp, timestamp.PAUSec)
	}
	if _, err := GetPAEncTSEncAsnMarshalled(); err != nil {
		t.Fatal(err)
	}

	info := ETypeInfo{{EType: 17, Salt: []byte("salt")}}
	infoBytes, _ := asn1.Marshal(info)
	pa := PAData{PADataType: patype.PA_ETYPE_INFO, PADataValue: infoBytes}
	decodedInfo, err := pa.GetETypeInfo()
	if err != nil || len(decodedInfo) != 1 || decodedInfo[0].EType != 17 {
		t.Fatalf("ETypeInfo = %+v, %v", decodedInfo, err)
	}
	if _, err := pa.GetETypeInfo2(); err == nil {
		t.Fatal("ETypeInfo accepted as ETypeInfo2")
	}
	var infoEntry ETypeInfoEntry
	entryBytes, _ := asn1.Marshal(info[0])
	if err := infoEntry.Unmarshal(entryBytes); err != nil {
		t.Fatal(err)
	}

	info2 := ETypeInfo2{{EType: 18, Salt: "salt2", S2KParams: []byte{0, 0, 0, 1}}}
	info2Bytes, _ := asn1.Marshal(info2)
	pa2 := PAData{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info2Bytes}
	decodedInfo2, err := pa2.GetETypeInfo2()
	if err != nil || len(decodedInfo2) != 1 || decodedInfo2[0].EType != 18 {
		t.Fatalf("ETypeInfo2 = %+v, %v", decodedInfo2, err)
	}
	if _, err := pa2.GetETypeInfo(); err == nil {
		t.Fatal("ETypeInfo2 accepted as ETypeInfo")
	}
	var info2Entry ETypeInfo2Entry
	entry2Bytes, _ := asn1.Marshal(info2[0])
	if err := info2Entry.Unmarshal(entry2Bytes); err != nil {
		t.Fatal(err)
	}

	request := PAReqEncPARep{ChksumType: 1, Chksum: []byte("checksum")}
	requestBytes, _ := asn1.Marshal(request)
	var decodedRequest PAReqEncPARep
	if err := decodedRequest.Unmarshal(requestBytes); err != nil {
		t.Fatal(err)
	}
	paBytes, _ := asn1.Marshal(pa)
	var decodedPA PAData
	if err := decodedPA.Unmarshal(paBytes); err != nil {
		t.Fatal(err)
	}
	sequence := PADataSequence{pa, pa2}
	if !sequence.Contains(patype.PA_ETYPE_INFO) || sequence.Contains(patype.PA_PK_AS_REQ) {
		t.Fatal("PADataSequence.Contains returned an unexpected result")
	}

	encrypted := PAEncTimestamp{EType: 17, Cipher: []byte("ciphertext")}
	encryptedBytes, _ := asn1.Marshal(encrypted)
	var decodedEncrypted PAEncTimestamp
	if err := decodedEncrypted.Unmarshal(encryptedBytes); err != nil {
		t.Fatal(err)
	}
	for name, unmarshal := range map[string]func([]byte) error{
		"PAData": decodedPA.Unmarshal, "PAReqEncPARep": decodedRequest.Unmarshal,
		"PAEncTimestamp": decodedEncrypted.Unmarshal, "PAEncTSEnc": timestamp.Unmarshal,
		"ETypeInfo": decodedInfo.Unmarshal, "ETypeInfoEntry": infoEntry.Unmarshal,
		"ETypeInfo2": decodedInfo2.Unmarshal, "ETypeInfo2Entry": info2Entry.Unmarshal,
	} {
		if err := unmarshal([]byte{0x30, 0x01}); err == nil {
			t.Fatalf("%s accepted malformed ASN.1", name)
		}
	}
}
