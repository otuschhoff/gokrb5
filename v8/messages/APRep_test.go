package messages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalAPRep(t *testing.T) {
	t.Parallel()
	var a APRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AP_REP, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Ticket encPart etype not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Ticket encPart KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Ticket encPart cipher not as expected")
}

func TestUnmarshalEncAPRepPart(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
	assert.Equal(t, int32(1), a.Subkey.KeyType, "Subkey type not as expected")
	assert.Equal(t, []byte("12345678"), a.Subkey.KeyValue, "Subkey value not as expected")
	assert.Equal(t, int64(17), a.SequenceNumber, "Sequence number not as expected")
}

func TestUnmarshalEncAPRepPart_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncAPRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, tt, a.CTime, "CTime not as expected")
	assert.Equal(t, 123456, a.Cusec, "Client microseconds not as expected")
}

func TestAPRepRoundTripAndVerify(t *testing.T) {
	t.Parallel()
	key := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}
	auth := types.Authenticator{
		CTime: time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
		Cusec: 123456,
	}
	subkey := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdef"),
	}

	rep, err := NewAPRepFromAuthenticator(auth, key, subkey, 17)
	require.NoError(t, err)
	wire, err := rep.Marshal()
	require.NoError(t, err)

	var decoded APRep
	require.NoError(t, decoded.Unmarshal(wire))
	require.NoError(t, decoded.Verify(auth, key))
	assert.Equal(t, subkey, decoded.DecryptedEncPart.Subkey)
	assert.Equal(t, int64(17), decoded.DecryptedEncPart.SequenceNumber)
}

func TestAPRepVerifyRejectsTimestampMismatch(t *testing.T) {
	t.Parallel()
	key := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdef"),
	}
	auth := types.Authenticator{
		CTime: time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
		Cusec: 123456,
	}
	rep, err := NewAPRepFromAuthenticator(auth, key, types.EncryptionKey{}, 0)
	require.NoError(t, err)

	auth.Cusec++
	require.Error(t, rep.Verify(auth, key))
}

func TestAPRepVerifyRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	key := types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdef"),
	}
	auth := types.Authenticator{
		CTime: time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
		Cusec: 123456,
	}
	rep, err := NewAPRepFromAuthenticator(auth, key, types.EncryptionKey{}, 0)
	require.NoError(t, err)
	rep.EncPart.Cipher[len(rep.EncPart.Cipher)-1] ^= 0xff

	require.Error(t, rep.Verify(auth, key))
}

func TestAPRepVerifyDCE(t *testing.T) {
	t.Parallel()
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	now := time.Now().UTC()
	rep, err := NewAPRep(EncAPRepPart{
		CTime: now, Cusec: int((now.UnixNano() / int64(time.Microsecond)) - now.Unix()*1e6), SequenceNumber: 42,
	}, key)
	require.NoError(t, err)
	require.NoError(t, rep.VerifyDCE(key, 42, true, time.Minute))
	require.Error(t, rep.VerifyDCE(key, 43, true, time.Minute))
}
