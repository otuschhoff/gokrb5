package messages

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalAPReq(t *testing.T) {
	t.Parallel()
	var a APReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_req)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AP_REQ, a.MsgType, "MsgType is not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.APOptions.Bytes), "AP Options not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO, "Ticket VNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType, "Ticket SName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "Ticket SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName name string entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Ticket encPart etype not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO, "Ticket encPart KVNO not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.Ticket.EncPart.Cipher, "Ticket encPart cipher not as expected")
}

func TestMarshalAPReq(t *testing.T) {
	t.Parallel()
	var a APReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5ap_req)
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

func TestAPReqDecryptAndVerify(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	address := types.HostAddress{AddrType: addrtype.IPv4, Address: []byte{127, 0, 0, 1}}
	kt := keytab.New()
	if err := kt.AddEntry("HTTP/server.example.org", "EXAMPLE.ORG", "password", now, 2, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}

	newRequest := func(t *testing.T, authName types.PrincipalName, authTime time.Time) APReq {
		t.Helper()
		ticket, sessionKey, err := NewTicket(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), kt,
			etypeID.AES256_CTS_HMAC_SHA1_96, 2, now, now, now.Add(time.Hour), now.Add(2*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		authenticator, err := types.NewAuthenticator("EXAMPLE.ORG", authName)
		if err != nil {
			t.Fatal(err)
		}
		authenticator.CTime = authTime
		request, err := NewAPReq(ticket, sessionKey, authenticator)
		if err != nil {
			t.Fatal(err)
		}
		return request
	}

	request := newRequest(t, cname, now)
	if ok, err := request.Verify(kt, time.Minute, address, nil); !ok || err != nil {
		t.Fatalf("AP-REQ verification = %v, %v", ok, err)
	}
	if !request.Authenticator.CName.Equal(cname) {
		t.Fatalf("decrypted authenticator = %+v", request.Authenticator)
	}

	wrongKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0xff}, 32)}
	request = newRequest(t, cname, now)
	if err := request.DecryptAuthenticatorWithKeyUsage(wrongKey, 11); err == nil {
		t.Fatal("wrong authenticator key was accepted")
	}

	request = newRequest(t, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "mallory"), now)
	if ok, err := request.Verify(kt, time.Minute, address, nil); ok || err == nil {
		t.Fatalf("mismatched principal verification = %v, %v", ok, err)
	}
	request = newRequest(t, cname, now.Add(-time.Hour))
	if ok, err := request.Verify(kt, time.Minute, address, nil); ok || err == nil {
		t.Fatalf("skewed authenticator verification = %v, %v", ok, err)
	}
}
