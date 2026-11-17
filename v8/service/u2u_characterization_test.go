package service

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestVerifyAPREQUserToUserRequiresAcceptorKeySupport(t *testing.T) {
	const realm = "EXAMPLE.COM"
	sender := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "sender")
	receiver := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "receiver")
	tgtKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{1}, 32)}
	now := time.Now().UTC()
	ticket, sessionKey, err := messages.NewTicketWithKey(sender, realm, receiver, realm,
		types.NewKrbFlags(), tgtKey, 1, now, now, now.Add(time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := types.NewAuthenticator(realm, sender)
	if err != nil {
		t.Fatal(err)
	}
	request, err := messages.NewAPReq(ticket, sessionKey, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	types.SetFlag(&request.APOptions, flags.APOptionUseSessionKey)
	settings := NewSettings(keytab.New(), DecodePAC(false), ServicePrincipals(receiver.PrincipalNameString()+"@"+realm))
	accepted, _, err := VerifyAPREQ(&request, settings)
	if accepted || err == nil || !strings.Contains(err.Error(), "keytab") {
		t.Fatalf("user-to-user acceptance = %v, %v; want unsupported acceptor key lookup", accepted, err)
	}
}
