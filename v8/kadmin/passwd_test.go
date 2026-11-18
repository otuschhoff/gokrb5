package kadmin

import (
	"errors"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestChangePasswdMsgAPReqError(t *testing.T) {
	t.Parallel()

	const passwordFixture = "fixture-text"
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	var ticket messages.Ticket
	ticket.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "kadmin/changepw")
	request, subkey, err := ChangePasswdMsg(
		cname,
		"EXAMPLE.ORG",
		passwordFixture,
		ticket,
		types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte{1}},
	)
	if err == nil {
		t.Fatal("accepted an invalid session key")
	}
	if strings.Contains(err.Error(), passwordFixture) {
		t.Fatal("error exposed the password fixture")
	}
	cause, ok := errors.AsType[krberror.Krberror](err)
	if !ok || !strings.Contains(cause.Error(), "incorrect keysize") ||
		!strings.HasPrefix(err.Error(), "build kpasswd AP-REQ:") {
		t.Fatalf("want AP-REQ construction context with Kerberos cause, got %v", err)
	}
	if request.APREQ.MsgType != 0 || len(subkey.KeyValue) != 32 {
		t.Fatal("unexpected request or subkey result after AP-REQ failure")
	}
}

func TestChangePasswdMsgRequiresTicketServicePrincipal(t *testing.T) {
	t.Parallel()

	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	var ticket messages.Ticket
	_, _, err := ChangePasswdMsg(
		cname,
		"EXAMPLE.ORG",
		"fixture-text",
		ticket,
		types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)},
	)
	if err == nil || !strings.Contains(err.Error(), "ticket service principal is missing") {
		t.Fatalf("want a missing ticket service principal error, got %v", err)
	}
}
