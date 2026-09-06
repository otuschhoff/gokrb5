package types

import (
	"encoding/hex"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

func TestKDCProxyMessageFixture(t *testing.T) {
	b, err := hex.DecodeString(testdata.MarshaledKRB5kkdcp_message)
	if err != nil {
		t.Fatal(err)
	}
	var message KDCProxyMessage
	if err := message.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if len(message.KerbMessage) == 0 || message.TargetDomain != "krb5data" {
		t.Fatalf("decoded message has payload length %d and target domain %q", len(message.KerbMessage), message.TargetDomain)
	}
	encoded, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encoded) != hex.EncodeToString(b) {
		t.Fatal("KDC-PROXY-MESSAGE did not round trip the fixture")
	}

	framed, err := NewKDCProxyMessage(message.KerbMessage, message.TargetDomain, message.DCLocatorHint)
	if err != nil {
		t.Fatal(err)
	}
	kerberosMessage, err := framed.KerberosMessage()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(kerberosMessage) != hex.EncodeToString(message.KerbMessage) {
		t.Fatal("standards-compliant framing changed the Kerberos message")
	}
}

func TestKDCProxyMessageRejectsInvalidLength(t *testing.T) {
	message, err := NewKDCProxyMessage([]byte("request"), "EXAMPLE.ORG", 0)
	if err != nil {
		t.Fatal(err)
	}
	message.KerbMessage[3]++
	if _, err := message.KerberosMessage(); err == nil {
		t.Fatal("accepted a Kerberos message with an invalid length prefix")
	}
}

func TestKDCProxyMessageRejectsTrailingData(t *testing.T) {
	message, err := NewKDCProxyMessage([]byte("request"), "EXAMPLE.ORG", 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, 0)
	if err := new(KDCProxyMessage).Unmarshal(encoded); err == nil {
		t.Fatal("accepted trailing data after KDC-PROXY-MESSAGE")
	}
}

func FuzzKDCProxyMessage(f *testing.F) {
	fixture, err := hex.DecodeString(testdata.MarshaledKRB5kkdcp_message)
	if err != nil {
		f.Fatal(err)
	}
	framed, err := NewKDCProxyMessage([]byte{0x6a, 0x03, 0x02, 0x01, 0x05}, "EXAMPLE.ORG", 0)
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := framed.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(fixture)
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, b []byte) {
		var message KDCProxyMessage
		if message.Unmarshal(b) == nil {
			_, _ = message.KerberosMessage()
		}
	})
}
