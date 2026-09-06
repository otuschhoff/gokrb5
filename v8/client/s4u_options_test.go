package client

import (
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestApplyS4UOptions(t *testing.T) {
	certificate := []byte{1, 2, 3}
	options := applyS4UOptions([]S4UOption{
		nil,
		S4UWithForwardable(false),
		S4UWithResourceBasedDelegation(),
		S4UWithCertificate(certificate),
	})
	certificate[0] = 9

	if options.forwardable == nil || *options.forwardable {
		t.Fatal("forwardable option was not set to false")
	}
	if !options.resourceBased {
		t.Fatal("resource-based delegation option was not set")
	}
	if len(options.subjectCertificate) != 3 || options.subjectCertificate[0] != 1 {
		t.Fatalf("certificate was not defensively copied: %v", options.subjectCertificate)
	}
	if empty := applyS4UOptions(nil); empty.forwardable != nil || empty.resourceBased || empty.subjectCertificate != nil {
		t.Fatalf("empty options = %+v", empty)
	}
}

func TestS4UIdentityForTicket(t *testing.T) {
	client := NewWithPassword("service", "EXAMPLE.COM", "unused", config.New())
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	ticket := s4uTestTicket("EXAMPLE.COM", "HTTP/service.example.com")
	now := time.Now().UTC()
	client.addS4UCacheEntry(user, "EXAMPLE.COM", "HTTP/service.example.com", messages.TGSRep{
		KDCRepFields: messages.KDCRepFields{
			Ticket: ticket,
			DecryptedEncPart: messages.EncKDCRepPart{
				StartTime: now.Add(-time.Minute),
				EndTime:   now.Add(time.Hour),
			},
		},
	})

	gotUser, gotRealm, ok := client.s4uIdentityForTicket(ticket)
	if !ok || !gotUser.Equal(user) || gotRealm != "EXAMPLE.COM" {
		t.Fatalf("identity = %v@%s, %v", gotUser, gotRealm, ok)
	}
	unknown := ticket
	unknown.EncPart.Cipher = []byte("different")
	if _, _, ok := client.s4uIdentityForTicket(unknown); ok {
		t.Fatal("unknown evidence ticket returned an identity")
	}
}

func TestTicketsEqualFields(t *testing.T) {
	base := s4uTestTicket("EXAMPLE.COM", "HTTP/service.example.com")
	base.EncPart.KVNO = 7
	if !ticketsEqual(base, base) {
		t.Fatal("identical tickets were not equal")
	}
	caseRealm := base
	caseRealm.Realm = "example.com"
	if !ticketsEqual(base, caseRealm) {
		t.Fatal("realm comparison was not case-insensitive")
	}

	tests := []struct {
		name   string
		mutate func(*messages.Ticket)
	}{
		{name: "version", mutate: func(ticket *messages.Ticket) { ticket.TktVNO++ }},
		{name: "realm", mutate: func(ticket *messages.Ticket) { ticket.Realm = "OTHER.COM" }},
		{name: "service", mutate: func(ticket *messages.Ticket) {
			ticket.SName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/other.example.com")
		}},
		{name: "encryption type", mutate: func(ticket *messages.Ticket) { ticket.EncPart.EType++ }},
		{name: "kvno", mutate: func(ticket *messages.Ticket) { ticket.EncPart.KVNO++ }},
		{name: "cipher", mutate: func(ticket *messages.Ticket) { ticket.EncPart.Cipher = []byte("different") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			other := base
			test.mutate(&other)
			if ticketsEqual(base, other) {
				t.Fatal("tickets with different fields were equal")
			}
		})
	}
}

func TestS4UForwardableCacheBoundary(t *testing.T) {
	client := NewWithPassword("service", "EXAMPLE.COM", "unused", config.New())
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	spn := "HTTP/service.example.com"
	now := time.Now().UTC()
	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Forwardable)
	client.addS4UCacheEntry(user, "EXAMPLE.COM", spn, messages.TGSRep{KDCRepFields: messages.KDCRepFields{
		Ticket: s4uTestTicket("EXAMPLE.COM", spn),
		DecryptedEncPart: messages.EncKDCRepPart{
			StartTime: now.Add(time.Minute),
			EndTime:   now.Add(time.Hour),
			Flags:     ticketFlags,
		},
	}})
	if _, ok := client.GetCachedServiceTicketForUserInfo(user, "EXAMPLE.COM", spn); ok {
		t.Fatal("not-yet-valid S4U ticket was returned")
	}
}
