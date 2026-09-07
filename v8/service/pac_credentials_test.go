package service

import (
	"testing"
	"time"

	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/otuschhoff/gokrb5/v8/pac"
)

func testSID(parts ...uint32) mstypes.RPCSID {
	return mstypes.RPCSID{
		Revision: 1, SubAuthorityCount: uint8(len(parts)),
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5}, SubAuthority: parts,
	}
}

func TestADCredentialsFromPAC(t *testing.T) {
	domainSID := testSID(21, 1, 2)
	extraSID := testSID(32, 544)
	resourceSID := testSID(21, 9, 8)
	validation := &pac.KerbValidationInfo{
		LogOnTime: mstypes.GetFileTime(time.Unix(10, 0)), LogOffTime: mstypes.GetFileTime(time.Unix(20, 0)),
		PasswordLastSet: mstypes.GetFileTime(time.Unix(30, 0)), UserID: 500, PrimaryGroupID: 513,
		GroupIDs:               []mstypes.GroupMembership{{RelativeID: 512, Attributes: 7}},
		ExtraSIDs:              []mstypes.KerbSidAndAttributes{{SID: extraSID, Attributes: 8}},
		ResourceGroupDomainSID: resourceSID,
		ResourceGroupIDs:       []mstypes.GroupMembership{{RelativeID: 1001, Attributes: 9}},
		LogonDomainID:          domainSID, UserAccountControl: 0x200,
	}
	validation.EffectiveName.Value = "alice"
	validation.FullName.Value = "Alice Example"
	validation.LogonServer.Value = "DC01"
	validation.LogonDomainName.Value = "EXAMPLE"
	authTime := time.Unix(40, 0).UTC()
	requestorSID := testSID(21, 1, 2, 500)
	parsed := pac.PACType{
		KerbValidationInfo: validation,
		UPNDNSInfo:         &pac.UPNDNSInfo{UPN: "alice@example.org", DNSDomain: "example.org", SAMAccountName: "ALICE"},
		AttributesInfo:     &pac.AttributesInfo{Flags: 3}, Requestor: &pac.Requestor{SID: requestorSID},
	}
	credentials := adCredentialsFromPAC(parsed, authTime)
	if credentials.EffectiveName != "alice" || credentials.FullName != "Alice Example" || credentials.UserID != 500 ||
		credentials.PrimaryGroupID != 513 || credentials.LogonServer != "DC01" || credentials.LogonDomainName != "EXAMPLE" ||
		credentials.LogonDomainID != "S-1-5-21-1-2" || credentials.UserSID != "S-1-5-21-1-2-500" ||
		credentials.UPN != "alice@example.org" || credentials.DNSDomain != "example.org" || credentials.SAMAccountName != "ALICE" ||
		credentials.PACAttributes != 3 || credentials.PACRequestorSID != "S-1-5-21-1-2-500" || !credentials.TicketAuthTime.Equal(authTime) {
		t.Fatalf("mapped credentials = %+v", credentials)
	}
	if len(credentials.GroupMembershipSIDs) != 3 || len(credentials.ExtraSIDs) != 1 || credentials.ExtraSIDs[0].SID != "S-1-5-32-544" ||
		len(credentials.ResourceGroupSIDs) != 1 || credentials.ResourceGroupSIDs[0].SID != "S-1-5-21-9-8-1001" {
		t.Fatalf("mapped groups = %+v", credentials)
	}
}

func TestDeviceCredentialsFromPAC(t *testing.T) {
	domainSID := testSID(21, 1, 2)
	extraSID := testSID(32, 545)
	foreignSID := testSID(21, 7, 8)
	device := pac.DeviceInfo{
		UserID: 100, PrimaryGroupID: 515, AccountDomainID: domainSID,
		AccountGroupIDs: []mstypes.GroupMembership{{RelativeID: 516, Attributes: 1}},
		ExtraSIDs:       []mstypes.KerbSidAndAttributes{{SID: extraSID, Attributes: 2}},
		DomainGroup:     []mstypes.DomainGroupMembership{{DomainID: foreignSID, GroupIDs: []mstypes.GroupMembership{{RelativeID: 517, Attributes: 3}}}},
	}
	credentials := deviceCredentialsFromPAC(device)
	if credentials.UserSID != "S-1-5-21-1-2-100" || credentials.PrimaryGroupSID != "S-1-5-21-1-2-515" ||
		len(credentials.GroupSIDs) != 1 || credentials.GroupSIDs[0].SID != "S-1-5-21-1-2-516" ||
		len(credentials.ExtraSIDs) != 1 || credentials.ExtraSIDs[0].SID != "S-1-5-32-545" ||
		len(credentials.DomainGroupSIDs) != 1 || credentials.DomainGroupSIDs[0].SID != "S-1-5-21-7-8-517" {
		t.Fatalf("mapped device credentials = %+v", credentials)
	}
	parsed := pac.PACType{KerbValidationInfo: &pac.KerbValidationInfo{LogonDomainID: domainSID}, DeviceInfo: &device}
	if got := adCredentialsFromPAC(parsed, time.Time{}).DeviceInfo; got == nil || got.UserSID != credentials.UserSID {
		t.Fatalf("nested device credentials = %+v", got)
	}
}
