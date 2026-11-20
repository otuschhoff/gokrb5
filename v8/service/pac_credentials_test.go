package service

import (
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/stretchr/testify/assert"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestAttachPACCredentialsPreservesDecodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry types.AuthorizationDataEntry
		cause error
	}{
		{
			name:  "incomplete PAC",
			entry: types.AuthorizationDataEntry{ADType: adtype.ADWin2KPAC, ADData: []byte{0}},
			cause: pac.ErrPACMalformed,
		},
		{
			name:  "incomplete authorization data",
			entry: types.AuthorizationDataEntry{ADType: adtype.ADIfRelevant, ADData: []byte{0x30}},
			cause: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var ticket messages.Ticket
			ticket.DecryptedEncPart.AuthorizationData = types.AuthorizationData{tt.entry}
			c := credentials.New("pac-fixture", testdata.TEST_REALM)
			err := attachPACCredentials(c, &ticket, NewSettings(keytab.New()))
			assert.ErrorContains(t, err, "process service ticket PAC:")
			if tt.cause != nil {
				assert.ErrorIs(t, err, tt.cause)
			} else {
				assert.ErrorAs(t, err, new(asn1.SyntaxError))
			}
			assert.Empty(t, c.GetADCredentials().UserSID)
		})
	}
}

func testSID(parts ...uint32) mstypes.RPCSID {
	return mstypes.RPCSID{
		Revision:            1,
		SubAuthorityCount:   uint8(len(parts)), // #nosec G115 -- RPC SID subauthority fixtures contain at most three entries.
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5}, SubAuthority: parts,
	}
}

func TestADCredentialsFromPAC(t *testing.T) {
	domainSID := testSID(21, 1, 2)
	extraSID := testSID(32, 544)
	resourceSID := testSID(21, 9, 8)
	var validation pac.KerbValidationInfo
	validation.LogOnTime = mstypes.GetFileTime(time.Unix(10, 0))
	validation.LogOffTime = mstypes.GetFileTime(time.Unix(20, 0))
	validation.PasswordLastSet = mstypes.GetFileTime(time.Unix(30, 0))
	validation.UserID = 500
	validation.PrimaryGroupID = 513
	validation.GroupIDs = []mstypes.GroupMembership{{RelativeID: 512, Attributes: 7}}
	validation.ExtraSIDs = []mstypes.KerbSidAndAttributes{{SID: extraSID, Attributes: 8}}
	validation.ResourceGroupDomainSID = resourceSID
	validation.ResourceGroupIDs = []mstypes.GroupMembership{{RelativeID: 1001, Attributes: 9}}
	validation.LogonDomainID = domainSID
	validation.UserAccountControl = 0x200
	validation.EffectiveName.Value = testUsername
	validation.FullName.Value = "Alice Example"
	validation.LogonServer.Value = "DC01"
	validation.LogonDomainName.Value = testDomain
	authTime := time.Unix(40, 0).UTC()
	requestorSID := testSID(21, 1, 2, 500)
	var upnInfo pac.UPNDNSInfo
	upnInfo.UPN = "alice@example.org"
	upnInfo.DNSDomain = "example.org"
	upnInfo.SAMAccountName = "ALICE"
	var parsed pac.PACType
	parsed.KerbValidationInfo = &validation
	parsed.UPNDNSInfo = &upnInfo
	parsed.AttributesInfo = &pac.AttributesInfo{FlagsLength: 0, Flags: 3}
	parsed.Requestor = &pac.Requestor{SID: requestorSID}

	got := adCredentialsFromPAC(parsed, authTime)
	checkPACIdentity(t, got)
	checkPACMetadata(t, got, authTime)
	if len(got.GroupMembershipSIDs) != 3 ||
		len(got.ExtraSIDs) != 1 || got.ExtraSIDs[0].SID != "S-1-5-32-544" ||
		len(got.ResourceGroupSIDs) != 1 || got.ResourceGroupSIDs[0].SID != "S-1-5-21-9-8-1001" {
		t.Fatalf("mapped groups = %+v", got)
	}
}

func checkPACIdentity(t *testing.T, got credentials.ADCredentials) {
	t.Helper()
	if got.EffectiveName != testUsername || got.FullName != "Alice Example" ||
		got.UserID != 500 || got.PrimaryGroupID != 513 ||
		got.LogonServer != "DC01" || got.LogonDomainName != testDomain ||
		got.LogonDomainID != "S-1-5-21-1-2" || got.UserSID != "S-1-5-21-1-2-500" {
		t.Fatalf("mapped credentials = %+v", got)
	}
}

func checkPACMetadata(t *testing.T, got credentials.ADCredentials, authTime time.Time) {
	t.Helper()
	if got.UPN != "alice@example.org" || got.DNSDomain != "example.org" || got.SAMAccountName != "ALICE" ||
		got.PACAttributes != 3 || got.PACRequestorSID != "S-1-5-21-1-2-500" ||
		!got.TicketAuthTime.Equal(authTime) {
		t.Fatalf("mapped credentials = %+v", got)
	}
}

func TestDeviceCredentialsFromPAC(t *testing.T) {
	domainSID := testSID(21, 1, 2)
	extraSID := testSID(32, 545)
	foreignSID := testSID(21, 7, 8)
	device := pac.DeviceInfo{
		UserID: 100, PrimaryGroupID: 515, AccountDomainID: domainSID,
		AccountGroupCount: 0,
		AccountGroupIDs:   []mstypes.GroupMembership{{RelativeID: 516, Attributes: 1}},
		SIDCount:          0,
		ExtraSIDs:         []mstypes.KerbSidAndAttributes{{SID: extraSID, Attributes: 2}},
		DomainGroupCount:  0,
		DomainGroup: []mstypes.DomainGroupMembership{{
			DomainID:   foreignSID,
			GroupCount: 0,
			GroupIDs:   []mstypes.GroupMembership{{RelativeID: 517, Attributes: 3}},
		}},
	}
	mapped := deviceCredentialsFromPAC(device)
	checkPACDevice(t, mapped)
	var validation pac.KerbValidationInfo
	validation.LogonDomainID = domainSID
	var parsed pac.PACType
	parsed.KerbValidationInfo = &validation
	parsed.DeviceInfo = &device
	if got := adCredentialsFromPAC(parsed, time.Time{}).DeviceInfo; got == nil || got.UserSID != mapped.UserSID {
		t.Fatalf("nested device credentials = %+v", got)
	}
}

func checkPACDevice(t *testing.T, got *credentials.ADDeviceInfo) {
	t.Helper()
	if got.UserSID != "S-1-5-21-1-2-100" || got.PrimaryGroupSID != "S-1-5-21-1-2-515" ||
		len(got.GroupSIDs) != 1 || got.GroupSIDs[0].SID != "S-1-5-21-1-2-516" ||
		len(got.ExtraSIDs) != 1 || got.ExtraSIDs[0].SID != "S-1-5-32-545" ||
		len(got.DomainGroupSIDs) != 1 || got.DomainGroupSIDs[0].SID != "S-1-5-21-7-8-517" {
		t.Fatalf("mapped device credentials = %+v", got)
	}
}
