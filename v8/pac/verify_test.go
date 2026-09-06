package pac

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestPACVerifyOptions(t *testing.T) {
	serverKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x51}, 16)}
	kdcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x52}, 32)}
	ticketData := []byte("ticket with zero PAC placeholder")
	data, err := minimalPAC().Sign(serverKey, kdcKey, SignOptions{IncludeFullChecksum: true, TicketData: ticketData})
	if err != nil {
		t.Fatal(err)
	}
	authTime := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	parsed := parsedPACForVerification(t, data, authTime)
	options := VerifyOptions{
		KDCKey: &kdcKey, TicketData: ticketData, ExpectedClientName: "TESTUSER",
		ExpectedAuthTime: &authTime, RequireFullChecksum: true, RequireTicketChecksum: true,
	}
	if err := parsed.Verify(serverKey, options); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PACType, *VerifyOptions)
		want   string
	}{
		{"client name", func(p *PACType, o *VerifyOptions) { o.ExpectedClientName = "other" }, "client name"},
		{"client time", func(p *PACType, o *VerifyOptions) { later := authTime.Add(time.Second); o.ExpectedAuthTime = &later }, "authentication time"},
		{"requestor SID", func(p *PACType, o *VerifyOptions) { p.Requestor.SID.SubAuthority[3]++ }, "requestor SID"},
		{"UPN SID", func(p *PACType, o *VerifyOptions) { p.UPNDNSInfo.ObjectSID.SubAuthority[3]++ }, "UPN/DNS SID"},
		{"SAM name", func(p *PACType, o *VerifyOptions) { p.UPNDNSInfo.SAMAccountName = "other" }, "SAM account name"},
		{"KDC checksum", func(p *PACType, o *VerifyOptions) { p.KDCChecksum.Signature[0] ^= 0xff }, "KDC checksum"},
		{"full checksum", func(p *PACType, o *VerifyOptions) { p.FullChecksum.Signature[0] ^= 0xff }, "full KDC checksum"},
		{"ticket checksum", func(p *PACType, o *VerifyOptions) { o.TicketData = []byte("wrong") }, "ticket checksum"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := parsedPACForVerification(t, data, authTime)
			candidateOptions := options
			test.mutate(&candidate, &candidateOptions)
			if err := candidate.Verify(serverKey, candidateOptions); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Verify error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func parsedPACForVerification(t *testing.T, data []byte, authTime time.Time) PACType {
	t.Helper()
	var parsed PACType
	if err := parsed.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	for _, buffer := range parsed.Buffers {
		start := int(buffer.Offset)
		payload := parsed.Data[start : start+int(buffer.CBBufferSize)]
		var signature SignatureData
		switch buffer.ULType {
		case infoTypePACServerSignatureData:
			if _, err := signature.Unmarshal(payload); err != nil {
				t.Fatal(err)
			}
			parsed.ServerChecksum = &signature
		case infoTypePACKDCSignatureData:
			if _, err := signature.Unmarshal(payload); err != nil {
				t.Fatal(err)
			}
			parsed.KDCChecksum = &signature
		case infoTypePACFullChecksum:
			if _, err := signature.Unmarshal(payload); err != nil {
				t.Fatal(err)
			}
			parsed.FullChecksum = &signature
		case infoTypePACTicketChecksum:
			if _, err := signature.Unmarshal(payload); err != nil {
				t.Fatal(err)
			}
			parsed.TicketChecksum = &signature
		}
	}
	domainSID := mstypes.RPCSID{
		Revision: 1, SubAuthorityCount: 3,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{21, 1, 2},
	}
	userSID := domainSID
	userSID.SubAuthority = append(append([]uint32(nil), domainSID.SubAuthority...), 500)
	userSID.SubAuthorityCount = 4
	objectSID := userSID
	objectSID.SubAuthority = append([]uint32(nil), userSID.SubAuthority...)
	parsed.KerbValidationInfo = &KerbValidationInfo{LogonDomainID: domainSID, UserID: 500}
	parsed.KerbValidationInfo.EffectiveName.Value = "testuser"
	parsed.ClientInfo = &ClientInfo{ClientID: mstypes.GetFileTime(authTime), Name: "testuser"}
	parsed.Requestor = &Requestor{SID: userSID}
	parsed.UPNDNSInfo = &UPNDNSInfo{Flags: UPNDNSInfoFlagExtended, SAMAccountName: "TESTUSER", ObjectSID: &objectSID}
	return parsed
}
