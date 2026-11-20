package pac

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/rpc/v2/mstypes"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestVerifyPACChecksumEnctypeError(t *testing.T) {
	t.Parallel()

	var signature SignatureData
	signature.SignatureType = 12345
	var unusedKey types.EncryptionKey
	err := verifyPACChecksum(&signature, unusedKey, nil, "service")
	if err == nil || !strings.HasPrefix(err.Error(), "select PAC service checksum algorithm:") {
		t.Fatalf("want contextual checksum lookup error, got %v", err)
	}
	if cause := errors.Unwrap(err); cause == nil || !strings.Contains(cause.Error(), "unsupported checksum type") {
		t.Fatalf("checksum lookup cause was lost: %v", err)
	}
}

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
		{"client name", func(_ *PACType, o *VerifyOptions) { o.ExpectedClientName = "other" }, "client name"},
		{"client time", func(_ *PACType, o *VerifyOptions) {
			later := authTime.Add(time.Second)
			o.ExpectedAuthTime = &later
		}, "authentication time"},
		{"requestor SID", func(p *PACType, _ *VerifyOptions) { p.Requestor.SID.SubAuthority[3]++ }, "requestor SID"},
		{"UPN SID", func(p *PACType, _ *VerifyOptions) { p.UPNDNSInfo.ObjectSID.SubAuthority[3]++ }, "UPN/DNS SID"},
		{"SAM name", func(p *PACType, _ *VerifyOptions) { p.UPNDNSInfo.SAMAccountName = "other" }, "SAM account name"},
		{"KDC checksum", func(p *PACType, _ *VerifyOptions) { p.KDCChecksum.Signature[0] ^= 0xff }, "KDC checksum"},
		{"full checksum", func(p *PACType, _ *VerifyOptions) { p.FullChecksum.Signature[0] ^= 0xff }, "full KDC checksum"},
		{"ticket checksum", func(_ *PACType, o *VerifyOptions) { o.TicketData = []byte("wrong") }, "ticket checksum"},
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
		start := mustPACInt(t, buffer.Offset)
		payload := parsed.Data[start : start+int(buffer.CBBufferSize)]
		var target **SignatureData
		switch buffer.ULType {
		case infoTypePACServerSignatureData:
			target = &parsed.ServerChecksum
		case infoTypePACKDCSignatureData:
			target = &parsed.KDCChecksum
		case infoTypePACFullChecksum:
			target = &parsed.FullChecksum
		case infoTypePACTicketChecksum:
			target = &parsed.TicketChecksum
		default:
			continue
		}
		var signature SignatureData
		if _, err := signature.Unmarshal(payload); err != nil {
			t.Fatal(err)
		}
		*target = &signature
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
	parsed.KerbValidationInfo = new(KerbValidationInfo)
	parsed.KerbValidationInfo.LogonDomainID = domainSID
	parsed.KerbValidationInfo.UserID = 500
	parsed.KerbValidationInfo.EffectiveName.Value = "testuser"
	parsed.ClientInfo = &ClientInfo{ClientID: mstypes.GetFileTime(authTime), NameLength: 0, Name: "testuser"}
	parsed.Requestor = &Requestor{SID: userSID}
	parsed.UPNDNSInfo = new(UPNDNSInfo)
	parsed.UPNDNSInfo.Flags = UPNDNSInfoFlagExtended
	parsed.UPNDNSInfo.SAMAccountName = "TESTUSER"
	parsed.UPNDNSInfo.ObjectSID = &objectSID
	return parsed
}
