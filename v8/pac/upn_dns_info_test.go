package pac

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/stretchr/testify/assert"
)

func TestUPN_DNSInfo_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_UPN_DNS_Info)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k UPNDNSInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	assert.Equal(t, uint16(42), k.UPNLength, "UPN Length not as expected")
	assert.Equal(t, uint16(16), k.UPNOffset, "UPN Offset not as expected")
	assert.Equal(t, uint16(22), k.DNSDomainNameLength, "DNS Domain Length not as expected")
	assert.Equal(t, uint16(64), k.DNSDomainNameOffset, "DNS Domain Offset not as expected")
	assert.Equal(t, "testuser1@test.gokrb5", k.UPN, "UPN not as expected")
	assert.Equal(t, "TEST.GOKRB5", k.DNSDomain, "DNS Domain not as expected")
	assert.Equal(t, uint32(0), k.Flags, "DNS Domain not as expected")
}

func TestUPNDNSInfoExtendedRoundTrip(t *testing.T) {
	sid := mstypes.RPCSID{
		Revision: 1, SubAuthorityCount: 4,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthority:        []uint32{21, 1, 2, 500},
	}
	want := UPNDNSInfo{
		Flags: UPNDNSInfoFlagNoUPNAttribute | UPNDNSInfoFlagExtended,
		UPN:   "user\U0001f600@example.test", DNSDomain: "EXAMPLE.TEST",
		SAMAccountName: "user", ObjectSID: &sid,
	}
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got UPNDNSInfo
	if err := got.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if got.UPN != want.UPN || got.DNSDomain != want.DNSDomain || got.SAMAccountName != want.SAMAccountName || got.ObjectSID.String() != sid.String() {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestUPNDNSInfoExtendedRequiresHeaderAndSID(t *testing.T) {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[8:12], UPNDNSInfoFlagExtended)
	if err := (&UPNDNSInfo{}).Unmarshal(b); !errors.Is(err, ErrPACMalformed) {
		t.Fatalf("short extension error = %v, want ErrPACMalformed", err)
	}
	_, err := (&UPNDNSInfo{Flags: UPNDNSInfoFlagExtended}).Marshal()
	if err == nil {
		t.Fatal("Marshal accepted extended UPN_DNS_INFO without SID")
	}
}

func TestUPNDNSInfoRejectsUnpairedSurrogate(t *testing.T) {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint16(b[0:2], 2)
	binary.LittleEndian.PutUint16(b[2:4], 12)
	binary.LittleEndian.PutUint16(b[4:6], 2)
	binary.LittleEndian.PutUint16(b[6:8], 14)
	binary.LittleEndian.PutUint16(b[12:14], 0xd800)
	if err := (&UPNDNSInfo{}).Unmarshal(b); !errors.Is(err, ErrPACMalformed) {
		t.Fatalf("Unmarshal error = %v, want ErrPACMalformed", err)
	}
}

func TestUPNDNSInfoBoundsChecks(t *testing.T) {
	validHeader := func() []byte {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[0:2], 2)
		binary.LittleEndian.PutUint16(b[2:4], 12)
		binary.LittleEndian.PutUint16(b[4:6], 2)
		binary.LittleEndian.PutUint16(b[6:8], 14)
		return b
	}
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{"UPN past end", func(b []byte) { binary.LittleEndian.PutUint16(b[2:4], 16) }},
		{"DNS past end", func(b []byte) { binary.LittleEndian.PutUint16(b[6:8], 16) }},
		{"odd UPN length", func(b []byte) { binary.LittleEndian.PutUint16(b[0:2], 1) }},
		{"odd DNS length", func(b []byte) { binary.LittleEndian.PutUint16(b[4:6], 1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := validHeader()
			tt.mutate(b)
			if err := (&UPNDNSInfo{}).Unmarshal(b); !errors.Is(err, ErrPACMalformed) {
				t.Fatalf("Unmarshal error = %v, want ErrPACMalformed", err)
			}
		})
	}
}
