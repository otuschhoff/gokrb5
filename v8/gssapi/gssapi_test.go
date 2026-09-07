package gssapi

import (
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
)

func TestOID(t *testing.T) {
	var tests = []struct {
		name OIDName
		oid  []int
	}{
		{OIDMSLegacyKRB5, []int{1, 2, 840, 48018, 1, 2, 2}},
		{OIDKRB5, []int{1, 2, 840, 113554, 1, 2, 2}},
		{OIDSPNEGO, []int{1, 3, 6, 1, 5, 5, 2}},
		{OIDGSSIAKerb, []int{1, 3, 6, 1, 5, 2, 5}},
		{OIDNegoEx, []int{1, 3, 6, 1, 4, 1, 311, 2, 2, 30}},
		{OIDPKU2U, []int{1, 3, 6, 1, 5, 2, 7}},
	}

	for _, tst := range tests {
		oid := asn1.ObjectIdentifier(tst.oid)
		assert.True(t, oid.Equal(OIDName(tst.name).OID()), "OID value not as expected for %s", tst.name)
	}
	assert.Empty(t, OIDName("unknown").OID())
}

func TestStatusErrorDescriptions(t *testing.T) {
	codes := []int{
		StatusBadBindings, StatusBadMech, StatusBadName, StatusBadNameType,
		StatusBadStatus, StatusBadSig, StatusBadMIC, StatusContextExpired,
		StatusCredentialsExpired, StatusDefectiveCredential, StatusDefectiveToken,
		StatusFailure, StatusNoContext, StatusNoCred, StatusBadQOP,
		StatusUnauthorized, StatusUnavailable, StatusDuplicateElement,
		StatusNameNotMN, StatusComplete, StatusContinueNeeded, StatusDuplicateToken,
		StatusOldToken, StatusUnseqToken, StatusGapToken,
	}
	for _, code := range codes {
		if got := (Status{Code: code}).Error(); got == "" || got == "unknown GSS-API error status" {
			t.Fatalf("status %d description = %q", code, got)
		}
	}
	if got := (Status{Code: -1}).Error(); got != "unknown GSS-API error status" {
		t.Fatalf("unknown status = %q", got)
	}
	if got := (Status{Code: StatusFailure, Message: "details"}).Error(); got != "failure, unspecified at GSS-API level: details" {
		t.Fatalf("status with details = %q", got)
	}
}
