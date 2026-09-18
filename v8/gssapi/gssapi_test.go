package gssapi

import (
	"fmt"
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

func TestStatusError(t *testing.T) {
	testCases := []struct {
		code int
		want string
	}{
		{StatusBadBindings, "channel binding mismatch"},
		{StatusBadMech, "unsupported mechanism requested"},
		{StatusBadName, "invalid name provided"},
		{StatusBadNameType, "name of unsupported type provided"},
		{StatusBadStatus, "invalid input status selector"},
		{StatusBadSig, "token had invalid integrity check"},
		{StatusBadMIC, "preferred alias for GSS_S_BAD_SIG"},
		{StatusContextExpired, "specified security context expired"},
		{StatusCredentialsExpired, "expired credentials detected"},
		{StatusDefectiveCredential, "defective credential detected"},
		{StatusDefectiveToken, "defective token detected"},
		{StatusFailure, "failure, unspecified at GSS-API level"},
		{StatusNoContext, "no valid security context specified"},
		{StatusNoCred, "no valid credentials provided"},
		{StatusBadQOP, "unsupported QOP valu"},
		{StatusUnauthorized, "operation unauthorized"},
		{StatusUnavailable, "operation unavailable"},
		{StatusDuplicateElement, "duplicate credential element requested"},
		{StatusNameNotMN, "name contains multi-mechanism elements"},
		{StatusComplete, "normal completion"},
		{StatusContinueNeeded, "continuation call to routine required"},
		{StatusDuplicateToken, "duplicate per-message token detected"},
		{StatusOldToken, "timed-out per-message token detected"},
		{StatusUnseqToken, "reordered (early) per-message token detected"},
		{StatusGapToken, "skipped predecessor token(s) detected"},
		{-1, "unknown GSS-API error status"},
	}
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("code-%d", testCase.code), func(t *testing.T) {
			assert.Equal(t, testCase.want, (Status{Code: testCase.code}).Error())
			assert.Equal(t, testCase.want+": detail", (Status{Code: testCase.code, Message: "detail"}).Error())
		})
	}
}

func TestNewContextFlags(t *testing.T) {
	flags := NewContextFlags()
	assert.Equal(t, 32, flags.BitLength)
	assert.Equal(t, []byte{0, 0, 0, 0}, flags.Bytes)
}
