package krberror

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
)

func TestErrorf(t *testing.T) {
	err := errors.New("an error")
	var a Krberror
	a = Errorf(err, "cause", "some text")
	assert.Equal(t, "[Root cause: cause] cause: some text: an error", a.Error())
	a = Errorf(err, "cause", "arg1=%d arg2=%s", 123, "arg")
	assert.Equal(t, "[Root cause: cause] cause: arg1=123 arg2=arg: an error", a.Error())

	err = NewErrorf("another error", "some text")
	a = Errorf(err, "cause", "some text")
	assert.Equal(t, "[Root cause: another error] cause: some text < another error: some text", a.Error())
	a = Errorf(err, "cause", "arg1=%d arg2=%s", 123, "arg")
	assert.Equal(t, "[Root cause: another error] cause: arg1=123 arg2=arg < another error: some text", a.Error())
}

func TestErrorfPreservesInterveningWrapper(t *testing.T) {
	cause := errors.New("injected decoding failure")
	inner := Errorf(cause, EncodingError, "decode")
	wrapper := fmt.Errorf("outer context: %w", inner)
	result := Errorf(wrapper, NetworkingError, "exchange")
	assert.ErrorIs(t, result, cause)
	assert.ErrorIs(t, result, wrapper)
	assert.Contains(t, result.Error(), "outer context")
	assert.Equal(t, NetworkingError, result.RootCause)
}

func TestErrorfUnwrapsKRBError(t *testing.T) {
	want := errors.New("KDC error")
	err := Errorf(want, KDCError, "KDC rejected request")
	err = Errorf(err, KRBMsgError, "AS exchange failed")
	assert.ErrorIs(t, err, want)
}

type statusError struct{}

func (statusError) Error() string { return "KDC error" }
func (statusError) NTStatus() (ntstatus.Code, bool) {
	return ntstatus.STATUS_ACCOUNT_DISABLED, true
}

func TestKrberrorNTStatus(t *testing.T) {
	err := Errorf(statusError{}, KDCError, "KDC rejected request")
	status, ok := err.NTStatus()
	if !ok || status != ntstatus.STATUS_ACCOUNT_DISABLED {
		t.Fatalf("NTStatus = %v, %v", status, ok)
	}
}

func TestPolicyErrorContracts(t *testing.T) {
	cause := statusError{}
	err := NewPolicyError(ErrDelegationNotPermitted, cause)
	assert.EqualError(t, err, "delegation not permitted: KDC error")
	assert.ErrorIs(t, err, ErrDelegationNotPermitted)
	assert.ErrorIs(t, err, cause)
	var policy PolicyError
	require.ErrorAs(t, err, &policy)
	assert.IsType(t, policy, err)
	assert.ErrorIs(t, policy.Unwrap(), cause)
	status, ok := policy.NTStatus()
	if !ok || status != ntstatus.STATUS_ACCOUNT_DISABLED {
		t.Fatalf("policy NTStatus = %v, %v", status, ok)
	}
}

func TestPolicyErrorWithoutNTStatus(t *testing.T) {
	cause := errors.New("denied")
	err := NewPolicyError(ErrProtocolTransitionNotPermitted, cause)
	assert.ErrorIs(t, err, ErrProtocolTransitionNotPermitted)
	var policy PolicyError
	require.ErrorAs(t, err, &policy)
	assert.IsType(t, policy, err)
	assert.ErrorIs(t, policy.Unwrap(), cause)
	if status, ok := policy.NTStatus(); ok || status != 0 {
		t.Fatalf("missing NTStatus = %v, %v", status, ok)
	}
}

func TestKrberrorConstructorsAndMissingStatus(t *testing.T) {
	err := New(ConfigError, "invalid configuration")
	if err.Error() != "[Root cause: Configuration_Error] invalid configuration" || err.Unwrap() != nil {
		t.Fatalf("new error = %q, unwrap %v", err, err.Unwrap())
	}
	if status, ok := err.NTStatus(); ok || status != 0 {
		t.Fatalf("missing NTStatus = %v, %v", status, ok)
	}
	formatted := NewErrorf(EncodingError, "bad field %d", 3)
	if formatted.Error() != "[Root cause: Encoding_Error] Encoding_Error: bad field 3" {
		t.Fatalf("formatted error = %q", formatted)
	}
}

func TestNewErrorfFormatting(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		format   string
		args     []any
		wantText string
	}{
		{
			name:     "no arguments preserves percent signs",
			format:   "literal %d and %%",
			args:     []any{},
			wantText: "Encoding_Error: literal %d and %%",
		},
		{
			name:     "arguments expand directives",
			format:   "field %d uses %%",
			args:     []any{3},
			wantText: "Encoding_Error: field 3 uses %",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewErrorf(EncodingError, tt.format, tt.args...)
			assert.EqualError(t, err, "[Root cause: Encoding_Error] "+tt.wantText)
			assert.Equal(t, EncodingError, err.RootCause)
			assert.Equal(t, []string{tt.wantText}, err.EText)
			assert.NoError(t, err.Unwrap())
		})
	}
}
