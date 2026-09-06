package krberror

import (
	"errors"
	"fmt"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/stretchr/testify/assert"
)

func TestErrorf(t *testing.T) {
	err := fmt.Errorf("an error")
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
