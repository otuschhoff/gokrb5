package ntstatus

import "testing"

func TestCodeString(t *testing.T) {
	if got := STATUS_ACCOUNT_DISABLED.String(); got != "STATUS_ACCOUNT_DISABLED" {
		t.Fatalf("known status string = %q", got)
	}
	if got := Code(0xDEADBEEF).String(); got != "NTSTATUS(0xDEADBEEF)" {
		t.Fatalf("unknown status string = %q", got)
	}
}
