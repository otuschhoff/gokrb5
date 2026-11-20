package pku2u

import (
	"math"
	"testing"
)

const (
	last30BitSequence = 1_073_741_823
	aboveSequenceErr  = "PKU2U sequence number 1073741824 exceeds 30-bit range"
)

func TestPKU2USequenceInt64(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   uint64
		want    int64
		wantErr string
	}{
		{name: "zero", input: 0, want: 0, wantErr: ""},
		{name: "upper bound", input: last30BitSequence, want: last30BitSequence, wantErr: ""},
		{
			name: "above upper bound", input: last30BitSequence + 1, want: 0,
			wantErr: aboveSequenceErr,
		},
		{
			name: "unsigned maximum", input: math.MaxUint64, want: 0,
			wantErr: "PKU2U sequence number 18446744073709551615 exceeds 30-bit range",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := pku2uSequenceInt64(tc.input)
			checkSequenceConversion(t, got, tc.want, err, tc.wantErr)
		})
	}
}

func TestPKU2USequenceUint64(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   int64
		want    uint64
		wantErr string
	}{
		{name: "negative", input: -1, want: 0, wantErr: "PKU2U sequence number -1 exceeds 30-bit range"},
		{name: "zero", input: 0, want: 0, wantErr: ""},
		{name: "upper bound", input: last30BitSequence, want: last30BitSequence, wantErr: ""},
		{
			name: "above upper bound", input: last30BitSequence + 1, want: 0,
			wantErr: aboveSequenceErr,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := pku2uSequenceUint64(tc.input)
			checkSequenceConversion(t, got, tc.want, err, tc.wantErr)
		})
	}
}

func TestRandomSequenceRange(t *testing.T) {
	t.Parallel()

	sequence, err := randomSequence()
	if err != nil {
		t.Fatal(err)
	}
	if sequence > last30BitSequence {
		t.Fatalf("generated sequence %d exceeds %d", sequence, last30BitSequence)
	}
}

func checkSequenceConversion[T int64 | uint64](t *testing.T, got, want T, err error, wantErr string) {
	t.Helper()

	var message string
	if err != nil {
		message = err.Error()
	}
	if got != want || message != wantErr || (err == nil) != (wantErr == "") {
		t.Errorf("conversion = (%d, %v), want (%d, %q)", got, err, want, wantErr)
	}
}
