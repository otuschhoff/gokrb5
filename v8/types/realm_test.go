package types

import "testing"

func TestRealmEqual(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "same", a: "EXAMPLE.COM", b: "EXAMPLE.COM", want: true},
		{name: "mixed case", a: "EXAMPLE.COM", b: "example.com", want: true},
		{name: "different", a: "EXAMPLE.COM", b: "OTHER.COM", want: false},
		{name: "empty", a: "", b: "", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := RealmEqual(test.a, test.b); got != test.want {
				t.Fatalf("RealmEqual(%q, %q) = %t, want %t", test.a, test.b, got, test.want)
			}
		})
	}
}
