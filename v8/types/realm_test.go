package types

import "testing"

func TestRealmEqual(t *testing.T) {
	const exampleRealm = "EXAMPLE.COM"
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "same", a: exampleRealm, b: exampleRealm, want: true},
		{name: "mixed case", a: exampleRealm, b: "example.com", want: true},
		{name: "different", a: exampleRealm, b: "OTHER.COM", want: false},
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
