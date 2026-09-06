package types

import "strings"

// RealmEqual reports whether two Kerberos realm names are equal.
func RealmEqual(a, b string) bool {
	return strings.EqualFold(a, b)
}
