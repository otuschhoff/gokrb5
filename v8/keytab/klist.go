package keytab

import (
	"fmt"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

// Klist renders the keytab in the format produced by MIT klist -k.
func (kt *Keytab) Klist(showTimestamps, showKeys, showEtypes bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Keytab name: FILE:%s\n", kt.name)
	if showTimestamps {
		b.WriteString("KVNO Timestamp         Principal\n")
		b.WriteString("---- ----------------- --------------------------------------------------------\n")
	} else {
		b.WriteString("KVNO Principal\n")
		b.WriteString("---- --------------------------------------------------------------------------\n")
	}
	for _, entry := range kt.Entries {
		fmt.Fprintf(&b, "%4d ", entry.KVNO)
		if showTimestamps {
			fmt.Fprintf(&b, "%s ", entry.Timestamp.Format("01/02/06 15:04:05"))
		}
		b.WriteString(entry.Principal.String())
		if showEtypes {
			fmt.Fprintf(&b, " (%s) ", etypeID.ETypeToString(entry.Key.KeyType))
		}
		if showKeys {
			fmt.Fprintf(&b, " (0x%x)", entry.Key.KeyValue)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
