// Package keytab implements Kerberos keytabs: https://web.mit.edu/kerberos/krb5-devel/doc/formats/keytab_file_format.html.
package keytab

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	keytabFirstByte byte = 0o5
)

var (
	// ErrNotFound indicates that no entry matched the requested principal and enctype.
	ErrNotFound = errors.New("matching keytab entry not found")
	// ErrKVNONotFound indicates that matching entries exist, but none has the requested KVNO.
	ErrKVNONotFound = errors.New("matching keytab KVNO not found")
)

// Keytab struct.
type Keytab struct {
	version   uint8
	byteOrder binary.ByteOrder
	name      string
	Entries   []Entry
}

// Entry is one keytab record.
type Entry struct {
	Principal     Principal
	Timestamp     time.Time
	Key           types.EncryptionKey
	KVNO          uint32
	kvno32Present bool
}

func (e Entry) String() string {
	return fmt.Sprintf("% 4d %s %-56s %2d %-64x",
		e.KVNO,
		e.Timestamp.Format("02/01/06 15:04:05"),
		e.Principal.String(),
		e.Key.KeyType,
		e.Key.KeyValue,
	)
}

// Principal identifies a keytab principal.
type Principal struct {
	Realm      string
	Components []string
	NameType   int32
}

func (p Principal) String() string {
	components := make([]string, len(p.Components))
	for i, component := range p.Components {
		components[i] = escapePrincipalPart(component)
	}
	name := strings.Join(components, "/")
	return name + "@" + escapePrincipalPart(p.Realm)
}

func escapePrincipalPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '/', '@', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case 0:
			b.WriteString(`\0`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParsePrincipal parses a principal name with MIT-style backslash escapes.
func ParsePrincipal(s string) (Principal, error) {
	enterprise, err := classifyPrincipalName(s)
	if err != nil {
		return Principal{}, err
	}
	return splitPrincipalName(s, enterprise)
}

// classifyPrincipalName counts the unescaped realm separators in s and reports
// whether the name is an enterprise principal with an embedded '@'.
func classifyPrincipalName(s string) (bool, error) {
	escaped := false
	unescapedAts := 0
	for _, r := range s {
		if escaped {
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '@':
			unescapedAts++
		}
	}
	if unescapedAts > 2 {
		return false, errors.New("principal contains too many realm separators")
	}
	return unescapedAts == 2, nil
}

// principalSplitter holds the state while splitting a principal name into
// components and realm.
type principalSplitter struct {
	p                 Principal
	part              strings.Builder
	inRealm           bool
	enterprise        bool
	firstEnterpriseAt bool
}

// splitPrincipalName splits s into components and realm. Enterprise names keep
// the first unescaped '@' literally inside the component.
func splitPrincipalName(s string, enterprise bool) (Principal, error) {
	sp := principalSplitter{enterprise: enterprise, firstEnterpriseAt: true}
	escaped := false
	for _, r := range s {
		if escaped {
			writePrincipalEscape(&sp.part, r)
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '@':
			if err := sp.realmSeparator(); err != nil {
				return Principal{}, err
			}
		case '/':
			if err := sp.componentSeparator(r); err != nil {
				return Principal{}, err
			}
		default:
			sp.part.WriteRune(r)
		}
	}
	if escaped {
		return Principal{}, errors.New("principal ends with an incomplete escape")
	}
	return sp.finish()
}

// writePrincipalEscape writes the escaped form of r to part.
func writePrincipalEscape(part *strings.Builder, r rune) {
	switch r {
	case 'n':
		part.WriteByte('\n')
	case 't':
		part.WriteByte('\t')
	case 'b':
		part.WriteByte('\b')
	case '0':
		part.WriteByte(0)
	default:
		part.WriteRune(r)
	}
}

// appendPart ends the current component and appends it to the principal.
func (sp *principalSplitter) appendPart() error {
	if sp.part.Len() == 0 {
		return errors.New("principal contains an empty component")
	}
	sp.p.Components = append(sp.p.Components, sp.part.String())
	sp.part.Reset()
	return nil
}

// realmSeparator handles an unescaped '@'.
func (sp *principalSplitter) realmSeparator() error {
	if sp.enterprise && sp.firstEnterpriseAt {
		sp.part.WriteByte('@')
		sp.firstEnterpriseAt = false
		return nil
	}
	if sp.inRealm {
		return errors.New("principal contains multiple realm separators")
	}
	if err := sp.appendPart(); err != nil {
		return err
	}
	sp.inRealm = true
	return nil
}

// componentSeparator handles an unescaped '/'; enterprise names keep it
// literally.
func (sp *principalSplitter) componentSeparator(r rune) error {
	if sp.enterprise {
		sp.part.WriteRune(r)
		return nil
	}
	if sp.inRealm {
		return errors.New("realm contains an unescaped component separator")
	}
	return sp.appendPart()
}

// finish stores the final part as the realm or last component and assigns the
// name type.
func (sp *principalSplitter) finish() (Principal, error) {
	if sp.part.Len() == 0 {
		if sp.inRealm {
			return Principal{}, errors.New("principal contains an empty realm")
		}
		return Principal{}, errors.New("principal contains an empty component")
	}
	if sp.inRealm {
		sp.p.Realm = sp.part.String()
	} else {
		sp.p.Components = append(sp.p.Components, sp.part.String())
	}
	if sp.enterprise {
		sp.p.NameType = nametype.KRB_NT_ENTERPRISE
	} else {
		sp.p.NameType = nametype.KRB_NT_PRINCIPAL
	}
	return sp.p, nil
}

// New creates new, empty Keytab type.
func New() *Keytab {
	var e []Entry
	return &Keytab{
		version:   2,
		byteOrder: binary.BigEndian,
		Entries:   e,
	}
}

// Version returns the keytab file format version.
func (kt *Keytab) Version() uint8 {
	return kt.version
}

// Principals returns the distinct principals in entry order.
func (kt *Keytab) Principals() []Principal {
	principals := make([]Principal, 0)
	for _, entry := range kt.Entries {
		seen := false
		for _, p := range principals {
			if principalMatches(entry.Principal, p) {
				seen = true
				break
			}
		}
		if !seen {
			p := entry.Principal
			p.Components = append([]string(nil), p.Components...)
			principals = append(principals, p)
		}
	}
	return principals
}

// ETypesForPrincipal returns the distinct encryption types available for p in
// keytab entry order.
func (kt *Keytab) ETypesForPrincipal(p Principal) []int32 {
	etypes := make([]int32, 0)
	seen := make(map[int32]struct{})
	for _, entry := range kt.Entries {
		if !principalMatches(entry.Principal, p) {
			continue
		}
		if _, ok := seen[entry.Key.KeyType]; ok {
			continue
		}
		seen[entry.Key.KeyType] = struct{}{}
		etypes = append(etypes, entry.Key.KeyType)
	}
	return etypes
}

// GetEntry returns the best matching keytab entry using MIT Kerberos lookup semantics.
// Enctype zero is a wildcard; similar enctype matching is not supported.
func (kt *Keytab) GetEntry(p Principal, kvno uint32, etype int32) (Entry, error) {
	var lookup entryLookup
	for _, candidate := range kt.Entries {
		if !principalMatches(candidate.Principal, p) || etype != 0 && candidate.Key.KeyType != etype {
			continue
		}
		lookup.principalAndETypeFound = true
		lookup.consider(candidate, kvno)
	}
	return lookup.result(p, kvno, etype)
}

// entryLookup accumulates the best exact and 8-bit KVNO fallback matches while
// scanning keytab entries.
type entryLookup struct {
	exact                  Entry
	fallback               Entry
	exactFound             bool
	fallbackFound          bool
	principalAndETypeFound bool
}

// consider records candidate for the requested KVNO. A zero KVNO requests the
// newest highest-KVNO entry; otherwise an exact KVNO match wins over the 8-bit
// fallback, and ties break on the newest timestamp.
func (l *entryLookup) consider(candidate Entry, kvno uint32) {
	if kvno == 0 {
		if !l.exactFound || candidate.KVNO > l.exact.KVNO || candidate.KVNO == l.exact.KVNO && candidate.Timestamp.After(l.exact.Timestamp) {
			l.exact = candidate
			l.exactFound = true
		}
		return
	}
	if candidate.KVNO == kvno {
		if !l.exactFound || candidate.Timestamp.After(l.exact.Timestamp) {
			l.exact = candidate
			l.exactFound = true
		}
		return
	}
	if kvno > 255 && candidate.KVNO == kvno&0xff {
		if !l.fallbackFound || candidate.Timestamp.After(l.fallback.Timestamp) {
			l.fallback = candidate
			l.fallbackFound = true
		}
	}
}

// result resolves the lookup: exact match, then fallback, then a typed error.
func (l *entryLookup) result(p Principal, kvno uint32, etype int32) (Entry, error) {
	if l.exactFound {
		return l.exact, nil
	}
	if l.fallbackFound {
		return l.fallback, nil
	}
	if l.principalAndETypeFound && kvno != 0 {
		return Entry{}, fmt.Errorf("%w: principal %q, kvno %d, enctype %d", ErrKVNONotFound, p.String(), kvno, etype)
	}
	return Entry{}, fmt.Errorf("%w: principal %q, enctype %d", ErrNotFound, p.String(), etype)
}

func principalMatches(candidate, requested Principal) bool {
	if requested.Realm != "" && !types.RealmEqual(candidate.Realm, requested.Realm) {
		return false
	}
	if len(candidate.Components) != len(requested.Components) {
		return false
	}
	for i := range requested.Components {
		if candidate.Components[i] != requested.Components[i] {
			return false
		}
	}
	return true
}

// GetEncryptionKey returns the EncryptionKey and KVNO from the best matching keytab entry.
func (kt *Keytab) GetEncryptionKey(princName types.PrincipalName, realm string, kvno int, etype int32) (types.EncryptionKey, int, error) {
	if kvno < 0 {
		return types.EncryptionKey{}, 0, fmt.Errorf("%w: kvno %d", ErrKVNONotFound, kvno)
	}
	entry, err := kt.GetEntry(Principal{
		Realm:      realm,
		Components: princName.NameString,
		NameType:   princName.NameType,
	}, uint32(kvno), etype)
	if err != nil {
		return types.EncryptionKey{}, 0, fmt.Errorf("matching key not found in keytab. Looking for %q realm: %v kvno: %v etype: %v: %w", princName.PrincipalNameString(), realm, kvno, etype, err)
	}
	return entry.Key, int(entry.KVNO), nil
}

// Create a new Keytab entry.
func newEntry() Entry {
	var b []byte
	return Entry{
		Principal: newPrincipal(),
		Timestamp: time.Time{},
		Key: types.EncryptionKey{
			KeyType:  0,
			KeyValue: b,
		},
		KVNO: 0,
	}
}

func (kt Keytab) String() string {
	var s string
	s = `KVNO Timestamp         Principal                                                ET Key
---- ----------------- -------------------------------------------------------- -- ----------------------------------------------------------------
`
	for _, entry := range kt.Entries {
		s += entry.String() + "\n"
	}
	return s
}

// AddEntry adds an entry to the keytab. The password should be provided in plain text and it will be converted using the defined enctype to be stored.
func (kt *Keytab) AddEntry(principalName, realm, password string, ts time.Time, kvno uint32, encType int32) error {
	princ, _ := types.ParseSPNString(principalName)
	key, _, err := crypto.GetKeyFromPassword(password, princ, realm, encType, types.PADataSequence{})
	if err != nil {
		return err
	}
	return kt.AddKey(Principal{Realm: realm, Components: princ.NameString, NameType: princ.NameType}, kvno, key, ts)
}

// AddEntryWithSalt derives and adds an entry using the supplied salt and string-to-key parameters.
func (kt *Keytab) AddEntryWithSalt(principalName, realm, password, salt, s2kparams string, ts time.Time, kvno uint32, encType int32) error {
	princ, _ := types.ParseSPNString(principalName)
	et, err := crypto.GetEtype(encType)
	if err != nil {
		return err
	}
	if s2kparams == "" {
		s2kparams = et.GetDefaultStringToKeyParams()
	}
	keyValue, err := et.StringToKey(password, salt, s2kparams)
	if err != nil {
		return fmt.Errorf("error deriving key from string: %w", err)
	}
	return kt.AddKey(
		Principal{Realm: realm, Components: princ.NameString, NameType: princ.NameType},
		kvno,
		types.EncryptionKey{KeyType: encType, KeyValue: keyValue},
		ts,
	)
}

// AddKey validates and adds an entry containing an already-derived key.
func (kt *Keytab) AddKey(p Principal, kvno uint32, key types.EncryptionKey, ts time.Time) error {
	if len(p.Components) == 0 {
		return errors.New("keytab principal must contain at least one component")
	}
	for _, component := range p.Components {
		if component == "" {
			return errors.New("keytab principal components must not be empty")
		}
	}
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}
	keySize := et.GetKeyByteSize()
	if key.KeyType == etypeID.AES256_CTS_HMAC_SHA384_192 {
		keySize = 32
	}
	if len(key.KeyValue) != keySize {
		return fmt.Errorf("invalid key length %d for enctype %d: expected %d", len(key.KeyValue), key.KeyType, keySize)
	}
	p.Components = append([]string(nil), p.Components...)
	key.KeyValue = append([]byte(nil), key.KeyValue...)
	kt.Entries = append(kt.Entries, Entry{Principal: p, Timestamp: ts, Key: key, KVNO: kvno})
	return nil
}

// RemoveEntry removes entries matching p, kvno, and etype. Zero kvno and etype values are wildcards.
func (kt *Keytab) RemoveEntry(p Principal, kvno uint32, etype int32) int {
	return kt.removeEntries(func(entry Entry) bool {
		return principalMatches(entry.Principal, p) && (kvno == 0 || entry.KVNO == kvno) && (etype == 0 || entry.Key.KeyType == etype)
	})
}

// RemovePrincipal removes every entry matching p.
func (kt *Keytab) RemovePrincipal(p Principal) int {
	return kt.removeEntries(func(entry Entry) bool {
		return principalMatches(entry.Principal, p)
	})
}

// RemoveOldKVNO retains entries for the newest keep distinct KVNOs matching p and removes older generations.
func (kt *Keytab) RemoveOldKVNO(p Principal, keep int) int {
	if keep <= 0 {
		return kt.RemovePrincipal(p)
	}
	kvnos := make(map[uint32]struct{})
	for _, entry := range kt.Entries {
		if principalMatches(entry.Principal, p) {
			kvnos[entry.KVNO] = struct{}{}
		}
	}
	ordered := make([]uint32, 0, len(kvnos))
	for kvno := range kvnos {
		ordered = append(ordered, kvno)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] > ordered[j] })
	if len(ordered) <= keep {
		return 0
	}
	old := make(map[uint32]struct{}, len(ordered)-keep)
	for _, kvno := range ordered[keep:] {
		old[kvno] = struct{}{}
	}
	return kt.removeEntries(func(entry Entry) bool {
		_, remove := old[entry.KVNO]
		return remove && principalMatches(entry.Principal, p)
	})
}

// Merge appends entries from other that are not already present and returns the number added.
func (kt *Keytab) Merge(other *Keytab) int {
	if other == nil {
		return 0
	}
	added := 0
	for _, candidate := range other.Entries {
		duplicate := false
		for _, entry := range kt.Entries {
			if entry.KVNO == candidate.KVNO && entry.Key.KeyType == candidate.Key.KeyType &&
				entry.Principal.NameType == candidate.Principal.NameType && entry.Principal.Realm == candidate.Principal.Realm &&
				principalMatches(entry.Principal, candidate.Principal) &&
				bytes.Equal(entry.Key.KeyValue, candidate.Key.KeyValue) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		candidate.Principal.Components = append([]string(nil), candidate.Principal.Components...)
		candidate.Key.KeyValue = append([]byte(nil), candidate.Key.KeyValue...)
		kt.Entries = append(kt.Entries, candidate)
		added++
	}
	return added
}

func (kt *Keytab) removeEntries(remove func(Entry) bool) int {
	kept := kt.Entries[:0]
	removed := 0
	for _, entry := range kt.Entries {
		if remove(entry) {
			removed++
			continue
		}
		kept = append(kept, entry)
	}
	kt.Entries = kept
	return removed
}

// Create a new principal.
func newPrincipal() Principal {
	var c []string
	return Principal{
		Realm:      "",
		Components: c,
		NameType:   0,
	}
}

// Load a Keytab file into a Keytab type.
func Load(ktPath string) (*Keytab, error) {
	path, _, err := ResolveName(ktPath, nil)
	if err != nil {
		return new(Keytab), err
	}
	kt := new(Keytab)
	b, err := os.ReadFile(path)
	if err != nil {
		return kt, err
	}
	err = kt.Unmarshal(b)
	if err == nil {
		kt.name = path
	}
	return kt, err
}

// Read reads and unmarshals a keytab from r.
func (kt *Keytab) Read(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return kt.Unmarshal(b)
}

// Marshal keytab into byte slice
func (kt *Keytab) Marshal() ([]byte, error) {
	b := []byte{keytabFirstByte, kt.version}
	endian := kt.byteOrder
	if endian == nil || kt.version == 2 {
		endian = binary.BigEndian
	}
	for _, e := range kt.Entries {
		eb, err := e.marshal(int(kt.version), endian)
		if err != nil {
			return b, err
		}
		b = append(b, eb...)
	}
	return b, nil
}

// Write the keytab bytes to io.Writer.
// Returns the number of bytes written
func (kt *Keytab) Write(w io.Writer) (int, error) {
	b, err := kt.Marshal()
	if err != nil {
		return 0, fmt.Errorf("error marshaling keytab: %w", err)
	}
	return w.Write(b)
}

// Unmarshal byte slice of Keytab data into Keytab type.
func (kt *Keytab) Unmarshal(b []byte) error {
	kt.Entries = nil
	hasRecords, err := kt.unmarshalHeader(b)
	if err != nil {
		return err
	}
	if !hasRecords {
		return nil
	}
	return kt.unmarshalRecords(b)
}

// unmarshalHeader validates the two-byte keytab header, records the format
// version and byte order, and reports whether record bytes follow the header.
func (kt *Keytab) unmarshalHeader(b []byte) (bool, error) {
	if len(b) < 2 {
		return false, fmt.Errorf("byte array is less than 2 bytes: %d", len(b))
	}

	// The first byte of the file always has the value 5
	if b[0] != keytabFirstByte {
		return false, errors.New("invalid keytab data. First byte does not equal 5")
	}
	// Get keytab version
	// The 2nd byte contains the version number (1 or 2)
	kt.version = b[1]
	if kt.version != 1 && kt.version != 2 {
		return false, errors.New("invalid keytab data. Keytab version is neither 1 nor 2")
	}
	kt.byteOrder = keytabByteOrder(b, kt.version)
	return len(b) > 2, nil
}

// keytabByteOrder determines the record byte order. Version 1 of the file
// format uses native byte order for integer representations and version 2
// always uses big-endian byte order, except that a version 1 file whose first
// record length is invalid in native order but valid in the other order uses
// the other order.
func keytabByteOrder(b []byte, version uint8) binary.ByteOrder {
	if version != 1 {
		return binary.BigEndian
	}
	endian := nativeByteOrder()
	if firstRecordLengthValid(b, endian) {
		return endian
	}
	other := binary.ByteOrder(binary.BigEndian)
	if endian == binary.BigEndian {
		other = binary.LittleEndian
	}
	if firstRecordLengthValid(b, other) {
		endian = other
	}
	return endian
}

// firstRecordLengthValid reports whether the bytes following the header start
// with a plausible record length in the given byte order.
func firstRecordLengthValid(b []byte, endian binary.ByteOrder) bool {
	return len(b) < 6 || validRecordLength(b[2:6], endian, len(b)-6)
}

// unmarshalRecords decodes the length-prefixed record stream that follows the
// two-byte header.
func (kt *Keytab) unmarshalRecords(b []byte) error {
	// n tracks position in the byte array
	n := 2
	l, err := readInt32(b, &n, &kt.byteOrder)
	if err != nil {
		return err
	}
	for l != 0 {
		if rerr := kt.unmarshalRecordOrHole(b, &n, l); rerr != nil {
			return rerr
		}
		// Read the size of the next entry
		l, err = nextRecordLength(b, &n, &kt.byteOrder)
		if err != nil {
			return err
		}
	}
	return nil
}

// nextRecordLength reads the length of the record at n, returning zero when
// fewer than four bytes remain or n is out of range.
func nextRecordLength(b []byte, n *int, e *binary.ByteOrder) (int32, error) {
	// Check if there are still 4 bytes left to read
	// Also check that n is greater than zero
	if *n < 0 || *n > len(b) || len(b[*n:]) < 4 {
		return 0, nil
	}
	return readInt32(b, n, e)
}

// unmarshalRecordOrHole handles one length-prefixed record at n: a negative
// length marks a hole left by a deleted entry and a positive length an entry
// record. n advances past the record.
func (kt *Keytab) unmarshalRecordOrHole(b []byte, n *int, l int32) error {
	if l < 0 {
		skip, err := holeLength(b, *n, l)
		if err != nil {
			return err
		}
		*n += skip
		return nil
	}
	return kt.unmarshalRecord(b, n, l)
}

// holeLength validates a negative record length at offset n-4 and returns the
// number of hole bytes to skip after the length field ending at n.
func holeLength(b []byte, n int, l int32) (int, error) {
	if l == -1<<31 {
		return 0, fmt.Errorf("invalid keytab hole length at offset %d", n-4)
	}
	hole := int(-l)
	if hole > len(b)-n {
		return 0, fmt.Errorf("keytab hole at offset %d exceeds remaining data", n-4)
	}
	return hole, nil
}

// unmarshalRecord decodes the entry record of length l at n and appends it to
// the keytab. n advances past the record.
func (kt *Keytab) unmarshalRecord(b []byte, n *int, l int32) error {
	if int(l) > len(b)-*n {
		return fmt.Errorf("keytab record at offset %d has length %d with only %d bytes remaining", *n-4, l, len(b)-*n)
	}
	entry, err := kt.unmarshalEntry(b[*n:*n+int(l)], *n-4)
	if err != nil {
		return err
	}
	*n += int(l)
	// Add the entry to the keytab
	kt.Entries = append(kt.Entries, entry)
	return nil
}

// unmarshalEntry decodes one record body into an Entry. offset is the
// record's position within the keytab, used only for error context.
func (kt *Keytab) unmarshalEntry(eb []byte, offset int) (Entry, error) {
	ke := newEntry()
	// p keeps track as to where we are in the byte stream
	var p int
	principal, err := parsePrincipal(eb, &p, kt.version, &kt.byteOrder)
	if err != nil {
		return Entry{}, fmt.Errorf("invalid principal in keytab record at offset %d: %w", offset, err)
	}
	ke.Principal = principal
	ke.Timestamp, err = readTimestamp(eb, &p, &kt.byteOrder)
	if err != nil {
		return Entry{}, err
	}
	kvno8, err := readEntryKey(eb, &p, &ke, &kt.byteOrder)
	if err != nil {
		return Entry{}, err
	}
	if kerr := readEntryKVNO(eb, &p, &ke, &kt.byteOrder); kerr != nil {
		return Entry{}, kerr
	}
	if ke.KVNO == 0 {
		ke.KVNO = uint32(kvno8)
	}
	return ke, nil
}

// readEntryKey decodes the eight bit key version, enctype, and key bytes of an
// entry, returning the eight bit key version for KVNO fallback.
func readEntryKey(b []byte, p *int, ke *Entry, e *binary.ByteOrder) (uint8, error) {
	kvno8, err := readUint8(b, p)
	if err != nil {
		return 0, err
	}
	keyType, err := readInt16(b, p, e)
	if err != nil {
		return 0, err
	}
	ke.Key.KeyType = int32(keyType)
	keyValue, err := readSizedBytes(b, p, e)
	if err != nil {
		return 0, err
	}
	ke.Key.KeyValue = keyValue
	return kvno8, nil
}

// readEntryKVNO applies the optional 32-bit key version trailer: if at least 4
// bytes are left after the other fields are read and they are non-zero this
// indicates the 32-bit version is present and overrides the 8-bit key version.
func readEntryKVNO(b []byte, p *int, ke *Entry, e *binary.ByteOrder) error {
	if len(b)-*p < 4 {
		return nil
	}
	// The 32-bit key version may be present
	kvno, err := readUint32(b, p, e)
	if err != nil {
		return err
	}
	if kvno != 0 {
		ke.KVNO = kvno
		ke.kvno32Present = true
	}
	return nil
}

func (e Entry) marshal(v int, endian binary.ByteOrder) ([]byte, error) {
	var b []byte
	pb, err := e.Principal.marshal(v, endian)
	if err != nil {
		return b, err
	}
	b = append(b, pb...)

	t := make([]byte, 9)
	endian.PutUint32(t[0:4], uint32(e.Timestamp.Unix()))
	t[4] = byte(e.KVNO)
	endian.PutUint16(t[5:7], uint16(e.Key.KeyType))
	endian.PutUint16(t[7:9], uint16(len(e.Key.KeyValue)))
	b = append(b, t...)

	buf := new(bytes.Buffer)
	err = binary.Write(buf, endian, e.Key.KeyValue)
	if err != nil {
		return b, err
	}
	b = append(b, buf.Bytes()...)

	if v == 2 || e.kvno32Present || e.KVNO > 255 {
		t = make([]byte, 4)
		endian.PutUint32(t, e.KVNO)
		b = append(b, t...)
	}

	// Add the length header
	t = make([]byte, 4)
	endian.PutUint32(t, uint32(len(b)))
	b = append(t, b...)
	return b, nil
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, version uint8, e *binary.ByteOrder) (Principal, error) {
	principal := newPrincipal()
	componentCount, err := readInt16(b, p, e)
	if err != nil {
		return Principal{}, err
	}
	if version == 1 {
		// In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		componentCount--
	}
	if componentCount <= 0 {
		return Principal{}, fmt.Errorf("principal component count must be positive: %d", componentCount)
	}
	realm, err := readSizedBytes(b, p, e)
	if err != nil {
		return Principal{}, err
	}
	principal.Realm = string(realm)
	for i := 0; i < int(componentCount); i++ {
		component, cerr := readSizedBytes(b, p, e)
		if cerr != nil {
			return Principal{}, cerr
		}
		principal.Components = append(principal.Components, string(component))
	}
	if version != 1 {
		// Name Type is omitted in version 1
		principal.NameType, err = readInt32(b, p, e)
		if err != nil {
			return Principal{}, err
		}
	}
	return principal, nil
}

func (p Principal) marshal(v int, endian binary.ByteOrder) ([]byte, error) {
	b := make([]byte, 2)
	componentCount := len(p.Components)
	if v == 1 {
		componentCount++
	}
	endian.PutUint16(b[0:], uint16(componentCount))
	realm, err := marshalString(p.Realm, endian)
	if err != nil {
		return b, err
	}
	b = append(b, realm...)
	for _, c := range p.Components {
		cb, err := marshalString(c, endian)
		if err != nil {
			return b, err
		}
		b = append(b, cb...)
	}
	if v != 1 {
		t := make([]byte, 4)
		endian.PutUint32(t, uint32(p.NameType))
		b = append(b, t...)
	}
	return b, nil
}

func marshalString(s string, endian binary.ByteOrder) ([]byte, error) {
	sb := []byte(s)
	b := make([]byte, 2)
	endian.PutUint16(b[0:], uint16(len(sb)))
	buf := new(bytes.Buffer)
	err := binary.Write(buf, endian, sb)
	if err != nil {
		return b, err
	}
	b = append(b, buf.Bytes()...)
	return b, err
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e *binary.ByteOrder) (time.Time, error) {
	i32, err := readInt32(b, p, e)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(i32), 0), nil
}

// Read bytes representing an eight bit unsigned integer.
func readUint8(b []byte, p *int) (uint8, error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 1) > len(b) {
		return 0, fmt.Errorf("need 1 byte at offset %d, input length is %d", *p, len(b))
	}
	i := b[*p]
	*p++
	return i, nil
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (i int16, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 2) > len(b) {
		return 0, fmt.Errorf("need 2 bytes at offset %d, input length is %d", *p, len(b))
	}

	i = int16((*e).Uint16(b[*p : *p+2]))
	*p += 2
	return
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e *binary.ByteOrder) (i int32, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 4) > len(b) {
		return 0, fmt.Errorf("need 4 bytes at offset %d, input length is %d", *p, len(b))
	}

	i = int32((*e).Uint32(b[*p : *p+4]))
	*p += 4
	return
}

// Read bytes representing a thirty two bit unsigned integer.
func readUint32(b []byte, p *int, e *binary.ByteOrder) (uint32, error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 4) > len(b) {
		return 0, fmt.Errorf("need 4 bytes at offset %d, input length is %d", *p, len(b))
	}

	i := (*e).Uint32(b[*p : *p+4])
	*p += 4
	return i, nil
}

func readBytes(b []byte, p *int, s int, e *binary.ByteOrder) ([]byte, error) {
	if *p < 0 {
		return nil, fmt.Errorf("%d cannot be less than zero", *p)
	}
	if s < 0 {
		return nil, fmt.Errorf("%d cannot be less than zero", s)
	}
	if s > len(b)-*p {
		return nil, fmt.Errorf("need %d bytes at offset %d, input length is %d", s, *p, len(b))
	}
	i := *p + s
	buf := bytes.NewBuffer(b[*p:i])
	r := make([]byte, s)
	if err := binary.Read(buf, *e, &r); err != nil {
		return nil, err
	}
	*p += s
	return r, nil
}

// Read a sixteen bit length followed by that many bytes.
func readSizedBytes(b []byte, p *int, e *binary.ByteOrder) ([]byte, error) {
	l, err := readInt16(b, p, e)
	if err != nil {
		return nil, err
	}
	return readBytes(b, p, int(l), e)
}

func isNativeEndianLittle() bool {
	x := 0x012345678
	p := unsafe.Pointer(&x)
	bp := (*[4]byte)(p)

	switch {
	case bp[0] == 0x01:
		return false
	case bp[0]&0xff == 0x78&0xff:
		return true
	default:
		// Default to big endian
		return false
	}
}

func nativeByteOrder() binary.ByteOrder {
	if isNativeEndianLittle() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func validRecordLength(b []byte, endian binary.ByteOrder, remaining int) bool {
	l := int32(endian.Uint32(b))
	if l == 0 {
		return true
	}
	if l == -1<<31 {
		return false
	}
	if l < 0 {
		l = -l
	}
	return int64(l) <= int64(remaining)
}

// JSON returns information about the keys held in the keytab in a JSON format.
// The output contains raw key material and must not be logged or disclosed.
func (kt *Keytab) JSON() (string, error) {
	b, err := json.MarshalIndent(kt, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
