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

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	keytabFirstByte byte = 05
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

// Deprecated: use Entry.
type entry = Entry

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

// Deprecated: use Principal.
type principal = Principal

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
	var p Principal
	var part strings.Builder
	inRealm := false
	escaped := false
	firstEnterpriseAt := true
	unescapedAts := 0
	for _, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
		} else if r == '@' {
			unescapedAts++
		}
	}
	if unescapedAts > 2 {
		return Principal{}, errors.New("principal contains too many realm separators")
	}
	enterprise := unescapedAts == 2
	escaped = false

	appendPart := func() error {
		if part.Len() == 0 {
			return errors.New("principal contains an empty component")
		}
		p.Components = append(p.Components, part.String())
		part.Reset()
		return nil
	}

	for _, r := range s {
		if escaped {
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
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '@' {
			if enterprise && firstEnterpriseAt {
				part.WriteByte('@')
				firstEnterpriseAt = false
				continue
			}
			if inRealm {
				return Principal{}, errors.New("principal contains multiple realm separators")
			}
			if err := appendPart(); err != nil {
				return Principal{}, err
			}
			inRealm = true
			continue
		}
		if r == '/' && !enterprise {
			if inRealm {
				return Principal{}, errors.New("realm contains an unescaped component separator")
			}
			if err := appendPart(); err != nil {
				return Principal{}, err
			}
			continue
		}
		part.WriteRune(r)
	}
	if escaped {
		return Principal{}, errors.New("principal ends with an incomplete escape")
	}
	if part.Len() == 0 {
		if inRealm {
			return Principal{}, errors.New("principal contains an empty realm")
		}
		return Principal{}, errors.New("principal contains an empty component")
	}
	if inRealm {
		p.Realm = part.String()
	} else {
		p.Components = append(p.Components, part.String())
	}
	if enterprise {
		p.NameType = nametype.KRB_NT_ENTERPRISE
	} else {
		p.NameType = nametype.KRB_NT_PRINCIPAL
	}
	return p, nil
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
			if principalMatches(entry.Principal, p) && entry.Principal.Realm == p.Realm {
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
	var exact Entry
	var fallback Entry
	var exactFound bool
	var fallbackFound bool
	var principalAndETypeFound bool

	for _, candidate := range kt.Entries {
		if !principalMatches(candidate.Principal, p) || etype != 0 && candidate.Key.KeyType != etype {
			continue
		}
		principalAndETypeFound = true

		if kvno == 0 {
			if !exactFound || candidate.KVNO > exact.KVNO || candidate.KVNO == exact.KVNO && candidate.Timestamp.After(exact.Timestamp) {
				exact = candidate
				exactFound = true
			}
			continue
		}
		if candidate.KVNO == kvno {
			if !exactFound || candidate.Timestamp.After(exact.Timestamp) {
				exact = candidate
				exactFound = true
			}
			continue
		}
		if kvno > 255 && !candidate.kvno32Present && candidate.KVNO == kvno&0xff {
			if !fallbackFound || candidate.Timestamp.After(fallback.Timestamp) {
				fallback = candidate
				fallbackFound = true
			}
		}
	}

	if exactFound {
		return exact, nil
	}
	if fallbackFound {
		return fallback, nil
	}
	if principalAndETypeFound && kvno != 0 {
		return Entry{}, fmt.Errorf("%w: principal %q, kvno %d, enctype %d", ErrKVNONotFound, p.String(), kvno, etype)
	}
	return Entry{}, fmt.Errorf("%w: principal %q, enctype %d", ErrNotFound, p.String(), etype)
}

func principalMatches(candidate, requested Principal) bool {
	if requested.Realm != "" && candidate.Realm != requested.Realm {
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
		return fmt.Errorf("error deriving key from string: %v", err)
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
	if len(key.KeyValue) != et.GetKeyByteSize() {
		return fmt.Errorf("invalid key length %d for enctype %d: expected %d", len(key.KeyValue), key.KeyType, et.GetKeyByteSize())
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
		return 0, fmt.Errorf("error marshaling keytab: %v", err)
	}
	return w.Write(b)
}

// Unmarshal byte slice of Keytab data into Keytab type.
func (kt *Keytab) Unmarshal(b []byte) error {
	kt.Entries = nil
	if len(b) < 2 {
		return fmt.Errorf("byte array is less than 2 bytes: %d", len(b))
	}

	//The first byte of the file always has the value 5
	if b[0] != keytabFirstByte {
		return errors.New("invalid keytab data. First byte does not equal 5")
	}
	//Get keytab version
	//The 2nd byte contains the version number (1 or 2)
	kt.version = b[1]
	if kt.version != 1 && kt.version != 2 {
		return errors.New("invalid keytab data. Keytab version is neither 1 nor 2")
	}
	//Version 1 of the file format uses native byte order for integer representations. Version 2 always uses big-endian byte order
	var endian binary.ByteOrder = binary.BigEndian
	if kt.version == 1 {
		endian = nativeByteOrder()
		if len(b) >= 6 && !validRecordLength(b[2:6], endian, len(b)-6) {
			other := binary.ByteOrder(binary.BigEndian)
			if endian == binary.BigEndian {
				other = binary.LittleEndian
			}
			if validRecordLength(b[2:6], other, len(b)-6) {
				endian = other
			}
		}
	}
	kt.byteOrder = endian
	if len(b) == 2 {
		return nil
	}
	// n tracks position in the byte array
	n := 2
	l, err := readInt32(b, &n, &endian)
	if err != nil {
		return err
	}
	for l != 0 {
		if l < 0 {
			if l == -1<<31 {
				return fmt.Errorf("invalid keytab hole length at offset %d", n-4)
			}
			holeLength := int(-l)
			if holeLength > len(b)-n {
				return fmt.Errorf("keytab hole at offset %d exceeds remaining data", n-4)
			}
			n += holeLength
		} else {
			if int(l) > len(b)-n {
				return fmt.Errorf("keytab record at offset %d has length %d with only %d bytes remaining", n-4, l, len(b)-n)
			}
			eb := b[n : n+int(l)]
			n = n + int(l)
			ke := newEntry()
			// p keeps track as to where we are in the byte stream
			var p int
			if err := parsePrincipal(eb, &p, kt, &ke, &endian); err != nil {
				return fmt.Errorf("invalid principal in keytab record at offset %d: %v", n-int(l)-4, err)
			}
			var err error
			ke.Timestamp, err = readTimestamp(eb, &p, &endian)
			if err != nil {
				return err
			}
			rei8, err := readInt8(eb, &p, &endian)
			if err != nil {
				return err
			}
			kvno8 := uint8(rei8)
			rei16, err := readInt16(eb, &p, &endian)
			if err != nil {
				return err
			}
			ke.Key.KeyType = int32(rei16)
			rei16, err = readInt16(eb, &p, &endian)
			if err != nil {
				return err
			}
			kl := int(rei16)
			ke.Key.KeyValue, err = readBytes(eb, &p, kl, &endian)
			if err != nil {
				return err
			}
			// The 32-bit key version overrides the 8-bit key version.
			// If at least 4 bytes are left after the other fields are read and they are non-zero
			// this indicates the 32-bit version is present.
			if len(eb)-p >= 4 {
				// The 32-bit key may be present
				ri32, err := readInt32(eb, &p, &endian)
				if err != nil {
					return err
				}
				if ri32 != 0 {
					ke.KVNO = uint32(ri32)
					ke.kvno32Present = true
				}
			}
			if ke.KVNO == 0 {
				ke.KVNO = uint32(kvno8)
			}
			// Add the entry to the keytab
			kt.Entries = append(kt.Entries, ke)
		}
		// Check if there are still 4 bytes left to read
		// Also check that n is greater than zero
		if n < 0 || n > len(b) || len(b[n:]) < 4 {
			break
		}
		// Read the size of the next entry
		l, err = readInt32(b, &n, &endian)
		if err != nil {
			return err
		}
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
func parsePrincipal(b []byte, p *int, kt *Keytab, ke *entry, e *binary.ByteOrder) error {
	componentCount, err := readInt16(b, p, e)
	if err != nil {
		return err
	}
	if kt.version == 1 {
		//In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		componentCount--
	}
	if componentCount <= 0 {
		return fmt.Errorf("principal component count must be positive: %d", componentCount)
	}
	lenRealm, err := readInt16(b, p, e)
	if err != nil {
		return err
	}
	realmB, err := readBytes(b, p, int(lenRealm), e)
	if err != nil {
		return err
	}
	ke.Principal.Realm = string(realmB)
	for i := 0; i < int(componentCount); i++ {
		l, err := readInt16(b, p, e)
		if err != nil {
			return err
		}
		compB, err := readBytes(b, p, int(l), e)
		if err != nil {
			return err
		}
		ke.Principal.Components = append(ke.Principal.Components, string(compB))
	}
	if kt.version != 1 {
		//Name Type is omitted in version 1
		ke.Principal.NameType, err = readInt32(b, p, e)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p Principal) marshal(v int, endian binary.ByteOrder) ([]byte, error) {
	//var b []byte
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

// Read bytes representing an eight bit integer.
func readInt8(b []byte, p *int, e *binary.ByteOrder) (i int8, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 1) > len(b) {
		return 0, fmt.Errorf("need 1 byte at offset %d, input length is %d", *p, len(b))
	}
	buf := bytes.NewBuffer(b[*p : *p+1])
	binary.Read(buf, *e, &i)
	*p++
	return
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (i int16, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 2) > len(b) {
		return 0, fmt.Errorf("need 2 bytes at offset %d, input length is %d", *p, len(b))
	}

	buf := bytes.NewBuffer(b[*p : *p+2])
	binary.Read(buf, *e, &i)
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

	buf := bytes.NewBuffer(b[*p : *p+4])
	binary.Read(buf, *e, &i)
	*p += 4
	return
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

func isNativeEndianLittle() bool {
	var x = 0x012345678
	var p = unsafe.Pointer(&x)
	var bp = (*[4]byte)(p)

	var endian bool
	if 0x01 == bp[0] {
		endian = false
	} else if (0x78 & 0xff) == (bp[0] & 0xff) {
		endian = true
	} else {
		// Default to big endian
		endian = false
	}
	return endian
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

// JSON return information about the keys held in the keytab in a JSON format.
func (kt *Keytab) JSON() (string, error) {
	b, err := json.MarshalIndent(kt, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
