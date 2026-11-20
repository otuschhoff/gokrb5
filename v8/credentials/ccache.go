package credentials

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	ccacheMagic             = 5
	ccacheVersion1          = 1
	ccacheVersion2          = 2
	ccacheVersion3          = 3
	ccacheVersion4          = 4
	ccacheVersionSize       = 2
	ccacheUint16Size        = 2
	ccacheInt32Size         = 4
	ccacheTicketFlagsSize   = 4
	ccacheTypedDataMinSize  = ccacheUint16Size + ccacheInt32Size
	headerFieldTagKDCOffset = 1
	headerKDCOffsetSize     = 2 * ccacheInt32Size
)

// CCache is a FILE credentials cache.
// See https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html.
type CCache struct {
	Version          uint8
	Header           header
	DefaultPrincipal Principal
	Credentials      []*Credential
	Path             string
}

type header struct {
	length uint16
	fields []headerField
}

type headerField struct {
	tag    uint16
	length uint16
	value  []byte
}

// Principal is a credential cache principal.
type Principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

// Deprecated: use Principal.
type principal = Principal

// Credential holds a Kerberos client's ccache credential information.
type Credential struct {
	Client       principal
	Server       principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// LoadCCache reads a FILE credential cache. File read errors wrap the underlying filesystem error.
func LoadCCache(cpath string) (*CCache, error) {
	path, err := resolveCCacheName(cpath)
	if err != nil {
		return new(CCache), err
	}
	c := new(CCache)
	b, err := os.ReadFile(path) // #nosec G304 -- path is an explicit API/test/config input, not request-derived traversal.
	if err != nil {
		return c, fmt.Errorf("read credential cache file: %w", err)
	}
	err = c.Unmarshal(b)
	if err == nil {
		c.Path = path
	}
	return c, err
}

// Unmarshal a byte slice of credential cache data into CCache type.
func (c *CCache) Unmarshal(b []byte) error {
	var emptyHeader header
	var emptyPrincipal Principal
	c.Header = emptyHeader
	c.DefaultPrincipal = emptyPrincipal
	c.Credentials = nil
	endian, err := c.parseVersion(b)
	if err != nil {
		return err
	}
	p := ccacheVersionSize
	if c.Version == ccacheVersion4 {
		if headerErr := parseHeader(b, &p, c, &endian); headerErr != nil {
			return headerErr
		}
	}
	defaultPrincipal, err := parsePrincipal(b, &p, c, &endian)
	if err != nil {
		return fmt.Errorf("invalid default principal: %w", err)
	}
	c.DefaultPrincipal = defaultPrincipal
	for p < len(b) {
		cred, err := parseCredential(b, &p, c, &endian)
		if err != nil {
			return err
		}
		c.Credentials = append(c.Credentials, cred)
	}
	return nil
}

func parseHeader(b []byte, p *int, c *CCache, e *binary.ByteOrder) error {
	if c.Version != ccacheVersion4 {
		//nolint:revive,staticcheck // Preserve the established error text.
		return errors.New("Credentials cache version is not 4 so there is no header to parse.")
	}
	length, err := readUint16(b, p, *e)
	if err != nil {
		return err
	}
	end := *p + int(length)
	if end < *p || end > len(b) {
		return fmt.Errorf("credential cache header length %d exceeds remaining input", length)
	}
	h := header{length: length, fields: nil}
	for *p < end {
		f, err := readHeaderField(b, p, end, *e)
		if err != nil {
			return err
		}
		h.fields = append(h.fields, f)
	}
	c.Header = h
	return nil
}

func readHeaderField(b []byte, p *int, end int, e binary.ByteOrder) (headerField, error) {
	var f headerField
	tag, err := readUint16(b, p, e)
	if err != nil {
		return f, err
	}
	length, err := readUint16(b, p, e)
	if err != nil {
		return f, err
	}
	value, err := readBytes(b, p, int(length))
	if err != nil || *p > end {
		return f, errors.New("invalid credential cache header field length")
	}
	f = headerField{tag: tag, length: length, value: value}
	if f.tag == headerFieldTagKDCOffset && !f.valid() {
		return f, errors.New("invalid credential cache KDC offset header")
	}
	return f, nil
}

func parsePrincipal(b []byte, p *int, c *CCache, e *binary.ByteOrder) (Principal, error) {
	var princ Principal
	var err error
	if c.Version != ccacheVersion1 {
		// Name Type is omitted in version 1
		princ.PrincipalName.NameType, err = readInt32(b, p, *e)
		if err != nil {
			return Principal{}, err
		}
	}
	componentCount, err := readInt32(b, p, *e)
	if err != nil {
		return Principal{}, err
	}
	nc := int(componentCount)
	if c.Version == ccacheVersion1 {
		// In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		nc--
	}
	if nc < 0 || nc > (len(b)-*p)/ccacheInt32Size {
		return Principal{}, fmt.Errorf("invalid principal component count %d", nc)
	}
	realm, err := readData(b, p, *e)
	if err != nil {
		return Principal{}, err
	}
	princ.Realm = string(realm)
	for i := 0; i < nc; i++ {
		component, err := readData(b, p, *e)
		if err != nil {
			return Principal{}, err
		}
		princ.PrincipalName.NameString = append(princ.PrincipalName.NameString, string(component))
	}
	return princ, nil
}

func parseCredential(b []byte, p *int, c *CCache, e *binary.ByteOrder) (*Credential, error) {
	cred := new(Credential)
	var err error
	cred.Client, err = parsePrincipal(b, p, c, e)
	if err != nil {
		return nil, err
	}
	cred.Server, err = parsePrincipal(b, p, c, e)
	if err != nil {
		return nil, err
	}
	if cred.Key, err = readCredentialKey(b, p, c.Version, *e); err != nil {
		return nil, err
	}
	if err = readCredentialTimesAndFlags(b, p, *e, cred); err != nil {
		return nil, err
	}
	if cred.Addresses, err = readAddresses(b, p, *e); err != nil {
		return nil, err
	}
	if cred.AuthData, err = readAuthorizationData(b, p, *e); err != nil {
		return nil, err
	}
	if cred.Ticket, err = readData(b, p, *e); err != nil {
		return nil, err
	}
	if cred.SecondTicket, err = readData(b, p, *e); err != nil {
		return nil, err
	}
	return cred, nil
}

func readCredentialKey(b []byte, p *int, version uint8, e binary.ByteOrder) (types.EncryptionKey, error) {
	var key types.EncryptionKey
	keyType, err := readUint16(b, p, e)
	if err != nil {
		return key, err
	}
	if version == ccacheVersion3 {
		repeatedKeyType, repeatErr := readUint16(b, p, e)
		if repeatErr != nil {
			return key, repeatErr
		}
		if repeatedKeyType != keyType {
			return key, errors.New("invalid version 3 credential cache key type")
		}
	}
	key.KeyType = int32(keyType)
	key.KeyValue, err = readData(b, p, e)
	return key, err
}

func readCredentialTimesAndFlags(b []byte, p *int, e binary.ByteOrder, cred *Credential) error {
	for _, timestamp := range []*time.Time{&cred.AuthTime, &cred.StartTime, &cred.EndTime, &cred.RenewTill} {
		value, err := readTimestamp(b, p, e)
		if err != nil {
			return err
		}
		*timestamp = value
	}
	isSKey, err := readUint8(b, p)
	if err != nil {
		return err
	}
	cred.IsSKey = isSKey != 0
	cred.TicketFlags = types.NewKrbFlags()
	cred.TicketFlags.Bytes, err = readBytes(b, p, ccacheTicketFlagsSize)
	return err
}

func readAddresses(b []byte, p *int, e binary.ByteOrder) ([]types.HostAddress, error) {
	count, err := readInt32(b, p, e)
	if err != nil || count < 0 || int64(count) > int64(len(b)-*p)/ccacheTypedDataMinSize {
		return nil, errors.New("invalid address count")
	}
	addresses := make([]types.HostAddress, int(count))
	for i := range addresses {
		addresses[i], err = readAddress(b, p, e)
		if err != nil {
			return nil, err
		}
	}
	return addresses, nil
}

func readAuthorizationData(b []byte, p *int, e binary.ByteOrder) ([]types.AuthorizationDataEntry, error) {
	count, err := readInt32(b, p, e)
	if err != nil || count < 0 || int64(count) > int64(len(b)-*p)/ccacheTypedDataMinSize {
		return nil, errors.New("invalid authorization data count")
	}
	authData := make([]types.AuthorizationDataEntry, int(count))
	for i := range authData {
		authData[i], err = readAuthDataEntry(b, p, e)
		if err != nil {
			return nil, err
		}
	}
	return authData, nil
}

// GetClientPrincipalName returns a PrincipalName type for the client the credentials cache is for.
func (c *CCache) GetClientPrincipalName() types.PrincipalName {
	if c == nil {
		var name types.PrincipalName
		return name
	}
	return c.DefaultPrincipal.PrincipalName
}

// GetClientRealm returns the reals of the client the credentials cache is for.
func (c *CCache) GetClientRealm() string {
	if c == nil {
		return ""
	}
	return c.DefaultPrincipal.Realm
}

// GetClientCredentials returns a Credentials object representing the client of the credentials cache.
func (c *CCache) GetClientCredentials() *Credentials {
	creds := new(Credentials)
	if c != nil {
		creds.username = c.DefaultPrincipal.PrincipalName.PrincipalNameString()
		creds.realm = c.GetClientRealm()
		creds.cname = c.DefaultPrincipal.PrincipalName
	}
	return creds
}

// Contains tests if the cache contains a credential for the provided server PrincipalName
func (c *CCache) Contains(p types.PrincipalName) bool {
	if c == nil {
		return false
	}
	for _, cred := range c.Credentials {
		if cred != nil && cred.Server.PrincipalName.Equal(p) {
			return true
		}
	}
	return false
}

// GetEntry returns a specific credential for the PrincipalName provided.
func (c *CCache) GetEntry(p types.PrincipalName) (*Credential, bool) {
	cred := new(Credential)
	if c == nil {
		return cred, false
	}
	var found bool
	for i := range c.Credentials {
		if c.Credentials[i] != nil && c.Credentials[i].Server.PrincipalName.Equal(p) {
			cred = c.Credentials[i]
			found = true
			break
		}
	}
	if !found {
		return cred, false
	}
	return cred, true
}

// GetEntries filters out configuration entries an returns a slice of credentials.
func (c *CCache) GetEntries() []*Credential {
	creds := make([]*Credential, 0)
	if c == nil {
		return creds
	}
	for _, cred := range c.Credentials {
		if cred == nil {
			continue
		}
		// Filter out configuration entries
		if strings.HasPrefix(cred.Server.Realm, "X-CACHECONF") {
			continue
		}
		creds = append(creds, cred)
	}
	return creds
}

func (c *CCache) parseVersion(b []byte) (binary.ByteOrder, error) {
	if len(b) < ccacheVersionSize {
		return nil, fmt.Errorf("credential cache is shorter than the 2-byte version header: %d", len(b))
	}
	if b[0] != ccacheMagic {
		//nolint:staticcheck // Preserve the established error text.
		return nil, errors.New("Invalid credential cache data. First byte does not equal 5")
	}
	c.Version = b[1]
	switch c.Version {
	case ccacheVersion1, ccacheVersion2:
		return binary.NativeEndian, nil
	case ccacheVersion3, ccacheVersion4:
		return binary.BigEndian, nil
	default:
		//nolint:staticcheck // Preserve the established error text, including "Keytab".
		return nil, errors.New("Invalid credential cache data. Keytab version is not within 1 to 4")
	}
}

func (h *headerField) valid() bool {
	// See https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html - Header format
	if h.tag != headerFieldTagKDCOffset {
		return false
	}
	return h.length == headerKDCOffsetSize && len(h.value) == headerKDCOffsetSize
}

func readData(b []byte, p *int, e binary.ByteOrder) ([]byte, error) {
	l, err := readInt32(b, p, e)
	if err != nil || l < 0 {
		return nil, errors.New("invalid data length")
	}
	return readBytes(b, p, int(l))
}

func readAddress(b []byte, p *int, e binary.ByteOrder) (types.HostAddress, error) {
	var a types.HostAddress
	t, err := readUint16(b, p, e)
	if err != nil {
		return a, err
	}
	a.AddrType = int32(t)
	a.Address, err = readData(b, p, e)
	return a, err
}

func readAuthDataEntry(b []byte, p *int, e binary.ByteOrder) (types.AuthorizationDataEntry, error) {
	var a types.AuthorizationDataEntry
	t, err := readUint16(b, p, e)
	if err != nil {
		return a, err
	}
	a.ADType = int32(t)
	a.ADData, err = readData(b, p, e)
	return a, err
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e binary.ByteOrder) (time.Time, error) {
	seconds, err := readInt32(b, p, e)
	return time.Unix(int64(seconds), 0), err
}

// Read bytes representing an eight bit integer.
func readUint8(b []byte, p *int) (uint8, error) {
	if *p < 0 || *p >= len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := b[*p]
	*p++
	return v, nil
}

// Read bytes representing a sixteen bit integer.
func readUint16(b []byte, p *int, e binary.ByteOrder) (uint16, error) {
	if *p < 0 || len(b)-*p < ccacheUint16Size {
		return 0, io.ErrUnexpectedEOF
	}
	v := e.Uint16(b[*p : *p+ccacheUint16Size])
	*p += ccacheUint16Size
	return v, nil
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e binary.ByteOrder) (int32, error) {
	if *p < 0 || len(b)-*p < ccacheInt32Size {
		return 0, io.ErrUnexpectedEOF
	}
	var value int32
	if err := binary.Read(bytes.NewReader(b[*p:*p+ccacheInt32Size]), e, &value); err != nil {
		return 0, fmt.Errorf("read credential cache int32: %w", err)
	}
	*p += ccacheInt32Size
	return value, nil
}

func readBytes(b []byte, p *int, size int) ([]byte, error) {
	if size < 0 || *p < 0 || size > len(b)-*p {
		return nil, io.ErrUnexpectedEOF
	}
	r := append([]byte(nil), b[*p:*p+size]...)
	*p += size
	return r, nil
}
