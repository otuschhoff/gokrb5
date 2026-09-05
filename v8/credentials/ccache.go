package credentials

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	headerFieldTagKDCOffset = 1
)

// CCache is the file credentials cache as define here: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
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

// LoadCCache loads a credential cache file into a CCache type.
func LoadCCache(cpath string) (*CCache, error) {
	path, err := resolveCCacheName(cpath)
	if err != nil {
		return new(CCache), err
	}
	c := new(CCache)
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = c.Unmarshal(b)
	if err == nil {
		c.Path = path
	}
	return c, err
}

// Unmarshal a byte slice of credential cache data into CCache type.
func (c *CCache) Unmarshal(b []byte) error {
	c.Header = header{}
	c.DefaultPrincipal = Principal{}
	c.Credentials = nil
	if len(b) < 2 {
		return fmt.Errorf("credential cache is shorter than the 2-byte version header: %d", len(b))
	}
	p := 0
	//The first byte of the file always has the value 5
	if int8(b[p]) != 5 {
		return errors.New("Invalid credential cache data. First byte does not equal 5")
	}
	p++
	//Get credential cache version
	//The second byte contains the version number (1 to 4)
	c.Version = b[p]
	if c.Version < 1 || c.Version > 4 {
		return errors.New("Invalid credential cache data. Keytab version is not within 1 to 4")
	}
	p++
	//Version 1 or 2 of the file format uses native byte order for integer representations. Versions 3 & 4 always uses big-endian byte order
	var endian binary.ByteOrder
	endian = binary.BigEndian
	if (c.Version == 1 || c.Version == 2) && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}
	if c.Version == 4 {
		err := parseHeader(b, &p, c, &endian)
		if err != nil {
			return err
		}
	}
	defaultPrincipal, err := parsePrincipal(b, &p, c, &endian)
	if err != nil {
		return fmt.Errorf("invalid default principal: %v", err)
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
	if c.Version != 4 {
		return errors.New("Credentials cache version is not 4 so there is no header to parse.")
	}
	h := header{}
	length, err := readUint16(b, p, *e)
	if err != nil {
		return err
	}
	h.length = length
	end := *p + int(h.length)
	if end < *p || end > len(b) {
		return fmt.Errorf("credential cache header length %d exceeds remaining input", h.length)
	}
	for *p < end {
		f := headerField{}
		f.tag, err = readUint16(b, p, *e)
		if err != nil {
			return err
		}
		f.length, err = readUint16(b, p, *e)
		if err != nil {
			return err
		}
		f.value, err = readBytes(b, p, int(f.length))
		if err != nil || *p > end {
			return errors.New("invalid credential cache header field length")
		}
		if f.tag == headerFieldTagKDCOffset && !f.valid() {
			return errors.New("invalid credential cache KDC offset header")
		}
		h.fields = append(h.fields, f)
	}
	c.Header = h
	return nil
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, c *CCache, e *binary.ByteOrder) (Principal, error) {
	var princ Principal
	var err error
	if c.Version != 1 {
		//Name Type is omitted in version 1
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
	if c.Version == 1 {
		//In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		nc--
	}
	if nc < 0 || nc > (len(b)-*p)/4 {
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

func parseCredential(b []byte, p *int, c *CCache, e *binary.ByteOrder) (cred *Credential, err error) {
	cred = new(Credential)
	cred.Client, err = parsePrincipal(b, p, c, e)
	if err != nil {
		return nil, err
	}
	cred.Server, err = parsePrincipal(b, p, c, e)
	if err != nil {
		return nil, err
	}
	key := types.EncryptionKey{}
	keyType, err := readUint16(b, p, *e)
	if err != nil {
		return nil, err
	}
	key.KeyType = int32(keyType)
	if c.Version == 3 {
		//repeated twice in version 3
		repeatedKeyType, err := readUint16(b, p, *e)
		if err != nil {
			return nil, err
		}
		if repeatedKeyType != keyType {
			return nil, errors.New("invalid version 3 credential cache key type")
		}
	}
	key.KeyValue, err = readData(b, p, *e)
	if err != nil {
		return nil, err
	}
	cred.Key = key
	if cred.AuthTime, err = readTimestamp(b, p, *e); err != nil {
		return nil, err
	}
	if cred.StartTime, err = readTimestamp(b, p, *e); err != nil {
		return nil, err
	}
	if cred.EndTime, err = readTimestamp(b, p, *e); err != nil {
		return nil, err
	}
	if cred.RenewTill, err = readTimestamp(b, p, *e); err != nil {
		return nil, err
	}
	ik, err := readUint8(b, p)
	if err != nil {
		return nil, err
	}
	if ik == 0 {
		cred.IsSKey = false
	} else {
		cred.IsSKey = true
	}
	cred.TicketFlags = types.NewKrbFlags()
	cred.TicketFlags.Bytes, err = readBytes(b, p, 4)
	if err != nil {
		return nil, err
	}
	count, err := readInt32(b, p, *e)
	if err != nil || count < 0 || int64(count) > int64(len(b)-*p)/6 {
		return nil, errors.New("invalid address count")
	}
	l := int(count)
	cred.Addresses = make([]types.HostAddress, l)
	for i := range cred.Addresses {
		cred.Addresses[i], err = readAddress(b, p, *e)
		if err != nil {
			return nil, err
		}
	}
	count, err = readInt32(b, p, *e)
	if err != nil || count < 0 || int64(count) > int64(len(b)-*p)/6 {
		return nil, errors.New("invalid authorization data count")
	}
	l = int(count)
	cred.AuthData = make([]types.AuthorizationDataEntry, l)
	for i := range cred.AuthData {
		cred.AuthData[i], err = readAuthDataEntry(b, p, *e)
		if err != nil {
			return nil, err
		}
	}
	cred.Ticket, err = readData(b, p, *e)
	if err != nil {
		return nil, err
	}
	cred.SecondTicket, err = readData(b, p, *e)
	if err != nil {
		return nil, err
	}
	return
}

// GetClientPrincipalName returns a PrincipalName type for the client the credentials cache is for.
func (c *CCache) GetClientPrincipalName() types.PrincipalName {
	return c.DefaultPrincipal.PrincipalName
}

// GetClientRealm returns the reals of the client the credentials cache is for.
func (c *CCache) GetClientRealm() string {
	return c.DefaultPrincipal.Realm
}

// GetClientCredentials returns a Credentials object representing the client of the credentials cache.
func (c *CCache) GetClientCredentials() *Credentials {
	return &Credentials{
		username: c.DefaultPrincipal.PrincipalName.PrincipalNameString(),
		realm:    c.GetClientRealm(),
		cname:    c.DefaultPrincipal.PrincipalName,
	}
}

// Contains tests if the cache contains a credential for the provided server PrincipalName
func (c *CCache) Contains(p types.PrincipalName) bool {
	for _, cred := range c.Credentials {
		if cred.Server.PrincipalName.Equal(p) {
			return true
		}
	}
	return false
}

// GetEntry returns a specific credential for the PrincipalName provided.
func (c *CCache) GetEntry(p types.PrincipalName) (*Credential, bool) {
	cred := new(Credential)
	var found bool
	for i := range c.Credentials {
		if c.Credentials[i].Server.PrincipalName.Equal(p) {
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
	for _, cred := range c.Credentials {
		// Filter out configuration entries
		if strings.HasPrefix(cred.Server.Realm, "X-CACHECONF") {
			continue
		}
		creds = append(creds, cred)
	}
	return creds
}

func (h *headerField) valid() bool {
	// See https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html - Header format
	switch h.tag {
	case headerFieldTagKDCOffset:
		if h.length != 8 || len(h.value) != 8 {
			return false
		}
		return true
	}
	return false
}

func readData(b []byte, p *int, e binary.ByteOrder) ([]byte, error) {
	l, err := readInt32(b, p, e)
	if err != nil || l < 0 {
		return nil, errors.New("invalid data length")
	}
	return readBytes(b, p, int(l))
}

func readAddress(b []byte, p *int, e binary.ByteOrder) (types.HostAddress, error) {
	a := types.HostAddress{}
	t, err := readUint16(b, p, e)
	if err != nil {
		return a, err
	}
	a.AddrType = int32(t)
	a.Address, err = readData(b, p, e)
	return a, err
}

func readAuthDataEntry(b []byte, p *int, e binary.ByteOrder) (types.AuthorizationDataEntry, error) {
	a := types.AuthorizationDataEntry{}
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
	if *p < 0 || len(b)-*p < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	v := e.Uint16(b[*p : *p+2])
	*p += 2
	return v, nil
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e binary.ByteOrder) (int32, error) {
	if *p < 0 || len(b)-*p < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	v := int32(e.Uint32(b[*p : *p+4]))
	*p += 4
	return v, nil
}

func readBytes(b []byte, p *int, size int) ([]byte, error) {
	if size < 0 || *p < 0 || size > len(b)-*p {
		return nil, io.ErrUnexpectedEOF
	}
	r := append([]byte(nil), b[*p:*p+size]...)
	*p += size
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
