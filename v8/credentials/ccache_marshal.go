package credentials

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/internal/fileio"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const configRealm = "X-CACHECONF:"

// NewCCache creates an empty version 4 credential cache.
func NewCCache(defaultPrincipal types.PrincipalName, realm string) *CCache {
	c := &CCache{
		Version: 4,
		DefaultPrincipal: Principal{
			Realm:         realm,
			PrincipalName: clonePrincipalName(defaultPrincipal),
		},
	}
	c.SetKDCTimeOffset(0)
	return c
}

// AddCredential appends cred to the cache.
func (c *CCache) AddCredential(cred *Credential) {
	if cred != nil {
		components := cred.Server.PrincipalName.NameString
		if len(components) == 2 && components[0] == "krbtgt" && !types.RealmEqual(cred.Client.Realm, components[1]) {
			_ = c.SetConfig("start_realm", "", components[1])
		}
		c.Credentials = append(c.Credentials, cred)
	}
}

// SetConfig stores or replaces an X-CACHECONF credential.
func (c *CCache) SetConfig(key, principalName, value string) error {
	if key == "" {
		return errors.New("credential cache config key is empty")
	}
	components := []string{"krb5_ccache_conf_data", key}
	if principalName != "" {
		components = append(components, principalName)
	}
	server := Principal{
		Realm: configRealm,
		PrincipalName: types.PrincipalName{
			NameType:   nametype.KRB_NT_UNKNOWN,
			NameString: components,
		},
	}
	for _, cred := range c.Credentials {
		if configPrincipalEqual(cred.Server, server) {
			cred.Ticket = []byte(value)
			return nil
		}
	}
	flags := types.NewKrbFlags()
	c.Credentials = append(c.Credentials, &Credential{
		Client:      clonePrincipal(c.DefaultPrincipal),
		Server:      server,
		TicketFlags: flags,
		AuthTime:    time.Unix(0, 0),
		StartTime:   time.Unix(0, 0),
		EndTime:     time.Unix(0, 0),
		RenewTill:   time.Unix(0, 0),
		Ticket:      []byte(value),
	})
	return nil
}

// GetConfig retrieves an X-CACHECONF value.
func (c *CCache) GetConfig(key, principalName string) (string, bool) {
	components := []string{"krb5_ccache_conf_data", key}
	if principalName != "" {
		components = append(components, principalName)
	}
	server := Principal{Realm: configRealm, PrincipalName: types.PrincipalName{NameString: components}}
	for _, cred := range c.Credentials {
		if configPrincipalEqual(cred.Server, server) {
			return string(cred.Ticket), true
		}
	}
	return "", false
}

func configPrincipalEqual(a, b Principal) bool {
	if a.Realm != b.Realm || len(a.PrincipalName.NameString) != len(b.PrincipalName.NameString) {
		return false
	}
	for i := range a.PrincipalName.NameString {
		if a.PrincipalName.NameString[i] != b.PrincipalName.NameString[i] {
			return false
		}
	}
	return true
}

// KDCTimeOffset returns the KDC time offset recorded in the cache header.
func (c *CCache) KDCTimeOffset() (time.Duration, bool) {
	for _, field := range c.Header.fields {
		if field.tag == headerFieldTagKDCOffset && len(field.value) == 8 {
			var seconds, microseconds int32
			if err := binary.Read(bytes.NewReader(field.value[:4]), binary.BigEndian, &seconds); err != nil {
				return 0, false
			}
			if err := binary.Read(bytes.NewReader(field.value[4:]), binary.BigEndian, &microseconds); err != nil {
				return 0, false
			}
			return time.Duration(seconds)*time.Second + time.Duration(microseconds)*time.Microsecond, true
		}
	}
	return 0, false
}

// SetKDCTimeOffset stores the KDC time offset with microsecond precision,
// saturating only the seconds component to the cache's signed 32-bit range.
func (c *CCache) SetKDCTimeOffset(offset time.Duration) {
	seconds := offset / time.Second
	microseconds := (offset % time.Second) / time.Microsecond
	value := make([]byte, 8)
	encodedSeconds, err := ccacheInt32("KDC offset seconds", int64(seconds))
	if err != nil {
		if seconds < 0 {
			encodedSeconds = math.MinInt32
		} else {
			encodedSeconds = math.MaxInt32
		}
	}
	encodedMicroseconds, err := ccacheInt32("KDC offset microseconds", int64(microseconds))
	if err != nil {
		encodedMicroseconds = 0
	}
	var encoded bytes.Buffer
	_ = binary.Write(&encoded, binary.BigEndian, encodedSeconds)
	copy(value[:4], encoded.Bytes())
	encoded.Reset()
	_ = binary.Write(&encoded, binary.BigEndian, encodedMicroseconds)
	copy(value[4:], encoded.Bytes())
	for i := range c.Header.fields {
		if c.Header.fields[i].tag == headerFieldTagKDCOffset {
			c.Header.fields[i].length = 8
			c.Header.fields[i].value = value
			return
		}
	}
	c.Header.fields = append(c.Header.fields, headerField{tag: headerFieldTagKDCOffset, length: 8, value: value})
}

// Marshal returns c encoded as a version 3 or version 4 FILE credential cache.
func (c *CCache) Marshal() ([]byte, error) {
	version := c.Version
	if version == 0 {
		version = 4
	}
	if version != 3 && version != 4 {
		return nil, fmt.Errorf("credential cache marshaling supports versions 3 and 4, not %d", version)
	}
	var out bytes.Buffer
	out.Write([]byte{5, version})
	if version == 4 {
		if err := marshalVersion4Header(&out, c.Header); err != nil {
			return nil, err
		}
	}
	if err := marshalPrincipal(&out, c.DefaultPrincipal); err != nil {
		return nil, fmt.Errorf("invalid default principal: %w", err)
	}
	for i, cred := range c.Credentials {
		if cred == nil {
			return nil, fmt.Errorf("credential %d is nil", i)
		}
		if err := marshalCredential(&out, cred, version); err != nil {
			return nil, fmt.Errorf("invalid credential %d: %w", i, err)
		}
	}
	return out.Bytes(), nil
}

func marshalVersion4Header(out *bytes.Buffer, h header) error {
	headerBytes, err := marshalHeader(h)
	if err != nil {
		return err
	}
	headerLength, err := ccacheUint16("header length", int64(len(headerBytes)))
	if err != nil {
		return err
	}
	if err := binary.Write(out, binary.BigEndian, headerLength); err != nil {
		return fmt.Errorf("write credential cache header length: %w", err)
	}
	out.Write(headerBytes)
	return nil
}

func ccacheInt32(name string, value int64) (int32, error) {
	if value < math.MinInt32 || value > math.MaxInt32 {
		return 0, fmt.Errorf("credential cache %s %d exceeds int32 range", name, value)
	}
	return int32(value), nil
}

func ccacheUint16(name string, value int64) (uint16, error) {
	if value < 0 || value > math.MaxUint16 {
		return 0, fmt.Errorf("credential cache %s %d exceeds uint16 range", name, value)
	}
	return uint16(value), nil
}

func marshalHeader(h header) ([]byte, error) {
	var out bytes.Buffer
	for _, field := range h.fields {
		if len(field.value) > math.MaxUint16 {
			return nil, errors.New("credential cache header field is too large")
		}
		if field.tag == headerFieldTagKDCOffset && len(field.value) != 8 {
			return nil, errors.New("invalid credential cache KDC offset header")
		}
		_ = binary.Write(&out, binary.BigEndian, field.tag)
		length, err := ccacheUint16("header field length", int64(len(field.value)))
		if err != nil {
			return nil, err
		}
		_ = binary.Write(&out, binary.BigEndian, length)
		out.Write(field.value)
	}
	if out.Len() > math.MaxUint16 {
		return nil, errors.New("credential cache header is too large")
	}
	return out.Bytes(), nil
}

func marshalPrincipal(out *bytes.Buffer, p Principal) error {
	if len(p.PrincipalName.NameString) > math.MaxInt32 {
		return errors.New("too many principal components")
	}
	_ = binary.Write(out, binary.BigEndian, p.PrincipalName.NameType)
	componentCount, err := ccacheInt32("principal component count", int64(len(p.PrincipalName.NameString)))
	if err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, componentCount)
	if err := marshalData(out, []byte(p.Realm)); err != nil {
		return err
	}
	for _, component := range p.PrincipalName.NameString {
		if err := marshalData(out, []byte(component)); err != nil {
			return err
		}
	}
	return nil
}

func marshalCredential(out *bytes.Buffer, cred *Credential, version uint8) error {
	if err := marshalPrincipal(out, cred.Client); err != nil {
		return err
	}
	if err := marshalPrincipal(out, cred.Server); err != nil {
		return err
	}
	if err := marshalCredentialKey(out, cred, version); err != nil {
		return err
	}
	if err := marshalCredentialTimes(out, cred); err != nil {
		return err
	}
	if cred.IsSKey {
		out.WriteByte(1)
	} else {
		out.WriteByte(0)
	}
	if err := marshalTicketFlags(out, cred.TicketFlags.Bytes); err != nil {
		return err
	}
	if err := marshalCredentialAddresses(out, cred.Addresses); err != nil {
		return err
	}
	if err := marshalCredentialAuthData(out, cred.AuthData); err != nil {
		return err
	}
	if err := marshalData(out, cred.Ticket); err != nil {
		return err
	}
	return marshalData(out, cred.SecondTicket)
}

func marshalCredentialKey(out *bytes.Buffer, cred *Credential, version uint8) error {
	if cred.Key.KeyType < 0 || cred.Key.KeyType > math.MaxUint16 {
		return errors.New("credential enctype is outside uint16 range")
	}
	keyType, err := ccacheUint16("credential enctype", int64(cred.Key.KeyType))
	if err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, keyType)
	if version == 3 {
		_ = binary.Write(out, binary.BigEndian, keyType)
	}
	return marshalData(out, cred.Key.KeyValue)
}

func marshalCredentialTimes(out *bytes.Buffer, cred *Credential) error {
	for _, timestamp := range []time.Time{cred.AuthTime, cred.StartTime, cred.EndTime, cred.RenewTill} {
		seconds := int64(0)
		if !timestamp.IsZero() {
			seconds = timestamp.Unix()
		}
		if seconds < math.MinInt32 || seconds > math.MaxInt32 {
			return errors.New("credential timestamp is outside int32 range")
		}
		encoded, err := ccacheInt32("credential timestamp", seconds)
		if err != nil {
			return err
		}
		_ = binary.Write(out, binary.BigEndian, encoded)
	}
	return nil
}

func marshalTicketFlags(out *bytes.Buffer, flags []byte) error {
	if len(flags) == 0 {
		flags = make([]byte, 4)
	}
	if len(flags) != 4 {
		return errors.New("credential ticket flags must contain 4 bytes")
	}
	out.Write(flags)
	return nil
}

func marshalCredentialAddresses(out *bytes.Buffer, addresses []types.HostAddress) error {
	if len(addresses) > math.MaxInt32 {
		return errors.New("too many credential addresses")
	}
	count, err := ccacheInt32("credential address count", int64(len(addresses)))
	if err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, count)
	for _, address := range addresses {
		if address.AddrType < 0 || address.AddrType > math.MaxUint16 {
			return errors.New("address type is outside uint16 range")
		}
		addressType, convertErr := ccacheUint16("address type", int64(address.AddrType))
		if convertErr != nil {
			return convertErr
		}
		_ = binary.Write(out, binary.BigEndian, addressType)
		if err := marshalData(out, address.Address); err != nil {
			return err
		}
	}
	return nil
}

func marshalCredentialAuthData(out *bytes.Buffer, authData []types.AuthorizationDataEntry) error {
	if len(authData) > math.MaxInt32 {
		return errors.New("too many authorization data entries")
	}
	count, err := ccacheInt32("credential authorization data count", int64(len(authData)))
	if err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, count)
	for _, entry := range authData {
		if entry.ADType < 0 || entry.ADType > math.MaxUint16 {
			return errors.New("authorization data type is outside uint16 range")
		}
		authDataType, convertErr := ccacheUint16("authorization data type", int64(entry.ADType))
		if convertErr != nil {
			return convertErr
		}
		_ = binary.Write(out, binary.BigEndian, authDataType)
		if err := marshalData(out, entry.ADData); err != nil {
			return err
		}
	}
	return nil
}

func marshalData(out *bytes.Buffer, data []byte) error {
	if len(data) > math.MaxInt32 {
		return errors.New("credential cache data field is too large")
	}
	count, err := ccacheInt32("credential cache data field length", int64(len(data)))
	if err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, count)
	out.Write(data)
	return nil
}

// WriteFile atomically writes c to path with mode 0600.
func (c *CCache) WriteFile(path string) error {
	resolved, err := resolveCCacheName(path)
	if err != nil {
		return err
	}
	b, err := c.Marshal()
	if err != nil {
		return err
	}
	if err := fileio.AtomicWrite(resolved, b); err != nil {
		return fmt.Errorf("write credential cache: %w", err)
	}
	c.Path = resolved
	return nil
}

func clonePrincipal(p Principal) Principal {
	p.PrincipalName = clonePrincipalName(p.PrincipalName)
	return p
}

func clonePrincipalName(p types.PrincipalName) types.PrincipalName {
	p.NameString = append([]string(nil), p.NameString...)
	return p
}
