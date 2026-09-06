package credentials

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
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
			seconds := int32(binary.BigEndian.Uint32(field.value[:4]))
			microseconds := int32(binary.BigEndian.Uint32(field.value[4:]))
			return time.Duration(seconds)*time.Second + time.Duration(microseconds)*time.Microsecond, true
		}
	}
	return 0, false
}

// SetKDCTimeOffset stores the KDC time offset with microsecond precision.
func (c *CCache) SetKDCTimeOffset(offset time.Duration) {
	seconds := offset / time.Second
	microseconds := (offset % time.Second) / time.Microsecond
	value := make([]byte, 8)
	binary.BigEndian.PutUint32(value[:4], uint32(int32(seconds)))
	binary.BigEndian.PutUint32(value[4:], uint32(int32(microseconds)))
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
		headerBytes, err := marshalHeader(c.Header)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(&out, binary.BigEndian, uint16(len(headerBytes))); err != nil {
			return nil, err
		}
		out.Write(headerBytes)
	}
	if err := marshalPrincipal(&out, c.DefaultPrincipal); err != nil {
		return nil, fmt.Errorf("invalid default principal: %v", err)
	}
	for i, cred := range c.Credentials {
		if cred == nil {
			return nil, fmt.Errorf("credential %d is nil", i)
		}
		if err := marshalCredential(&out, cred, version); err != nil {
			return nil, fmt.Errorf("invalid credential %d: %v", i, err)
		}
	}
	return out.Bytes(), nil
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
		_ = binary.Write(&out, binary.BigEndian, uint16(len(field.value)))
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
	_ = binary.Write(out, binary.BigEndian, int32(len(p.PrincipalName.NameString)))
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
	if cred.Key.KeyType < 0 || cred.Key.KeyType > math.MaxUint16 {
		return errors.New("credential enctype is outside uint16 range")
	}
	_ = binary.Write(out, binary.BigEndian, uint16(cred.Key.KeyType))
	if version == 3 {
		_ = binary.Write(out, binary.BigEndian, uint16(cred.Key.KeyType))
	}
	if err := marshalData(out, cred.Key.KeyValue); err != nil {
		return err
	}
	for _, timestamp := range []time.Time{cred.AuthTime, cred.StartTime, cred.EndTime, cred.RenewTill} {
		seconds := timestamp.Unix()
		if seconds < math.MinInt32 || seconds > math.MaxInt32 {
			return errors.New("credential timestamp is outside int32 range")
		}
		_ = binary.Write(out, binary.BigEndian, int32(seconds))
	}
	if cred.IsSKey {
		out.WriteByte(1)
	} else {
		out.WriteByte(0)
	}
	flags := cred.TicketFlags.Bytes
	if len(flags) == 0 {
		flags = make([]byte, 4)
	}
	if len(flags) != 4 {
		return errors.New("credential ticket flags must contain 4 bytes")
	}
	out.Write(flags)
	if len(cred.Addresses) > math.MaxInt32 {
		return errors.New("too many credential addresses")
	}
	_ = binary.Write(out, binary.BigEndian, int32(len(cred.Addresses)))
	for _, address := range cred.Addresses {
		if address.AddrType < 0 || address.AddrType > math.MaxUint16 {
			return errors.New("address type is outside uint16 range")
		}
		_ = binary.Write(out, binary.BigEndian, uint16(address.AddrType))
		if err := marshalData(out, address.Address); err != nil {
			return err
		}
	}
	if len(cred.AuthData) > math.MaxInt32 {
		return errors.New("too many authorization data entries")
	}
	_ = binary.Write(out, binary.BigEndian, int32(len(cred.AuthData)))
	for _, entry := range cred.AuthData {
		if entry.ADType < 0 || entry.ADType > math.MaxUint16 {
			return errors.New("authorization data type is outside uint16 range")
		}
		_ = binary.Write(out, binary.BigEndian, uint16(entry.ADType))
		if err := marshalData(out, entry.ADData); err != nil {
			return err
		}
	}
	if err := marshalData(out, cred.Ticket); err != nil {
		return err
	}
	return marshalData(out, cred.SecondTicket)
}

func marshalData(out *bytes.Buffer, data []byte) error {
	if len(data) > math.MaxInt32 {
		return errors.New("credential cache data field is too large")
	}
	_ = binary.Write(out, binary.BigEndian, int32(len(data)))
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
	dir := filepath.Dir(resolved)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(resolved)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		return err
	}
	if err := syncCacheDir(dir); err != nil {
		return err
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
