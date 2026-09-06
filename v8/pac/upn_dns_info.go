package pac

import (
	"bytes"
	"fmt"

	"github.com/jcmturner/rpc/v2/mstypes"
)

// UPNDNSInfo implements https://msdn.microsoft.com/en-us/library/dd240468.aspx
type UPNDNSInfo struct {
	UPNLength           uint16 // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the UPN field.
	UPNOffset           uint16 // An unsigned 16-bit integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the UPN_DNS_INFO structure.
	DNSDomainNameLength uint16
	DNSDomainNameOffset uint16
	Flags               uint32
	UPN                 string
	DNSDomain           string
}

const (
	upnNoUPNAttr uint32 = 1 << 0 // The account has no userPrincipalName attribute; the UPN is constructed from the account and DNS domain names.
)

// Unmarshal bytes into the UPN_DNSInfo struct
func (k *UPNDNSInfo) Unmarshal(b []byte) (err error) {
	//The UPN_DNS_INFO structure is a simple structure that is not NDR-encoded.
	r := mstypes.NewReader(bytes.NewReader(b))
	k.UPNLength, err = r.Uint16()
	if err != nil {
		return
	}
	k.UPNOffset, err = r.Uint16()
	if err != nil {
		return
	}
	k.DNSDomainNameLength, err = r.Uint16()
	if err != nil {
		return
	}
	k.DNSDomainNameOffset, err = r.Uint16()
	if err != nil {
		return
	}
	k.Flags, err = r.Uint32()
	if err != nil {
		return
	}
	if k.UPNLength%2 != 0 {
		return fmt.Errorf("%w: UPN length %d is not valid UTF-16", ErrPACMalformed, k.UPNLength)
	}
	if k.DNSDomainNameLength%2 != 0 {
		return fmt.Errorf("%w: DNS domain length %d is not valid UTF-16", ErrPACMalformed, k.DNSDomainNameLength)
	}
	upn, err := copyPACRange(b, uint64(k.UPNOffset), uint64(k.UPNLength))
	if err != nil {
		return fmt.Errorf("UPN_DNS_INFO UPN: %w", err)
	}
	domain, err := copyPACRange(b, uint64(k.DNSDomainNameOffset), uint64(k.DNSDomainNameLength))
	if err != nil {
		return fmt.Errorf("UPN_DNS_INFO DNS domain: %w", err)
	}
	ub := mstypes.NewReader(bytes.NewReader(upn))
	db := mstypes.NewReader(bytes.NewReader(domain))

	u := make([]rune, k.UPNLength/2)
	for i := 0; i < len(u); i++ {
		var r uint16
		r, err = ub.Uint16()
		if err != nil {
			return
		}
		u[i] = rune(r)
	}
	k.UPN = string(u)
	d := make([]rune, k.DNSDomainNameLength/2)
	for i := 0; i < len(d); i++ {
		var r uint16
		r, err = db.Uint16()
		if err != nil {
			return
		}
		d[i] = rune(r)
	}
	k.DNSDomain = string(d)

	return
}
