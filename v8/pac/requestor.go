package pac

import (
	"encoding/binary"
	"fmt"

	"github.com/jcmturner/rpc/v2/mstypes"
)

const (
	maxSIDSubAuthorities = 15
	sidHeaderLength      = 8
	sidSubAuthoritySize  = 4
)

// Requestor contains the SID of the account that requested the PAC.
type Requestor struct {
	SID mstypes.RPCSID
}

// Unmarshal decodes a PAC_REQUESTOR buffer.
func (r *Requestor) Unmarshal(b []byte) error {
	if len(b) < sidHeaderLength {
		return fmt.Errorf("%w: PAC_REQUESTOR is %d bytes, want at least %d", ErrPACMalformed, len(b), sidHeaderLength)
	}
	count := int(b[1])
	if count > maxSIDSubAuthorities {
		return fmt.Errorf("%w: PAC_REQUESTOR SID has %d subauthorities, maximum is 15", ErrPACMalformed, count)
	}
	want := sidHeaderLength + count*sidSubAuthoritySize
	if len(b) != want {
		return fmt.Errorf("%w: PAC_REQUESTOR is %d bytes, want %d", ErrPACMalformed, len(b), want)
	}
	if b[0] != 1 {
		return fmt.Errorf("%w: PAC_REQUESTOR SID revision is %d, want 1", ErrPACMalformed, b[0])
	}
	r.SID.Revision = b[0]
	r.SID.SubAuthorityCount = b[1]
	copy(r.SID.IdentifierAuthority[:], b[2:sidHeaderLength])
	r.SID.SubAuthority = make([]uint32, count)
	for i := range r.SID.SubAuthority {
		start := sidHeaderLength + i*sidSubAuthoritySize
		r.SID.SubAuthority[i] = binary.LittleEndian.Uint32(b[start : start+sidSubAuthoritySize])
	}
	return nil
}

// Marshal encodes a PAC_REQUESTOR buffer.
func (r Requestor) Marshal() ([]byte, error) {
	if r.SID.Revision != 1 {
		return nil, fmt.Errorf("PAC_REQUESTOR SID revision is %d, want 1", r.SID.Revision)
	}
	if len(r.SID.SubAuthority) > maxSIDSubAuthorities {
		return nil, fmt.Errorf("PAC_REQUESTOR SID has %d subauthorities, maximum is 15", len(r.SID.SubAuthority))
	}
	if int(r.SID.SubAuthorityCount) != len(r.SID.SubAuthority) {
		return nil, fmt.Errorf("PAC_REQUESTOR SID count is %d, but contains %d subauthorities",
			r.SID.SubAuthorityCount, len(r.SID.SubAuthority))
	}
	b := make([]byte, sidHeaderLength+len(r.SID.SubAuthority)*sidSubAuthoritySize)
	b[0] = r.SID.Revision
	b[1] = r.SID.SubAuthorityCount
	copy(b[2:sidHeaderLength], r.SID.IdentifierAuthority[:])
	for i, authority := range r.SID.SubAuthority {
		start := sidHeaderLength + i*sidSubAuthoritySize
		binary.LittleEndian.PutUint32(b[start:start+sidSubAuthoritySize], authority)
	}
	return b, nil
}
