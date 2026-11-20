package pac

import (
	"bytes"
	"fmt"

	"github.com/jcmturner/rpc/v2/mstypes"

	"github.com/otuschhoff/gokrb5/v8/pac/internal/ndr"
)

// DeviceInfo implements https://msdn.microsoft.com/en-us/library/hh536402.aspx
type DeviceInfo struct {
	// UserID is the account's RID. If zero, the account SID is the first entry in ExtraSIDs.
	UserID uint32
	// PrimaryGroupID is the RID of the account's primary group.
	PrimaryGroupID uint32
	// AccountDomainID is the domain SID used with the account and group RIDs to form their SIDs.
	AccountDomainID mstypes.RPCSID `ndr:"pointer"`
	// AccountGroupCount is the number of groups in AccountGroupIDs.
	AccountGroupCount uint32
	// AccountGroupIDs lists the account's group memberships in its own domain.
	AccountGroupIDs []mstypes.GroupMembership `ndr:"pointer,conformant"`
	// SIDCount is the number of SIDs in ExtraSIDs.
	SIDCount uint32
	// ExtraSIDs lists SIDs for groups not in domains and starts with the account SID if UserID is zero.
	ExtraSIDs []mstypes.KerbSidAndAttributes `ndr:"pointer,conformant"`
	// DomainGroupCount is the number of domains in DomainGroup.
	DomainGroupCount uint32
	// DomainGroup lists the account's group memberships by domain.
	DomainGroup []mstypes.DomainGroupMembership `ndr:"pointer,conformant"`
}

// Unmarshal bytes into the DeviceInfo struct
func (k *DeviceInfo) Unmarshal(b []byte) error {
	var err error
	dec := ndr.NewDecoder(bytes.NewReader(b))
	err = dec.Decode(k)
	if err != nil {
		err = fmt.Errorf("error unmarshaling DeviceInfo: %w", err)
	}
	return err
}
