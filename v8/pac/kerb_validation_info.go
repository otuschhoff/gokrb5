// Package pac implements Microsoft Privilege Attribute Certificate (PAC) processing.
package pac

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/jcmturner/rpc/v2/mstypes"

	"github.com/otuschhoff/gokrb5/v8/pac/internal/ndr"
)

// KERB_VALIDATION_INFO flags.
//
//nolint:revive // Preserve published flag names from the protocol.
const (
	// Authentication used the GUEST account without a password.
	USERFLAG_GUEST                   = 31
	USERFLAG_NO_ENCRYPTION_AVAILABLE = 30 // No encryption is available.
	USERFLAG_LAN_MANAGER_KEY         = 28 // LAN Manager key was used for authentication.
	// The session key came from the sub-authentication package.
	USERFLAG_SUB_AUTH          = 25
	USERFLAG_EXTRA_SIDS        = 26 // ExtraSIDs contains additional SIDs.
	USERFLAG_MACHINE_ACCOUNT   = 24 // The account is a machine account.
	USERFLAG_DC_NTLM2          = 23 // The domain controller understands NTLMv2.
	USERFLAG_RESOURCE_GROUPIDS = 22 // ResourceGroupIDs is populated.
	USERFLAG_PROFILEPATH       = 21 // ProfilePath is populated.
	// The NTLMv2 NtChallengeResponseFields response authenticated and generated the session key.
	USERFLAG_NTLM2_NTCHALLENGERESP = 20
	// The LMv2 LmChallengeResponseFields response authenticated and generated the session key.
	USERFLAG_LM2_LMCHALLENGERESP = 19
	// The LMv2 LmChallengeResponseFields response authenticated;
	// the NTLMv2 NtChallengeResponseFields response generated the session key.
	// Both fields are specified in [MS-NLMP] section 2.2.1.3.
	USERFLAG_AUTH_LMCHALLENGERESP_KEY_NTCHALLENGERESP = 18
)

// KerbValidationInfo implement https://msdn.microsoft.com/en-us/library/cc237948.aspx
type KerbValidationInfo struct {
	LogOnTime              mstypes.FileTime
	LogOffTime             mstypes.FileTime
	KickOffTime            mstypes.FileTime
	PasswordLastSet        mstypes.FileTime
	PasswordCanChange      mstypes.FileTime
	PasswordMustChange     mstypes.FileTime
	EffectiveName          mstypes.RPCUnicodeString
	FullName               mstypes.RPCUnicodeString
	LogonScript            mstypes.RPCUnicodeString
	ProfilePath            mstypes.RPCUnicodeString
	HomeDirectory          mstypes.RPCUnicodeString
	HomeDirectoryDrive     mstypes.RPCUnicodeString
	LogonCount             uint16
	BadPasswordCount       uint16
	UserID                 uint32
	PrimaryGroupID         uint32
	GroupCount             uint32
	GroupIDs               []mstypes.GroupMembership `ndr:"pointer,conformant"`
	UserFlags              uint32
	UserSessionKey         mstypes.UserSessionKey
	LogonServer            mstypes.RPCUnicodeString
	LogonDomainName        mstypes.RPCUnicodeString
	LogonDomainID          mstypes.RPCSID `ndr:"pointer"`
	Reserved1              [2]uint32      // Has 2 elements
	UserAccountControl     uint32
	SubAuthStatus          uint32
	LastSuccessfulILogon   mstypes.FileTime
	LastFailedILogon       mstypes.FileTime
	FailedILogonCount      uint32
	Reserved3              uint32
	SIDCount               uint32
	ExtraSIDs              []mstypes.KerbSidAndAttributes `ndr:"pointer,conformant"`
	ResourceGroupDomainSID mstypes.RPCSID                 `ndr:"pointer"`
	ResourceGroupCount     uint32
	ResourceGroupIDs       []mstypes.GroupMembership `ndr:"pointer,conformant"`
}

// Unmarshal bytes into the DeviceInfo struct
func (k *KerbValidationInfo) Unmarshal(b []byte) error {
	var err error
	dec := ndr.NewDecoder(bytes.NewReader(b))
	err = dec.Decode(k)
	if err != nil {
		err = fmt.Errorf("error unmarshaling KerbValidationInfo: %w", err)
	}
	return err
}

// GetGroupMembershipSIDs returns a slice of strings containing the group membership SIDs found in the PAC.
func (k *KerbValidationInfo) GetGroupMembershipSIDs() []string {
	var g []string
	lSID := k.LogonDomainID.String()
	for i := range k.GroupIDs {
		g = append(g, fmt.Sprintf("%s-%d", lSID, k.GroupIDs[i].RelativeID))
	}
	for _, entry := range k.ExtraSIDs {
		sid := entry.SID.String()
		if !slices.Contains(g, sid) {
			g = append(g, sid)
		}
	}
	for _, r := range k.ResourceGroupIDs {
		sid := fmt.Sprintf("%s-%d", k.ResourceGroupDomainSID.String(), r.RelativeID)
		if !slices.Contains(g, sid) {
			g = append(g, sid)
		}
	}
	return g
}
