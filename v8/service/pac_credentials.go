package service

import (
	"fmt"
	"time"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/pac"
)

func adCredentialsFromPAC(p pac.PACType, authTime time.Time) credentials.ADCredentials {
	validation := p.KerbValidationInfo
	domainSID := validation.LogonDomainID.String()
	result := credentials.ADCredentials{
		GroupMembershipSIDs: validation.GetGroupMembershipSIDs(),
		LogOnTime:           validation.LogOnTime.Time(),
		LogOffTime:          validation.LogOffTime.Time(),
		PasswordLastSet:     validation.PasswordLastSet.Time(),
		EffectiveName:       validation.EffectiveName.Value,
		FullName:            validation.FullName.Value,
		UserID:              int(validation.UserID),
		PrimaryGroupID:      int(validation.PrimaryGroupID),
		LogonServer:         validation.LogonServer.Value,
		LogonDomainName:     validation.LogonDomainName.Value,
		LogonDomainID:       domainSID,
		UserSID:             fmt.Sprintf("%s-%d", domainSID, validation.UserID),
		UserAccountControl:  validation.UserAccountControl,
		TicketAuthTime:      authTime,
	}
	for _, sid := range validation.ExtraSIDs {
		result.ExtraSIDs = append(result.ExtraSIDs, credentials.SIDAndAttributes{SID: sid.SID.String(), Attributes: sid.Attributes})
	}
	for _, group := range validation.ResourceGroupIDs {
		result.ResourceGroupSIDs = append(result.ResourceGroupSIDs, credentials.SIDAndAttributes{
			SID: fmt.Sprintf("%s-%d", validation.ResourceGroupDomainSID.String(), group.RelativeID), Attributes: group.Attributes,
		})
	}
	if p.UPNDNSInfo != nil {
		result.UPN = p.UPNDNSInfo.UPN
		result.DNSDomain = p.UPNDNSInfo.DNSDomain
		result.SAMAccountName = p.UPNDNSInfo.SAMAccountName
	}
	if p.ClientClaimsInfo != nil {
		claims := p.ClientClaimsInfo.ClaimsSet
		result.ClientClaims = &claims
	}
	if p.DeviceClaimsInfo != nil {
		claims := p.DeviceClaimsInfo.ClaimsSet
		result.DeviceClaims = &claims
	}
	if p.DeviceInfo != nil {
		result.DeviceInfo = deviceCredentialsFromPAC(*p.DeviceInfo)
	}
	if p.S4UDelegationInfo != nil {
		result.S4UDelegationInfo = &credentials.ADS4UDelegationInfo{
			ProxyTarget: p.S4UDelegationInfo.ProxyTarget(), TransitedServices: p.S4UDelegationInfo.TransitedServices(),
		}
	}
	if p.AttributesInfo != nil {
		result.PACAttributes = p.AttributesInfo.Flags
	}
	if p.Requestor != nil {
		result.PACRequestorSID = p.Requestor.SID.String()
	}
	return result
}

func deviceCredentialsFromPAC(device pac.DeviceInfo) *credentials.ADDeviceInfo {
	domainSID := device.AccountDomainID.String()
	result := &credentials.ADDeviceInfo{
		UserSID:         fmt.Sprintf("%s-%d", domainSID, device.UserID),
		PrimaryGroupSID: fmt.Sprintf("%s-%d", domainSID, device.PrimaryGroupID),
	}
	for _, group := range device.AccountGroupIDs {
		result.GroupSIDs = append(result.GroupSIDs, credentials.SIDAndAttributes{SID: fmt.Sprintf("%s-%d", domainSID, group.RelativeID), Attributes: group.Attributes})
	}
	for _, sid := range device.ExtraSIDs {
		result.ExtraSIDs = append(result.ExtraSIDs, credentials.SIDAndAttributes{SID: sid.SID.String(), Attributes: sid.Attributes})
	}
	for _, domain := range device.DomainGroup {
		for _, group := range domain.GroupIDs {
			result.DomainGroupSIDs = append(result.DomainGroupSIDs, credentials.SIDAndAttributes{SID: fmt.Sprintf("%s-%d", domain.DomainID.String(), group.RelativeID), Attributes: group.Attributes})
		}
	}
	return result
}
