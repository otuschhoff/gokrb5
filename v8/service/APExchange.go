package service

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// APREQResult contains the established identity and GSS negotiation data.
type APREQResult struct {
	Credentials *credentials.Credentials
	Checksum    gssapi.AuthenticatorChecksum
	HasChecksum bool
}

// VerifyAPREQ verifies an AP_REQ sent to the service. Returns a boolean for if the AP_REQ is valid and the client's principal name and realm.
func VerifyAPREQ(APReq *messages.APReq, s *Settings) (bool, *credentials.Credentials, error) {
	result, err := VerifyAPREQWithResult(APReq, s)
	if err != nil {
		return false, nil, err
	}
	return true, result.Credentials, nil
}

// VerifyAPREQWithResult verifies an AP_REQ and returns its GSS negotiation data.
func VerifyAPREQWithResult(APReq *messages.APReq, s *Settings) (APREQResult, error) {
	var result APREQResult
	if !servicePrincipalAllowed(APReq.Ticket.SName, APReq.Ticket.Realm, s) {
		return result, messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_NOT_US, "ticket service principal is not accepted")
	}
	ok, err := APReq.Verify(s.Keytab, s.MaxClockSkew(), s.ClientAddress(), s.KeytabPrincipal())
	if err != nil || !ok {
		return result, err
	}

	if s.RequireHostAddr() && len(APReq.Ticket.DecryptedEncPart.CAddr) < 1 {
		return result,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
	}
	cbtAdvertised, err := authenticatorAdvertisesCBT(APReq.Authenticator.AuthorizationData)
	if err != nil {
		return result, err
	}
	checksum, hasChecksum, err := verifyAuthenticatorChecksumWithCBT(APReq.Authenticator.Cksum, s, cbtAdvertised)
	if err != nil {
		return result, err
	}
	result.Checksum = checksum
	result.HasChecksum = hasChecksum

	// Check for replay
	rc := GetReplayCache(s.MaxClockSkew())
	if rc.IsReplay(APReq.Ticket.SName, APReq.Authenticator) {
		return result,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	c := credentials.NewFromPrincipalName(APReq.Authenticator.CName, APReq.Authenticator.CRealm)
	result.Credentials = c
	c.SetAuthTime(time.Now().UTC())
	c.SetAuthenticated(true)
	c.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)
	if checksum.Flags&gssapi.ContextFlagDeleg != 0 {
		delegated, err := extractDelegatedCredentials(checksum, APReq.Ticket.DecryptedEncPart.Key)
		if err != nil {
			return result, err
		}
		c.SetDelegatedCredentials(delegated)
	}

	//PAC decoding
	if !s.disablePACDecoding {
		isPAC, pac, err := APReq.Ticket.GetPACType(s.Keytab, s.KeytabPrincipal(), s.Logger())
		if isPAC && err != nil {
			return result, err
		}
		if isPAC {
			// There is a valid PAC. Adding attributes to creds
			c.SetADCredentials(credentials.ADCredentials{
				GroupMembershipSIDs: pac.KerbValidationInfo.GetGroupMembershipSIDs(),
				LogOnTime:           pac.KerbValidationInfo.LogOnTime.Time(),
				LogOffTime:          pac.KerbValidationInfo.LogOffTime.Time(),
				PasswordLastSet:     pac.KerbValidationInfo.PasswordLastSet.Time(),
				EffectiveName:       pac.KerbValidationInfo.EffectiveName.Value,
				FullName:            pac.KerbValidationInfo.FullName.Value,
				UserID:              int(pac.KerbValidationInfo.UserID),
				PrimaryGroupID:      int(pac.KerbValidationInfo.PrimaryGroupID),
				LogonServer:         pac.KerbValidationInfo.LogonServer.Value,
				LogonDomainName:     pac.KerbValidationInfo.LogonDomainName.Value,
				LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.String(),
			})
		}
	}
	return result, nil
}

func servicePrincipalAllowed(sname types.PrincipalName, realm string, settings *Settings) bool {
	if settings == nil || settings.Keytab == nil {
		return false
	}
	keytabPrincipals := settings.Keytab.Principals()
	if len(settings.servicePrincipals) == 0 {
		for _, principal := range keytabPrincipals {
			if principalMatchesTicket(principal, sname, realm) {
				return true
			}
		}
		return false
	}
	for _, configured := range settings.servicePrincipals {
		principalName, configuredRealm := types.ParseSPNString(configured)
		if !principalName.Equal(sname) {
			continue
		}
		if configuredRealm != "" {
			if types.RealmEqual(configuredRealm, realm) {
				return true
			}
			continue
		}
		for _, principal := range keytabPrincipals {
			if principalMatchesTicket(principal, sname, realm) {
				return true
			}
		}
	}
	return false
}

func principalMatchesTicket(principal keytab.Principal, sname types.PrincipalName, realm string) bool {
	return types.PrincipalName{NameType: principal.NameType, NameString: principal.Components}.Equal(sname) &&
		types.RealmEqual(principal.Realm, realm)
}

func verifyAuthenticatorChecksum(raw types.Checksum, settings *Settings) (gssapi.AuthenticatorChecksum, bool, error) {
	return verifyAuthenticatorChecksumWithCBT(raw, settings, false)
}

func verifyAuthenticatorChecksumWithCBT(raw types.Checksum, settings *Settings, cbtAdvertised bool) (gssapi.AuthenticatorChecksum, bool, error) {
	var checksum gssapi.AuthenticatorChecksum
	if raw.CksumType == 0 && len(raw.Checksum) == 0 {
		if settings.ExtendedProtection() == ExtendedProtectionRequired {
			return checksum, false, fmt.Errorf("extended protection requires a GSSAPI authenticator checksum")
		}
		return checksum, false, nil
	}
	if raw.CksumType != chksumtype.GSSAPI {
		return checksum, false, fmt.Errorf("authenticator checksum type is %d, want %d", raw.CksumType, chksumtype.GSSAPI)
	}
	if err := checksum.Unmarshal(raw.Checksum); err != nil {
		return checksum, false, fmt.Errorf("invalid GSSAPI authenticator checksum: %v", err)
	}
	if checksum.Flags&gssapi.ContextFlagDeleg != 0 && (checksum.DelegationOption != 1 || len(checksum.Deleg) == 0) {
		return checksum, true, fmt.Errorf("GSSAPI delegation requires option 1 and a KRB_CRED")
	}
	if settings.ExtendedProtection() == ExtendedProtectionDisabled || settings.ChannelBindings() == nil {
		if settings.ExtendedProtection() == ExtendedProtectionRequired && settings.ChannelBindings() == nil {
			return checksum, true, fmt.Errorf("extended protection requires acceptor channel bindings")
		}
		return checksum, true, nil
	}
	want := settings.ChannelBindings().MD5Hash()
	var zero [16]byte
	if settings.ExtendedProtection() == ExtendedProtectionAllowed && !cbtAdvertised && subtle.ConstantTimeCompare(checksum.Bnd[:], zero[:]) == 1 {
		return checksum, true, nil
	}
	if subtle.ConstantTimeCompare(checksum.Bnd[:], want[:]) != 1 {
		return checksum, true, fmt.Errorf("GSSAPI channel bindings do not match")
	}
	return checksum, true, nil
}

func authenticatorAdvertisesCBT(authorizationData types.AuthorizationData) (bool, error) {
	entries, err := authorizationData.EntriesOfType(adtype.ADAuthDataAPOptions)
	if err != nil {
		return false, fmt.Errorf("invalid authenticator authorization data: %v", err)
	}
	for _, entry := range entries {
		options, err := entry.GetADAuthDataAPOptions()
		if err != nil {
			return false, fmt.Errorf("invalid authenticator AP options: %v", err)
		}
		if msflags.APOptions(options)&msflags.KERB_AP_OPTIONS_CBT != 0 {
			return true, nil
		}
	}
	return false, nil
}

func extractDelegatedCredentials(checksum gssapi.AuthenticatorChecksum, key types.EncryptionKey) ([]*credentials.Credential, error) {
	var delegated messages.KRBCred
	if err := delegated.Unmarshal(checksum.Deleg); err != nil {
		return nil, fmt.Errorf("invalid delegated KRB_CRED: %v", err)
	}
	if err := delegated.DecryptEncPart(key); err != nil {
		return nil, fmt.Errorf("could not decrypt delegated KRB_CRED: %v", err)
	}
	if len(delegated.Tickets) == 0 || len(delegated.Tickets) != len(delegated.DecryptedEncPart.TicketInfo) {
		return nil, fmt.Errorf("delegated KRB_CRED ticket count does not match ticket-info count")
	}
	result := make([]*credentials.Credential, 0, len(delegated.Tickets))
	for i, ticket := range delegated.Tickets {
		info := delegated.DecryptedEncPart.TicketInfo[i]
		if !ticket.SName.Equal(info.SName) || !types.RealmEqual(ticket.Realm, info.SRealm) {
			return nil, fmt.Errorf("delegated KRB_CRED ticket %d does not match ticket-info", i)
		}
		ticketBytes, err := ticket.Marshal()
		if err != nil {
			return nil, fmt.Errorf("could not marshal delegated ticket %d: %v", i, err)
		}
		result = append(result, &credentials.Credential{
			Client: credentials.Principal{Realm: info.PRealm, PrincipalName: info.PName},
			Server: credentials.Principal{Realm: info.SRealm, PrincipalName: info.SName},
			Key:    info.Key, AuthTime: info.AuthTime, StartTime: info.StartTime,
			EndTime: info.EndTime, RenewTill: info.RenewTill, TicketFlags: info.Flags,
			Addresses: append([]types.HostAddress(nil), info.CAddr...), Ticket: ticketBytes,
		})
	}
	return result, nil
}
