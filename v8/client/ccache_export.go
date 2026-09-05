package client

import (
	"errors"
	"sort"
	"strconv"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/types"
)

// CCache exports the client's current TGT sessions and cached service tickets.
func (cl *Client) CCache() (*credentials.CCache, error) {
	if cl == nil || cl.Credentials == nil {
		return nil, errors.New("client has no credentials")
	}
	cache := credentials.NewCCache(cl.Credentials.CName(), cl.Credentials.Domain())
	cache.SetKDCTimeOffset(cl.KDCTimeOffset())

	sessionRealms := make([]string, 0)
	cl.sessions.mux.RLock()
	for realm := range cl.sessions.Entries {
		sessionRealms = append(sessionRealms, realm)
	}
	sort.Strings(sessionRealms)
	for _, realm := range sessionRealms {
		session := cl.sessions.Entries[realm]
		session.mux.RLock()
		credential, err := sessionCredential(cl, session)
		session.mux.RUnlock()
		if err != nil {
			cl.sessions.mux.RUnlock()
			return nil, err
		}
		cache.AddCredential(credential)
	}
	cl.sessions.mux.RUnlock()
	serviceNames := make([]string, 0)
	cl.cache.mux.RLock()
	for name := range cl.cache.Entries {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)
	for _, name := range serviceNames {
		entry := cl.cache.Entries[name]
		credential, err := cacheEntryCredential(cl, entry)
		if err != nil {
			cl.cache.mux.RUnlock()
			return nil, err
		}
		cache.AddCredential(credential)
	}
	cl.cache.mux.RUnlock()
	if len(sessionRealms) == 0 && len(serviceNames) == 0 {
		return nil, errors.New("client has no credentials to export")
	}

	if cl.settings.preAuthType != 0 {
		entries := cache.GetEntries()
		principal := entries[0].Server.PrincipalName.PrincipalNameString() + "@" + entries[0].Server.Realm
		if err := cache.SetConfig("pa_type", principal, strconv.FormatInt(int64(cl.settings.preAuthType), 10)); err != nil {
			return nil, err
		}
	}
	return cache, nil
}

func sessionCredential(cl *Client, session *session) (*credentials.Credential, error) {
	ticket, err := session.tgt.Marshal()
	if err != nil {
		return nil, err
	}
	return &credentials.Credential{
		Client:       ccacheClientPrincipal(cl),
		Server:       credentials.Principal{Realm: session.tgt.Realm, PrincipalName: clonePrincipalName(session.tgt.SName)},
		Key:          cloneEncryptionKey(session.sessionKey),
		AuthTime:     session.authTime,
		StartTime:    session.startTime,
		EndTime:      session.endTime,
		RenewTill:    session.renewTill,
		IsSKey:       session.isSKey,
		TicketFlags:  cloneBitString(session.ticketFlags),
		Addresses:    cloneHostAddresses(session.addresses),
		AuthData:     cloneAuthorizationData(session.authData),
		Ticket:       ticket,
		SecondTicket: append([]byte(nil), session.secondTicket...),
	}, nil
}

func cacheEntryCredential(cl *Client, entry CacheEntry) (*credentials.Credential, error) {
	ticket, err := entry.Ticket.Marshal()
	if err != nil {
		return nil, err
	}
	return &credentials.Credential{
		Client:       ccacheClientPrincipal(cl),
		Server:       credentials.Principal{Realm: entry.Ticket.Realm, PrincipalName: clonePrincipalName(entry.Ticket.SName)},
		Key:          cloneEncryptionKey(entry.SessionKey),
		AuthTime:     entry.AuthTime,
		StartTime:    entry.StartTime,
		EndTime:      entry.EndTime,
		RenewTill:    entry.RenewTill,
		IsSKey:       entry.IsSKey,
		TicketFlags:  cloneBitString(entry.TicketFlags),
		Addresses:    cloneHostAddresses(entry.Addresses),
		AuthData:     cloneAuthorizationData(entry.AuthData),
		Ticket:       ticket,
		SecondTicket: append([]byte(nil), entry.SecondTicket...),
	}, nil
}

func ccacheClientPrincipal(cl *Client) credentials.Principal {
	return credentials.Principal{Realm: cl.Credentials.Domain(), PrincipalName: clonePrincipalName(cl.Credentials.CName())}
}

func clonePrincipalName(name types.PrincipalName) types.PrincipalName {
	name.NameString = append([]string(nil), name.NameString...)
	return name
}

func cloneEncryptionKey(key types.EncryptionKey) types.EncryptionKey {
	key.KeyValue = append([]byte(nil), key.KeyValue...)
	return key
}

func cloneBitString(flags asn1.BitString) asn1.BitString {
	flags.Bytes = append([]byte(nil), flags.Bytes...)
	return flags
}

func cloneHostAddresses(addresses []types.HostAddress) []types.HostAddress {
	result := make([]types.HostAddress, len(addresses))
	for index, address := range addresses {
		result[index] = address
		result[index].Address = append([]byte(nil), address.Address...)
	}
	return result
}

func cloneAuthorizationData(entries []types.AuthorizationDataEntry) []types.AuthorizationDataEntry {
	result := make([]types.AuthorizationDataEntry, len(entries))
	for index, entry := range entries {
		result[index] = entry
		result[index].ADData = append([]byte(nil), entry.ADData...)
	}
	return result
}
