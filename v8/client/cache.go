package client

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// Cache for service tickets held by the client.
type Cache struct {
	Entries map[string]CacheEntry
	mux     sync.RWMutex
}

// CacheEntry holds details for a cache entry.
type CacheEntry struct {
	SPN          string
	UserName     types.PrincipalName `json:"-"`
	UserRealm    string              `json:"-"`
	Ticket       messages.Ticket     `json:"-"`
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	SessionKey   types.EncryptionKey            `json:"-"`
	TicketFlags  asn1.BitString                 `json:"-"`
	Addresses    []types.HostAddress            `json:"-"`
	AuthData     []types.AuthorizationDataEntry `json:"-"`
	IsSKey       bool                           `json:"-"`
	SecondTicket []byte                         `json:"-"`
}

// S4UTicketInfo exposes an impersonated ticket and its KDC-issued metadata.
type S4UTicketInfo struct {
	Ticket      messages.Ticket
	SessionKey  types.EncryptionKey
	Forwardable bool
	EndTime     time.Time
}

// NewCache creates a new client ticket cache instance.
func NewCache() *Cache {
	return &Cache{
		Entries: map[string]CacheEntry{},
	}
}

// getEntry returns a cache entry that matches the SPN.
func (c *Cache) getEntry(spn string) (CacheEntry, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	e, ok := (*c).Entries[spn]
	return e, ok
}

// JSON returns information about the cached service tickets in a JSON format.
func (c *Cache) JSON() (string, error) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	var es []CacheEntry
	keys := make([]string, 0, len(c.Entries))
	for k := range c.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		es = append(es, c.Entries[k])
	}
	b, err := json.MarshalIndent(&es, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// addEntry adds a ticket to the cache.
func (c *Cache) addEntry(tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey) CacheEntry {
	return c.addEntryWithDetails(tkt, authTime, startTime, endTime, renewTill, sessionKey, types.NewKrbFlags(), nil, nil, false, nil)
}

func (c *Cache) addEntryWithDetails(tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey, ticketFlags asn1.BitString, addresses []types.HostAddress, authData []types.AuthorizationDataEntry, isSKey bool, secondTicket []byte) CacheEntry {
	spn := tkt.SName.PrincipalNameString()
	return c.addEntryWithKey(spn, spn, tkt, authTime, startTime, endTime, renewTill, sessionKey, ticketFlags, addresses, authData, isSKey, secondTicket)
}

func (c *Cache) addEntryWithKey(cacheKey, spn string, tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey, ticketFlags asn1.BitString, addresses []types.HostAddress, authData []types.AuthorizationDataEntry, isSKey bool, secondTicket []byte) CacheEntry {
	c.mux.Lock()
	defer c.mux.Unlock()
	(*c).Entries[cacheKey] = CacheEntry{
		SPN:          spn,
		Ticket:       tkt,
		AuthTime:     authTime,
		StartTime:    startTime,
		EndTime:      endTime,
		RenewTill:    renewTill,
		SessionKey:   sessionKey,
		TicketFlags:  ticketFlags,
		Addresses:    append([]types.HostAddress(nil), addresses...),
		AuthData:     append([]types.AuthorizationDataEntry(nil), authData...),
		IsSKey:       isSKey,
		SecondTicket: append([]byte(nil), secondTicket...),
	}
	return c.Entries[cacheKey]
}

// clear deletes all the cache entries
func (c *Cache) clear() {
	c.mux.Lock()
	defer c.mux.Unlock()
	for k := range c.Entries {
		delete(c.Entries, k)
	}
}

// RemoveEntry removes the cache entry for the defined SPN.
func (c *Cache) RemoveEntry(spn string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.Entries, spn)
}

// GetCachedTicket returns a ticket from the cache for the SPN.
// Only a ticket that is currently valid will be returned.
func (cl *Client) GetCachedTicket(spn string) (messages.Ticket, types.EncryptionKey, bool) {
	if e, ok := cl.cache.getEntry(spn); ok {
		//If within time window of ticket return it
		if time.Now().UTC().After(e.StartTime) && time.Now().UTC().Before(e.EndTime) {
			cl.Log("ticket received from cache for %s", spn)
			return e.Ticket, e.SessionKey, true
		} else if time.Now().UTC().Before(e.RenewTill) {
			e, err := cl.renewTicket(e)
			if err != nil {
				return e.Ticket, e.SessionKey, false
			}
			return e.Ticket, e.SessionKey, true
		}
	}
	var tkt messages.Ticket
	var key types.EncryptionKey
	return tkt, key, false
}

// GetCachedServiceTicketForUser returns a valid S4U ticket for a user and SPN.
func (cl *Client) GetCachedServiceTicketForUser(user types.PrincipalName, userRealm, spn string) (messages.Ticket, types.EncryptionKey, bool) {
	info, ok := cl.GetCachedServiceTicketForUserInfo(user, userRealm, spn)
	if ok {
		return info.Ticket, info.SessionKey, true
	}
	return messages.Ticket{}, types.EncryptionKey{}, false
}

// GetCachedServiceTicketForUserInfo returns a valid S4U ticket with its
// forwardable state and expiry.
func (cl *Client) GetCachedServiceTicketForUserInfo(user types.PrincipalName, userRealm, spn string) (S4UTicketInfo, bool) {
	entry, ok := cl.s4uCache.getEntry(s4uCacheKey(user, userRealm, spn))
	if ok && time.Now().UTC().After(entry.StartTime) && time.Now().UTC().Before(entry.EndTime) {
		cl.Log("S4U ticket received from cache for %s as %s@%s", spn, user.PrincipalNameString(), userRealm)
		forwardable := len(entry.TicketFlags.Bytes) > flags.Forwardable/8 && types.IsFlagSet(&entry.TicketFlags, flags.Forwardable)
		return S4UTicketInfo{
			Ticket:      entry.Ticket,
			SessionKey:  entry.SessionKey,
			Forwardable: forwardable,
			EndTime:     entry.EndTime,
		}, true
	}
	return S4UTicketInfo{}, false
}

func s4uCacheKey(user types.PrincipalName, userRealm, spn string) string {
	return strings.ToUpper(userRealm) + "\x00" + user.PrincipalNameString() + "\x00" + spn
}

func (cl *Client) addS4UCacheEntry(user types.PrincipalName, userRealm, spn string, tgsRep messages.TGSRep) {
	part := tgsRep.DecryptedEncPart
	key := s4uCacheKey(user, userRealm, spn)
	cl.s4uCache.mux.Lock()
	defer cl.s4uCache.mux.Unlock()
	cl.s4uCache.Entries[key] = CacheEntry{
		SPN:         spn,
		UserName:    user,
		UserRealm:   userRealm,
		Ticket:      tgsRep.Ticket,
		AuthTime:    part.AuthTime,
		StartTime:   part.StartTime,
		EndTime:     part.EndTime,
		RenewTill:   part.RenewTill,
		SessionKey:  part.Key,
		TicketFlags: part.Flags,
		Addresses:   append([]types.HostAddress(nil), part.CAddr...),
	}
}

func (cl *Client) s4uIdentityForTicket(ticket messages.Ticket) (types.PrincipalName, string, bool) {
	cl.s4uCache.mux.RLock()
	defer cl.s4uCache.mux.RUnlock()
	for _, entry := range cl.s4uCache.Entries {
		if ticketsEqual(entry.Ticket, ticket) {
			return entry.UserName, entry.UserRealm, true
		}
	}
	return types.PrincipalName{}, "", false
}

func ticketsEqual(left, right messages.Ticket) bool {
	if left.TktVNO != right.TktVNO || !types.RealmEqual(left.Realm, right.Realm) || !left.SName.Equal(right.SName) {
		return false
	}
	return left.EncPart.EType == right.EncPart.EType && left.EncPart.KVNO == right.EncPart.KVNO && string(left.EncPart.Cipher) == string(right.EncPart.Cipher)
}

// renewTicket renews a cache entry ticket.
// To renew from outside the client package use GetCachedTicket
func (cl *Client) renewTicket(e CacheEntry) (CacheEntry, error) {
	spn := e.Ticket.SName
	_, _, err := cl.TGSREQGenerateAndExchange(spn, e.Ticket.Realm, e.Ticket, e.SessionKey, true)
	if err != nil {
		return e, err
	}
	e, ok := cl.cache.getEntry(e.Ticket.SName.PrincipalNameString())
	if !ok {
		return e, errors.New("ticket was not added to cache")
	}
	cl.Log("ticket renewed for %s (EndTime: %v)", spn.PrincipalNameString(), e.EndTime)
	return e, nil
}
