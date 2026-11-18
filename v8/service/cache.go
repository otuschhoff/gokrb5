// Package service provides server side integrations for Kerberos authentication.
package service

import (
	"fmt"
	"sync"
	"time"

	"github.com/otuschhoff/gokrb5/v8/types"
)

// Replay cache is required as specified in RFC 4120 section 3.2.3

// Cache for tickets received from clients keyed by fully qualified client name. Used to track replay of tickets.
type Cache struct {
	entries map[replayCacheClient]clientEntries
	mux     sync.RWMutex
}

type replayCacheClient struct {
	name  string
	realm string
}

type replayCacheKey struct {
	clientTime  time.Time
	serviceName string
}

// clientEntries holds entries of client details sent to the service.
type clientEntries struct {
	replayMap map[replayCacheKey]replayCacheEntry
	seqNumber int64
	subKey    types.EncryptionKey
}

// Cache entry tracking client time values of tickets sent to the service.
type replayCacheEntry struct {
	presentedTime time.Time
}

func replayCacheKeys(sname types.PrincipalName, a types.Authenticator) (replayCacheClient, replayCacheKey) {
	// Quoted components distinguish names containing "/" from multiple components.
	client := replayCacheClient{name: fmt.Sprintf("%q", a.CName.NameString), realm: a.CRealm}
	key := replayCacheKey{
		clientTime:  a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond).UTC(),
		serviceName: fmt.Sprintf("%q", sname.NameString),
	}
	return client, key
}

// Instance of the ServiceCache. This needs to be a singleton.
var (
	replayCache Cache
	once        sync.Once
)

// GetReplayCache returns a pointer to the Cache singleton.
func GetReplayCache(d time.Duration) *Cache {
	// Create a singleton of the ReplayCache and start a background thread to regularly clean out old entries
	once.Do(func() {
		replayCache = Cache{
			entries: make(map[replayCacheClient]clientEntries),
		}
		go func() {
			for {
				// TODO consider using a context here.
				time.Sleep(d)
				replayCache.ClearOldEntries(d)
			}
		}()
	})
	return &replayCache
}

// AddEntry adds an entry to the Cache.
func (c *Cache) AddEntry(sname types.PrincipalName, a types.Authenticator) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.addEntryLocked(sname, a)
}

func (c *Cache) addEntryLocked(sname types.PrincipalName, a types.Authenticator) {
	if c.entries == nil {
		c.entries = make(map[replayCacheClient]clientEntries)
	}
	client, key := replayCacheKeys(sname, a)
	if ce, ok := c.entries[client]; ok {
		ce.replayMap[key] = replayCacheEntry{
			presentedTime: time.Now().UTC(),
		}
		ce.seqNumber = a.SeqNumber
		ce.subKey = a.SubKey
		c.entries[client] = ce
	} else {
		c.entries[client] = clientEntries{
			replayMap: map[replayCacheKey]replayCacheEntry{
				key: {
					presentedTime: time.Now().UTC(),
				},
			},
			seqNumber: a.SeqNumber,
			subKey:    a.SubKey,
		}
	}
}

// ClearOldEntries clears entries from the Cache that are older than the duration provided.
func (c *Cache) ClearOldEntries(d time.Duration) {
	c.mux.Lock()
	defer c.mux.Unlock()
	for ke, ce := range c.entries {
		for k, e := range ce.replayMap {
			if time.Now().UTC().Sub(e.presentedTime) > d {
				delete(ce.replayMap, k)
			}
		}
		if len(ce.replayMap) == 0 {
			delete(c.entries, ke)
		}
	}
}

// IsReplay tests if the Authenticator provided is a replay within the duration defined. If this is not a replay add the entry to the cache for tracking.
func (c *Cache) IsReplay(sname types.PrincipalName, a types.Authenticator) bool {
	c.mux.Lock()
	defer c.mux.Unlock()
	client, key := replayCacheKeys(sname, a)
	if ce, ok := c.entries[client]; ok {
		if _, found := ce.replayMap[key]; found {
			return true
		}
	}
	c.addEntryLocked(sname, a)
	return false
}
