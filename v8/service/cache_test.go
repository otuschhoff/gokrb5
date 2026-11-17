package service

import (
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestReplayCacheUpdatesAuthenticatorMetadata(t *testing.T) {
	var cache Cache
	name := types.NewPrincipalName(1, "user")
	service := types.NewPrincipalName(2, "HTTP/host")
	authenticator := types.Authenticator{CName: name, CTime: time.Now().UTC(), SeqNumber: 1}
	cache.AddEntry(service, authenticator)
	authenticator.SeqNumber = 2
	authenticator.Cusec = 1
	authenticator.SubKey = types.EncryptionKey{KeyType: 18, KeyValue: []byte("second key")}
	cache.AddEntry(service, authenticator)
	entry, ok := cache.entries[replayCacheClient{name: `["user"]`}]
	if !ok || entry.seqNumber != 2 || string(entry.subKey.KeyValue) != "second key" || len(entry.replayMap) != 2 {
		t.Fatalf("updated cache entry = %+v, found %v", entry, ok)
	}
}

func TestReplayCacheSeparatesServicesAndRealms(t *testing.T) {
	var cache Cache
	authenticator := types.Authenticator{
		CName:  types.NewPrincipalName(1, "user"),
		CRealm: "FIRST.EXAMPLE",
		CTime:  time.Now().UTC(),
	}
	first := types.NewPrincipalName(2, "HTTP/first")
	second := types.NewPrincipalName(2, "HTTP/second")
	if cache.IsReplay(first, authenticator) || cache.IsReplay(second, authenticator) {
		t.Fatal("distinct services were treated as replays")
	}
	if !cache.IsReplay(first, authenticator) || !cache.IsReplay(second, authenticator) {
		t.Fatal("a second service evicted the first service's replay record")
	}
	authenticator.CRealm = "SECOND.EXAMPLE"
	if cache.IsReplay(first, authenticator) {
		t.Fatal("distinct client realms were treated as replays")
	}
	if !cache.IsReplay(first, authenticator) {
		t.Fatal("the second realm's replay record was not retained")
	}
}

func TestReplayCachePrincipalComponentsAndTimeIdentity(t *testing.T) {
	var cache Cache
	authenticator := types.Authenticator{CName: types.NewPrincipalName(1, "user"), CTime: time.Now().UTC()}
	first := types.PrincipalName{NameString: []string{"HTTP", "a/b"}}
	second := types.PrincipalName{NameString: []string{"HTTP/a", "b"}}
	if cache.IsReplay(first, authenticator) || cache.IsReplay(second, authenticator) {
		t.Fatal("distinct service name components were treated as replays")
	}
	authenticator.CTime = authenticator.CTime.In(time.FixedZone("test", 3600))
	if !cache.IsReplay(first, authenticator) || !cache.IsReplay(second, authenticator) {
		t.Fatal("equivalent timestamp locations changed replay identity")
	}
	authenticator.CName = types.PrincipalName{NameString: []string{"a/b"}}
	if cache.IsReplay(first, authenticator) {
		t.Fatal("a new client name was treated as a replay")
	}
	authenticator.CName = types.PrincipalName{NameString: []string{"a", "b"}}
	if cache.IsReplay(first, authenticator) {
		t.Fatal("distinct client name components were treated as replays")
	}
}

func TestReplayCacheConcurrentDistinctUpdates(t *testing.T) {
	const workers = 32
	var cache Cache
	now := time.Now().UTC()
	name := types.NewPrincipalName(1, "user")
	service := types.NewPrincipalName(2, "HTTP/host")
	var workersDone sync.WaitGroup
	for index := range workers {
		workersDone.Go(func() {
			cache.AddEntry(service, types.Authenticator{CName: name, CTime: now, Cusec: index})
			cache.ClearOldEntries(time.Hour)
		})
	}
	workersDone.Wait()
	entry := cache.entries[replayCacheClient{name: `["user"]`}]
	if len(entry.replayMap) != workers {
		t.Fatalf("retained %d replay records, want %d", len(entry.replayMap), workers)
	}
}

func TestReplayCacheConcurrentCheckAndInsert(t *testing.T) {
	const workers = 32
	var cache Cache
	name := types.NewPrincipalName(1, "user")
	service := types.NewPrincipalName(2, "HTTP/host")
	authenticator := types.Authenticator{CName: name, CTime: time.Now().UTC()}
	start := make(chan struct{})
	results := make(chan bool, workers)
	var workersDone sync.WaitGroup
	for range workers {
		workersDone.Go(func() {
			<-start
			results <- cache.IsReplay(service, authenticator)
		})
	}
	close(start)
	workersDone.Wait()
	close(results)
	accepted := 0
	for replay := range results {
		if !replay {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d identical concurrent authenticators, want 1", accepted)
	}
}
