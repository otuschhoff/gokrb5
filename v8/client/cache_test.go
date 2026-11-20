package client

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestCache_addEntry_getEntry_remove_clear(t *testing.T) {
	t.Parallel()
	c := NewCache()
	const cnt byte = 10
	var wg sync.WaitGroup
	for i := range cnt {
		wg.Go(func() {
			addTestCacheEntry(t, c, i)
		})
	}
	wg.Wait()
	for i := range cnt {
		wg.Go(func() {
			assertTestCacheEntry(t, c, i)
		})
	}
	wg.Wait()
	missingSPN := testCacheSPN(int(cnt) + 1)
	_, ok := c.getEntry(missingSPN)
	assert.False(t, ok, "entry found in cache when it shouldn't have been")

	// Remove just the even entries
	for i := 0; i < int(cnt); i += 2 {
		wg.Go(func() {
			c.RemoveEntry(testCacheSPN(i))
		})
	}
	wg.Wait()

	for i := range cnt {
		wg.Go(func() {
			if i%2 == 0 {
				_, ok := c.getEntry(missingSPN)
				assert.False(t, ok, "entry %d found in cache when it shouldn't have been", i)
			} else {
				assertTestCacheEntry(t, c, i)
			}
		})
	}
	wg.Wait()

	// Clear the cache
	c.clear()
	for i := range cnt {
		wg.Go(func() {
			_, ok := c.getEntry(missingSPN)
			assert.False(t, ok, "entry %d found in cache when it shouldn't have been", i)
		})
	}
	wg.Wait()
}

func TestCache_JSON(t *testing.T) {
	t.Parallel()
	c := NewCache()
	for i := range byte(3) {
		addTestCacheEntry(t, c, i)
	}
	expected := `[
  {
    "SPN": "0/test.cache",
    "AuthTime": "1970-01-01T00:00:00Z",
    "StartTime": "1970-01-01T00:00:10Z",
    "EndTime": "1970-01-01T00:00:20Z",
    "RenewTill": "1970-01-01T00:00:30Z"
  },
  {
    "SPN": "1/test.cache",
    "AuthTime": "1970-01-01T00:00:01Z",
    "StartTime": "1970-01-01T00:00:11Z",
    "EndTime": "1970-01-01T00:00:21Z",
    "RenewTill": "1970-01-01T00:00:31Z"
  },
  {
    "SPN": "2/test.cache",
    "AuthTime": "1970-01-01T00:00:02Z",
    "StartTime": "1970-01-01T00:00:12Z",
    "EndTime": "1970-01-01T00:00:22Z",
    "RenewTill": "1970-01-01T00:00:32Z"
  }
]`
	j, err := c.JSON()
	if err != nil {
		t.Errorf("error getting json output of cache: %v", err)
	}
	assert.Equal(t, expected, j, "json output not as expected")
}

const cacheTestHost = "test.cache"

func testCacheSPN(index int) string {
	return strconv.Itoa(index) + "/" + cacheTestHost
}

func addTestCacheEntry(t *testing.T, c *Cache, index byte) {
	t.Helper()
	var ticket messages.Ticket
	ticket.SName = types.PrincipalName{
		NameType:   1,
		NameString: []string{strconv.Itoa(int(index)), cacheTestHost},
	}
	key := types.EncryptionKey{KeyType: 1, KeyValue: []byte{index}}
	offset := int64(index)
	entry := c.addEntry(
		ticket,
		time.Unix(offset, 0).UTC(),
		time.Unix(10+offset, 0).UTC(),
		time.Unix(20+offset, 0).UTC(),
		time.Unix(30+offset, 0).UTC(),
		key,
	)
	assert.Equal(t, testCacheSPN(int(index)), entry.SPN, "SPN cache key not as expected")
}

func assertTestCacheEntry(t *testing.T, c *Cache, index byte) {
	t.Helper()
	entry, ok := c.getEntry(testCacheSPN(int(index)))
	assert.True(t, ok, "cache entry %d was not found", index)
	offset := int64(index)
	assert.Equal(t, time.Unix(offset, 0).UTC(), entry.AuthTime, "auth time not as expected")
	assert.Equal(t, time.Unix(10+offset, 0).UTC(), entry.StartTime, "start time not as expected")
	assert.Equal(t, time.Unix(20+offset, 0).UTC(), entry.EndTime, "end time not as expected")
	assert.Equal(t, time.Unix(30+offset, 0).UTC(), entry.RenewTill, "renew time not as expected")
	assert.Equal(t, []string{strconv.Itoa(int(index)), cacheTestHost}, entry.Ticket.SName.NameString, "ticket not correct")
	assert.Equal(t, []byte{index}, entry.SessionKey.KeyValue, "session key not correct")
}

func TestCacheJSONRetainsEncodingFailure(t *testing.T) {
	t.Parallel()
	c := NewCache()
	var entry CacheEntry
	entry.SPN = "HTTP/cache-diagnostics.test"
	entry.EndTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	c.Entries[entry.SPN] = entry

	text, err := c.JSON()
	require.ErrorContains(t, err, "encode service ticket cache as JSON")
	var cause *json.MarshalerError
	require.ErrorAs(t, err, &cause)
	require.Empty(t, text)
}
