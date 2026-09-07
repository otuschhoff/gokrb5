package client

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestMultiThreadedClientSession(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	err := cl.Login()
	if err != nil {
		t.Fatalf("failed to log in: %v", err)
	}

	s, ok := cl.sessions.get("TEST.GOKRB5")
	if !ok {
		t.Fatal("error initially getting session")
	}
	go func() {
		for {
			err := cl.renewTGT(s)
			if err != nil {
				t.Logf("error renewing TGT: %v", err)
			}
			time.Sleep(time.Millisecond * 100)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			tgt, _, err := cl.sessionTGT("TEST.GOKRB5")
			if err != nil || tgt.Realm != "TEST.GOKRB5" {
				t.Logf("error getting session: %v", err)
			}
			_, _, _, r, _ := cl.sessionTimes("TEST.GOKRB5")
			fmt.Fprintf(io.Discard, "%v", r)
		}()
		time.Sleep(time.Second)
	}
	wg.Wait()
}

func TestClient_AutoRenew_Goroutine(t *testing.T) {
	test.Integration(t)

	// Tests that the auto renew of client credentials is not spawning goroutines out of control.
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_SHORTTICKETS}
	c.LibDefaults.PreferredPreauthTypes = []int{int(etypeID.DES3_CBC_SHA1_KD)} // a preauth etype the KDC does not support. Test this does not cause renewal to fail.
	cl := NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Errorf("error on logging in: %v\n", err)
	}
	n := runtime.NumGoroutine()
	for i := 0; i < 24; i++ {
		time.Sleep(time.Second * 5)
		_, endTime, _, _, err := cl.sessionTimes("TEST.GOKRB5")
		if err != nil {
			t.Errorf("could not get client's session: %v", err)
		}
		if time.Now().UTC().After(endTime) {
			t.Fatalf("session auto update failed")
		}
		spn := "HTTP/host.test.gokrb5"
		tkt, key, err := cl.GetServiceTicket(spn)
		if err != nil {
			t.Fatalf("error getting service ticket: %v\n", err)
		}
		b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
		skt := keytab.New()
		skt.Unmarshal(b)
		tkt.DecryptEncPart(skt, nil)
		assert.Equal(t, spn, tkt.SName.PrincipalNameString())
		assert.Equal(t, int32(18), key.KeyType)
		if runtime.NumGoroutine() > n {
			t.Fatalf("number of goroutines is increasing: should not be more than %d, is %d", n, runtime.NumGoroutine())
		}
	}
}

func TestSessions_JSON(t *testing.T) {
	s := &sessions{
		Entries: make(map[string]*session),
	}
	for i := 0; i < 3; i++ {
		realm := fmt.Sprintf("test%d", i)
		e := &session{
			realm:                realm,
			authTime:             time.Unix(int64(0+i), 0).UTC(),
			endTime:              time.Unix(int64(10+i), 0).UTC(),
			renewTill:            time.Unix(int64(20+i), 0).UTC(),
			sessionKeyExpiration: time.Unix(int64(30+i), 0).UTC(),
		}
		s.Entries[realm] = e
	}
	j, err := s.JSON()
	if err != nil {
		t.Errorf("error getting json: %v", err)
	}
	expected := `[
  {
    "Realm": "test0",
    "AuthTime": "1970-01-01T00:00:00Z",
    "EndTime": "1970-01-01T00:00:10Z",
    "RenewTill": "1970-01-01T00:00:20Z",
    "SessionKeyExpiration": "1970-01-01T00:00:30Z"
  },
  {
    "Realm": "test1",
    "AuthTime": "1970-01-01T00:00:01Z",
    "EndTime": "1970-01-01T00:00:11Z",
    "RenewTill": "1970-01-01T00:00:21Z",
    "SessionKeyExpiration": "1970-01-01T00:00:31Z"
  },
  {
    "Realm": "test2",
    "AuthTime": "1970-01-01T00:00:02Z",
    "EndTime": "1970-01-01T00:00:12Z",
    "RenewTill": "1970-01-01T00:00:22Z",
    "SessionKeyExpiration": "1970-01-01T00:00:32Z"
  }
]`
	assert.Equal(t, expected, j, "json output not as expected")
}

func TestRenewRequiresHomeRealmTGT(t *testing.T) {
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", config.New())
	assert.EqualError(t, cl.Renew(), "TGT session not found for realm EXAMPLE.ORG")
}

func TestRenewAndRefreshSessionRoundTrip(t *testing.T) {
	client, _, tgt, oldKey := newCoverageTGSRequest(t)
	now := time.Now().UTC()
	session := &session{
		realm: "EXAMPLE.ORG", authTime: now.Add(-time.Hour), startTime: now.Add(-time.Hour),
		endTime: now.Add(time.Hour), renewTill: now.Add(2 * time.Hour), tgt: tgt, sessionKey: oldKey,
	}
	client.sessions.update(session)
	newKey := s4uTestKey(10)
	calls := 0
	client.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
		calls++
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if realm != "EXAMPLE.ORG" || !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Renew) {
			t.Fatalf("renew request = realm %q, options %v", realm, request.ReqBody.KDCOptions)
		}
		return marshalS4UTGSReply(t, request, oldKey, newKey, client.Credentials.CName(), client.Credentials.Realm(), request.ReqBody.SName), nil
	}
	if err := client.Renew(); err != nil {
		t.Fatal(err)
	}
	if string(session.sessionKey.KeyValue) != string(newKey.KeyValue) {
		t.Fatalf("renewed key = %x", session.sessionKey.KeyValue)
	}
	session.sessionKey = oldKey
	session.renewTill = now.Add(2 * time.Hour)
	if renewed, err := client.refreshSession(session); err != nil || !renewed || calls != 2 {
		t.Fatalf("refresh = renewed %v, calls %d, error %v", renewed, calls, err)
	}
}

func TestAddSessionDefaultsStartTimeToAuthTime(t *testing.T) {
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", config.New())
	authTime := time.Now().UTC().Truncate(time.Second)
	ticket := messages.Ticket{SName: types.NewPrincipalName(2, "krbtgt/EXAMPLE.ORG")}
	part := messages.EncKDCRepPart{
		Key:      types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)},
		Flags:    types.NewKrbFlags(),
		AuthTime: authTime,
		EndTime:  authTime.Add(time.Hour),
		SRealm:   "EXAMPLE.ORG",
		SName:    ticket.SName,
	}
	encoded, err := part.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decoded messages.EncKDCRepPart
	if err := decoded.Unmarshal(encoded); err != nil {
		t.Fatal(err)
	}
	cl.addSession(ticket, decoded)

	session, ok := cl.sessions.get("EXAMPLE.ORG")
	if !ok {
		t.Fatal("TGT session was not added")
	}
	assert.Equal(t, authTime, session.startTime)
}

func TestSessionsUseCaseInsensitiveRealmKeys(t *testing.T) {
	s := &sessions{Entries: make(map[string]*session)}
	want := &session{realm: "Example.Org"}
	s.update(want)
	got, ok := s.get("example.org")
	assert.True(t, ok)
	assert.Same(t, want, got)
}

func TestGetSupportedEncTypes(t *testing.T) {
	want := msflags.SupportedEncTypeAES256CTSHMACSHA196SK | msflags.SupportedEncTypeClaims
	pa, err := types.NewPASupportedEncTypesPAData(types.PASupportedEncTypes(want))
	if err != nil {
		t.Fatal(err)
	}
	got, err := getSupportedEncTypes(types.PADataSequence{pa})
	assert.NoError(t, err)
	assert.Equal(t, want, got)

	s := &session{supportedEncTypes: want}
	s.update(messages.Ticket{}, messages.EncKDCRepPart{})
	assert.Equal(t, msflags.SupportedEncTypes(0), s.supportedEncryptionTypes())
}

func TestReferralRealmUsesReplyMetadata(t *testing.T) {
	pa, err := types.NewPASvrReferralInfoPAData(types.PASvrReferralData{ReferredRealm: "CHILD.EXAMPLE.ORG"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := referralRealm(types.PADataSequence{pa}, "FALLBACK.EXAMPLE.ORG")
	assert.NoError(t, err)
	assert.Equal(t, "CHILD.EXAMPLE.ORG", got)

	got, err = referralRealm(nil, "FALLBACK.EXAMPLE.ORG")
	assert.NoError(t, err)
	assert.Equal(t, "FALLBACK.EXAMPLE.ORG", got)
}
