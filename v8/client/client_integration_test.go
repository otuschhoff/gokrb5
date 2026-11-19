package client_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/spnego"
	"github.com/otuschhoff/gokrb5/v8/test"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

const testHTTPServiceSPN = "HTTP/host.test.gokrb5"

func mustIntegrationConfig(t testing.TB, content string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromString(content)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("NewFromString returned nil config without error")
	}
	return cfg
}

func TestClient_SuccessfulLogin_Keytab(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	tests := []string{
		testdata.KDC_PORT_TEST_GOKRB5,
		testdata.KDC_PORT_TEST_GOKRB5_OLD,
		testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	}
	for _, tst := range tests {
		c.Realms[0].KDC = []string{addr + ":" + tst}
		cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c, mitKDCSettings(tst)...)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on logging in with KDC %s: %v\n", tst, err)
		}
	}
}

func TestClient_Login_Keytab_KDCPrefersEtypeNotInKeytab(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	allKeys := keytab.New()
	if err := allKeys.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	principal, err := keytab.ParsePrincipal("testuser1@TEST.GOKRB5")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := allKeys.GetEntry(principal, 0, etypeID.AES128_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatal(err)
	}
	aes128Only := keytab.New()
	if err := aes128Only.AddKey(principal, entry.KVNO, entry.Key, entry.Timestamp); err != nil {
		t.Fatal(err)
	}

	cfg := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	cfg.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}

	for name, port := range map[string]string{
		"default": testdata.KDC_PORT_TEST_GOKRB5,
		"older":   testdata.KDC_PORT_TEST_GOKRB5_OLD,
		"latest":  testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	} {
		t.Run(name, func(t *testing.T) {
			cfg.Realms[0].KDC = []string{addr + ":" + port}
			cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", aes128Only, cfg, mitKDCSettings(port)...)
			if err := cl.Login(); err != nil {
				t.Fatalf("error logging in with aes128-only keytab: %v", err)
			}
		})
	}
}

func TestClient_Login_RenewLifetime(t *testing.T) {
	test.Integration(t)

	cfg := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	cfg.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cfg.LibDefaults.RenewLifetime = 7 * 24 * time.Hour

	cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", cfg)
	if err := cl.Login(); err != nil {
		t.Fatalf("error logging in with renewable lifetime: %v", err)
	}
	cache, err := cl.CCache()
	if err != nil {
		t.Fatal(err)
	}
	entries := cache.GetEntries()
	if assert.Len(t, entries, 1) {
		assert.WithinDuration(t, time.Now().UTC().Add(7*24*time.Hour), entries[0].RenewTill, 5*time.Second)
	}
}

func TestClient_SuccessfulLogin_Password(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	tests := []string{
		testdata.KDC_PORT_TEST_GOKRB5,
		testdata.KDC_PORT_TEST_GOKRB5_OLD,
		testdata.KDC_PORT_TEST_GOKRB5_LASTEST,
	}
	for _, tst := range tests {
		c.Realms[0].KDC = []string{addr + ":" + tst}
		cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c, mitKDCSettings(tst)...)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on logging in with KDC %s: %v\n", tst, err)
		}
	}
}

func TestClient_SuccessfulLogin_TCPOnly(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Keytab(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_LASTEST}
	tests := []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, tst := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{tst}
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		c.LibDefaults.DefaultTGSEnctypes = []string{tst}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on login using enctype %s: %v\n", tst, err)
		}
		tkt, key, err := cl.GetServiceTicket(testHTTPServiceSPN)
		if err != nil {
			t.Errorf("error in TGS exchange using enctype %s: %v", tst, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", tst)
		assert.Equal(t, etypeID.ETypesByName[tst], key.KeyType, "Key is not for enctype %s", tst)
	}
}

func TestClient_ASExchange_TGSExchange_EncTypes_Password(t *testing.T) {
	test.Integration(t)

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_LASTEST}
	tests := []string{
		"des3-cbc-sha1-kd",
		"aes128-cts-hmac-sha1-96",
		"aes256-cts-hmac-sha1-96",
		"aes128-cts-hmac-sha256-128",
		"aes256-cts-hmac-sha384-192",
		"rc4-hmac",
	}
	for _, tst := range tests {
		c.LibDefaults.DefaultTktEnctypes = []string{tst}
		c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		c.LibDefaults.DefaultTGSEnctypes = []string{tst}
		c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName[tst]}
		cl := client.NewWithPassword("testuser1", "TEST.GOKRB5", "passwordvalue", c)

		err := cl.Login()
		if err != nil {
			t.Errorf("error on login using enctype %s: %v\n", tst, err)
		}
		tkt, key, err := cl.GetServiceTicket(testHTTPServiceSPN)
		if err != nil {
			t.Errorf("error in TGS exchange using enctype %s: %v", tst, err)
		}
		assert.Equal(t, "TEST.GOKRB5", tkt.Realm, "Realm in ticket not as expected for %s test", tst)
		assert.Equal(t, etypeID.ETypesByName[tst], key.KeyType, "Key is not for enctype %s", tst)
	}
}

func TestClient_FailedLogin(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5_WRONGPASSWD)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err == nil {
		t.Fatal("login with incorrect password did not error")
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_SuccessfulLogin_UserRequiringPreAuth_TCPOnly(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER2_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.LibDefaults.UDPPreferenceLimit = 1
	cl := client.NewWithKeytab("testuser2", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
}

func TestClient_NetworkTimeout(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err == nil {
		t.Fatal("login with incorrect KDC address did not error")
	}
}

func TestClient_NetworkTryNextKDC(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	// Two out fo three times this should fail the first time.
	// So will run login twice to expect at least once the first time it will be to a bad KDC
	c.Realms[0].KDC = []string{
		testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88",
		testdata.KDC_IP_TEST_GOKRB5_BADADDR + ":88",
		addr + ":" + testdata.KDC_PORT_TEST_GOKRB5,
	}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatal("login failed")
	}
	err = cl.Login()
	if err != nil {
		t.Fatal("login failed")
	}
}

func TestClient_GetServiceTicket(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	tkt, key, err := cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, testHTTPServiceSPN, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	// Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_CanonicalizeTrue(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	c.LibDefaults.Canonicalize = true
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	tkt, key, err := cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, testHTTPServiceSPN, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	// Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)
}

func TestClient_GetServiceTicket_InvalidSPN(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "host.test.gokrb5"
	_, _, err = cl.GetServiceTicket(spn)
	assert.NotNil(t, err, "Expected unknown principal error")
	assert.True(t, strings.Contains(err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN"), "Error text not as expected")
}

func TestClient_GetServiceTicket_OlderKDC(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_OLD}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c, client.DisablePAReqEncPARep(true))

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	tkt, key, err := cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, testHTTPServiceSPN, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)
}

func TestMultiThreadedClientUse(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	var wg sync.WaitGroup
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			err := cl.Login()
			if err != nil {
				panic(err)
			}
		}()
	}
	wg.Wait()

	var wg2 sync.WaitGroup
	wg2.Add(5)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg2.Done()
			err := spnegoGet(cl)
			if err != nil {
				panic(err)
			}
		}()
	}
	wg2.Wait()
}

func mitKDCSettings(port string) []func(*client.Settings) {
	if port == testdata.KDC_PORT_TEST_GOKRB5_OLD {
		return []func(*client.Settings){client.DisablePAReqEncPARep(true)}
	}
	return nil
}

func spnegoGet(cl *client.Client) error {
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url+"/modgssapi/index.html", nil) // #nosec G704 -- integration-test URL is explicitly configured by the environment. // #nosec G704 -- integration-test URL is explicitly configured by the environment.
	httpResp, err := http.DefaultClient.Do(r)                        // #nosec G704 -- integration-test URL is explicitly configured by the test environment.
	if httpResp != nil {
		defer func(resp *http.Response) { _ = resp.Body.Close() }(httpResp)
	}
	if err != nil {
		return fmt.Errorf("request error: %w\n", err)
	}
	if httpResp.StatusCode != http.StatusUnauthorized {
		return errors.New("did not get unauthorized code when no SPNEGO header set")
	}
	err = spnego.SetSPNEGOHeader(cl, r, testHTTPServiceSPN)
	if err != nil {
		return fmt.Errorf("error setting client SPNEGO header: %w", err)
	}
	httpResp, err = http.DefaultClient.Do(r) // #nosec G704 -- integration-test URL is explicitly configured by the test environment.
	if httpResp != nil {
		defer func(resp *http.Response) { _ = resp.Body.Close() }(httpResp)
	}
	if err != nil {
		return fmt.Errorf("request error: %w\n", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return errors.New("did not get OK code when SPNEGO header set")
	}
	return nil
}

func TestNewFromCCache(t *testing.T) {
	test.Integration(t)

	b, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatalf("error decoding test data")
	}
	cc := new(credentials.CCache)
	err = cc.Unmarshal(b)
	if err != nil {
		t.Fatal("error getting test CCache")
	}
	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl, err := client.NewFromCCache(cc, c)
	if err != nil {
		t.Fatalf("error creating client from CCache: %v", err)
	}
	if ok, err := cl.IsConfigured(); !ok {
		t.Fatalf("client was not configured from CCache: %v", err)
	}
}

// Login to the TEST.GOKRB5 domain and request service ticket for resource in the RESDOM.GOKRB5 domain.
// There is a trust between the two domains.
func TestClient_GetServiceTicket_Trusted_Resource_Domain(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	for i, r := range c.Realms {
		if r.Realm == "TEST.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
		}
		if r.Realm == "RESDOM.GOKRB5" {
			c.Realms[i].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_RESDOM}
		}
	}

	c.LibDefaults.DefaultRealm = "TEST.GOKRB5"
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	c.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}
	c.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96"}
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]}

	if err := cl.Login(); err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	spn := "HTTP/host.resdom.gokrb5"
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, spn, tkt.SName.PrincipalNameString())
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], key.KeyType)

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_RESDOM_GOKRB5)
	skt := keytab.New()
	if err := skt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	if err := tkt.DecryptEncPart(skt, nil); err != nil {
		t.Errorf("error decrypting ticket with service keytab: %v", err)
	}
}

type nativeCCacheFixture struct {
	configPath string
	cachePath  string
}

func newNativeCCacheFixture(t *testing.T) nativeCCacheFixture {
	t.Helper()
	dir := t.TempDir()
	fixture := nativeCCacheFixture{
		configPath: filepath.Join(dir, "krb5.conf"),
		cachePath:  filepath.Join(dir, "ccache"),
	}
	require.NoError(t, os.WriteFile(fixture.configPath, []byte(testdata.KRB5_CONF), 0o600))
	return fixture
}

func (fixture nativeCCacheFixture) run(cmd *exec.Cmd) error {
	cmd.Env = append(cmd.Environ(), "KRB5_CONFIG="+fixture.configPath, "KRB5CCNAME=FILE:"+fixture.cachePath)
	cmd.WaitDelay = time.Second
	_, err := cmd.Output() // Captures bounded stderr on failure.
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("run %s: %w: %s", filepath.Base(cmd.Path), err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	if err != nil {
		return fmt.Errorf("run %s: %w", filepath.Base(cmd.Path), err)
	}
	return nil
}

func loadNativeCCache(t *testing.T, withServiceTicket bool) *credentials.CCache {
	t.Helper()
	fixture := newNativeCCacheFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	kinit := exec.CommandContext(ctx, "kinit", "testuser1@TEST.GOKRB5")
	kinit.Stdin = strings.NewReader(testdata.TESTUSER_PASSWORD + "\n")
	if err := fixture.run(kinit); err != nil {
		t.Fatal(errors.Join(err, ctx.Err()))
	}
	if withServiceTicket {
		kvno := exec.CommandContext(ctx, "kvno", testHTTPServiceSPN)
		if err := fixture.run(kvno); err != nil {
			t.Fatal(errors.Join(err, ctx.Err()))
		}
	}
	cache, err := credentials.LoadCCache(fixture.cachePath)
	require.NoError(t, err, "load native credential cache")
	return cache
}

func TestNativeCCacheFixtureCommand(t *testing.T) {
	fixture := newNativeCCacheFixture(t)
	wantConfig, err := os.ReadFile(fixture.configPath)
	require.NoError(t, err)
	require.Equal(t, testdata.KRB5_CONF, string(wantConfig))

	executable, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// #nosec G204 -- Relaunch the running test binary with a fixed test selector.
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeCCacheFixtureChild$")
	cmd.Env = append(cmd.Environ(),
		"GOKRB5_TEST_NATIVE_CCACHE_CHILD=1",
		"KRB5_CONFIG=old.conf",
		"KRB5CCNAME=FILE:old.ccache",
	)
	cmd.Stdin = strings.NewReader("fixture input\n")

	err = fixture.run(cmd)
	require.ErrorContains(t, err, "native fixture subprocess")
	require.ErrorContains(t, err, "config="+fixture.configPath)
	require.ErrorContains(t, err, "cache=FILE:"+fixture.cachePath)
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitCode())
}

func TestNativeCCacheFixtureChild(t *testing.T) {
	if os.Getenv("GOKRB5_TEST_NATIVE_CCACHE_CHILD") != "1" {
		t.Skip("only used as a subprocess")
	}
	input, err := io.ReadAll(os.Stdin)
	require.NoError(t, err)
	require.Equal(t, "fixture input\n", string(input))
	configPath, cacheName := os.Getenv("KRB5_CONFIG"), os.Getenv("KRB5CCNAME")
	_, err = fmt.Fprintf(os.Stderr, "native fixture subprocess: config=%s cache=%s\n", configPath, cacheName)
	require.NoError(t, err)
	t.Fail()
}

func TestGetServiceTicketFromCCacheTGT(t *testing.T) {
	test.Privileged(t)

	c := loadNativeCCache(t, false)
	cfg := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	cfg.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	cl, err := client.NewFromCCache(c, cfg)
	if err != nil {
		t.Fatalf("error generating client from ccache: %v", err)
	}
	tkt, key, err := cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, testHTTPServiceSPN, tkt.SName.PrincipalNameString())
	assert.Equal(t, int32(18), key.KeyType)

	// Check cache use - should get the same values back again
	tkt2, key2, err := cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	assert.Equal(t, tkt.EncPart.Cipher, tkt2.EncPart.Cipher)
	assert.Equal(t, key.KeyValue, key2.KeyValue)

	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url+"/modgssapi/index.html", nil) // #nosec G704 -- integration-test URL is explicitly configured by the environment.
	err = spnego.SetSPNEGOHeader(cl, r, testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r) // #nosec G704 -- integration-test URL is explicitly configured by the test environment.
	if httpResp != nil {
		defer func(resp *http.Response) { _ = resp.Body.Close() }(httpResp)
	}
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "status code in response to client SPNEGO request not as expected")
}

func TestGetServiceTicketFromCCacheWithoutKDC(t *testing.T) {
	test.Privileged(t)

	c := loadNativeCCache(t, true)
	cfg := mustIntegrationConfig(t, "...")
	cl, err := client.NewFromCCache(c, cfg)
	if err != nil {
		t.Fatalf("error generating client from ccache: %v", err)
	}
	url := os.Getenv("TEST_HTTP_URL")
	if url == "" {
		url = testdata.TEST_HTTP_URL
	}
	r, _ := http.NewRequest("GET", url+"/modgssapi/index.html", nil) // #nosec G704 -- integration-test URL is explicitly configured by the environment.
	err = spnego.SetSPNEGOHeader(cl, r, testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error setting client SPNEGO header: %v", err)
	}
	httpResp, err := http.DefaultClient.Do(r) // #nosec G704 -- integration-test URL is explicitly configured by the test environment.
	if httpResp != nil {
		defer func(resp *http.Response) { _ = resp.Body.Close() }(httpResp)
	}
	if err != nil {
		t.Fatalf("request error: %v\n", err)
	}
	assert.Equal(t, http.StatusOK, httpResp.StatusCode, "status code in response to client SPNEGO request not as expected")
}

func TestClient_ChangePasswd(t *testing.T) {
	test.Integration(t)

	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5}
	c.Realms[0].KPasswdServer = []string{addr + ":464"}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	ok, err := cl.ChangePasswd("newpassword")
	if err != nil {
		t.Fatalf("error changing password: %v", err)
	}
	assert.True(t, ok, "password was not changed")

	cl = client.NewWithPassword("testuser1", "TEST.GOKRB5", "newpassword", c)
	ok, err = cl.ChangePasswd(testdata.TESTUSER_PASSWORD)
	if err != nil {
		t.Fatalf("error changing password: %v", err)
	}
	assert.True(t, ok, "password was not changed back")

	cl = client.NewWithPassword("testuser1", "TEST.GOKRB5", testdata.TESTUSER_PASSWORD, c)
	err = cl.Login()
	if err != nil {
		t.Fatalf("Could not log back in after reverting password: %v", err)
	}
}

func TestClient_Destroy(t *testing.T) {
	test.Integration(t)

	addr := os.Getenv("TEST_KDC_ADDR")
	if addr == "" {
		addr = testdata.KDC_IP_TEST_GOKRB5
	}
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}

	c := mustIntegrationConfig(t, testdata.KRB5_CONF)
	c.Realms[0].KDC = []string{addr + ":" + testdata.KDC_PORT_TEST_GOKRB5_SHORTTICKETS}
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Fatalf("error on login: %v\n", err)
	}
	_, _, err = cl.GetServiceTicket(testHTTPServiceSPN)
	if err != nil {
		t.Fatalf("error getting service ticket: %v\n", err)
	}
	n := runtime.NumGoroutine()
	time.Sleep(time.Second * 60)
	cl.Destroy()
	time.Sleep(time.Second * 5)
	assert.True(t, runtime.NumGoroutine() < n, "auto-renewal goroutine was not stopped when client destroyed")
	is, _ := cl.IsConfigured()
	assert.False(t, is, "client is still configured after it was destroyed")
}
