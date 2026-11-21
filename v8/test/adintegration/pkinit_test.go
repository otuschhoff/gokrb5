//go:build adintegration

package adintegration

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
)

func TestSambaPKINITRFC8636(t *testing.T) {
	t.Parallel()

	dir := os.Getenv("TESTAD_PKINIT_DIR")
	if dir == "" {
		t.Skip("set TESTAD_PKINIT_DIR to the disposable Samba PKINIT fixture")
	}
	const (
		realm = "SAMBA.GOKRB5.TEST"
		user  = "testuser"
		host  = "dc.samba.gokrb5.test"
	)
	kdc := os.Getenv("TESTAD_KDC")
	require.NotEmpty(t, kdc)
	cfg, err := config.NewFromString(fmt.Sprintf(`
[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    udp_preference_limit = 1
[realms]
    %s = {
        kdc = %s
    }
`, realm, realm, kdc))
	require.NoError(t, err)

	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		return data
	}
	identity, err := pkinit.FromPEM(read("client.pem"), read("client.key"), nil)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(read("ca.pem")))
	var policy pkinit.KDCCertificatePolicy
	policy.Roots, policy.Hostname, policy.Realm = roots, host, realm
	cl, err := client.NewFromPrincipalString(user+"@"+realm, cfg, client.PKINITIdentity(identity),
		client.PKINITKDCCertificatePolicy(policy))
	require.NoError(t, err)
	t.Cleanup(cl.Destroy)

	req, err := messages.NewASReqForTGT(realm, cfg, cl.Credentials.CName())
	require.NoError(t, err)
	reply, err := cl.ASExchange(realm, req, 0)
	require.NoError(t, err)
	require.Equal(t, realm, reply.CRealm)
	require.Equal(t, []string{user}, reply.CName.NameString)
	require.Equal(t, realm, reply.Ticket.Realm)
	require.Equal(t, []string{"krbtgt", realm}, reply.Ticket.SName.NameString)

	var pkReply pkinit.PAPKAsRep
	count := 0
	for _, pa := range reply.PAData {
		if pa.PADataType == patype.PA_PK_AS_REP {
			count++
			require.NoError(t, pkReply.Unmarshal(pa.PADataValue))
		}
	}
	require.Equal(t, 1, count, "expected one PA-PK-AS-REP")
	require.NotNil(t, pkReply.DHInfo, "expected a DH reply")
	require.NotNil(t, pkReply.DHInfo.KDF, "legacy PKINIT does not exercise RFC 8636")
	oid := pkReply.DHInfo.KDF.ID
	require.Contains(t, []string{
		pkinit.OIDKDFSHA256.String(),
		pkinit.OIDKDFSHA384.String(),
		pkinit.OIDKDFSHA512.String(),
	}, oid.String(), "KDC selected an unoffered KDF")
	t.Logf("Samba issued a verified PKINIT TGT with RFC 8636 KDF %s", oid)
}
