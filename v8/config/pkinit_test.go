package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKINITLibDefaults(t *testing.T) {
	configuration, err := NewFromString(`[libdefaults]
default_realm = EXAMPLE.COM
pkinit_anchors = FILE:/etc/krb5/ca.pem
pkinit_identities = FILE:/etc/krb5/user.pem,/etc/krb5/user.key
pkinit_kdc_hostname = dc.example.com
pkinit_eku_checking = kpServerAuth
pkinit_require_crl_checking = true
pkinit_dh_min_bits = 4096
pkinit_pool = FILE:/etc/krb5/intermediates.pem
`)
	require.NoError(t, err)
	require.Equal(t, []string{"FILE:/etc/krb5/ca.pem"}, configuration.LibDefaults.PKINITAnchors)
	require.Equal(t, []string{"FILE:/etc/krb5/user.pem,/etc/krb5/user.key"}, configuration.LibDefaults.PKINITIdentities)
	require.Equal(t, "dc.example.com", configuration.LibDefaults.PKINITKDCHostname)
	require.Equal(t, "kpServerAuth", configuration.LibDefaults.PKINITEKUChecking)
	require.True(t, configuration.LibDefaults.PKINITRequireCRLCheck)
	require.Equal(t, 4096, configuration.LibDefaults.PKINITDHMinBits)
	require.Equal(t, []string{"FILE:/etc/krb5/intermediates.pem"}, configuration.LibDefaults.PKINITPool)
}
