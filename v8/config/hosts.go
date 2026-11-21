package config

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/types"
)

type srvLookup func(service, proto, name string) (string, []*net.SRV, error)

// GetKDCs returns the count and available KDCs keyed by preference order,
// with the most preferred host at index 1. Configured hosts take precedence over DNS.
// DNS results follow [net.LookupSRV] ordering.
func (c *Config) GetKDCs(realm string, tcp bool) (int, map[int]string, error) {
	return c.getKDCs(realm, tcp, net.LookupSRV)
}

// GetKpasswdServers returns the count and password-change servers keyed by preference order,
// with the most preferred host at index 1. Configured kpasswd servers take
// precedence. If DNS lookup is disabled, the admin servers supply the hosts.
// DNS results follow [net.LookupSRV] ordering.
func (c *Config) GetKpasswdServers(realm string, tcp bool) (int, map[int]string, error) {
	return c.getKpasswdServers(realm, tcp, net.LookupSRV)
}

func (c *Config) getKDCs(realm string, tcp bool, lookup srvLookup) (int, map[int]string, error) {
	if realm == "" {
		realm = c.LibDefaults.DefaultRealm
	}
	var configured []string
	for _, r := range c.Realms {
		if types.RealmEqual(r.Realm, realm) {
			configured = r.KDC
		}
	}
	if len(configured) > 0 {
		return len(configured), randServOrder(configured), nil
	}
	if !c.LibDefaults.DNSLookupKDC {
		return 0, map[int]string{}, fmt.Errorf("no KDCs defined in configuration for realm %s", realm)
	}

	domainController := "dc._msdcs." + realm
	names := []string{domainController, realm}
	if c.LibDefaults.ADSite != "" {
		names = []string{c.LibDefaults.ADSite + "._sites." + domainController, domainController, realm}
	}
	proto := srvProtocol(tcp)
	count, hosts, err := firstSRVHosts(names, func(name string) ([]*net.SRV, error) {
		_, records, err := lookup("kerberos", proto, name)
		return records, err
	})
	if err == nil && len(hosts) == 0 {
		err = fmt.Errorf("no KDC SRV records found for realm %s", realm)
	}
	return count, hosts, err
}

func (c *Config) getKpasswdServers(realm string, tcp bool, lookup srvLookup) (int, map[int]string, error) {
	var configured, adminServers []string
	for _, r := range c.Realms {
		if types.RealmEqual(r.Realm, realm) {
			configured = r.KPasswdServer
			adminServers = r.AdminServer
			break
		}
	}
	if len(configured) > 0 {
		return len(configured), randServOrder(configured), nil
	}
	if !c.LibDefaults.DNSLookupKDC {
		return kpasswdFromAdminServers(realm, adminServers)
	}

	proto := srvProtocol(tcp)
	services := []string{"kpasswd", "kerberos-adm"}
	count, hosts, err := firstSRVHosts(services, func(service string) ([]*net.SRV, error) {
		_, records, err := lookup(service, proto, realm)
		return records, err
	})
	if err == nil && len(hosts) == 0 {
		err = fmt.Errorf("no kpasswd or kadmin SRV records found for realm %s", realm)
	}
	return count, hosts, err
}

func kpasswdFromAdminServers(realm string, adminServers []string) (int, map[int]string, error) {
	hosts := make([]string, 0, len(adminServers))
	for _, s := range adminServers {
		host, _, err := net.SplitHostPort(s)
		if err == nil {
			hosts = append(hosts, host+":464")
		}
	}
	if len(hosts) == 0 {
		return 0, map[int]string{}, fmt.Errorf("no kpasswd or kadmin defined in configuration for realm %s", realm)
	}
	return len(hosts), randServOrder(hosts), nil
}

func srvProtocol(tcp bool) string {
	if tcp {
		return "tcp"
	}
	return "udp"
}

func firstSRVHosts(
	candidates []string,
	query func(string) ([]*net.SRV, error),
) (int, map[int]string, error) {
	var lastErr error
	for _, candidate := range candidates {
		addrs, err := query(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		hosts := make(map[int]string, len(addrs))
		// LookupSRV has already ordered the records by priority and weight.
		for i, addr := range addrs {
			hosts[i+1] = strings.TrimRight(addr.Target, ".") + ":" + strconv.Itoa(int(addr.Port))
		}
		return len(addrs), hosts, nil
	}
	// Empty answers do not erase an earlier resolver failure.
	return 0, map[int]string{}, lastErr
}

func randServOrder(ks []string) map[int]string {
	if len(ks) == 0 {
		return map[int]string{}
	}
	ordered := append(make([]string, 0, len(ks)), ks...)
	for i := len(ordered) - 1; i > 0; i-- {
		index, err := crand.Int(crand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return sequentialKDCOrder(ks)
		}
		j := int(index.Int64())
		ordered[i], ordered[j] = ordered[j], ordered[i]
	}
	return sequentialKDCOrder(ordered)
}

func sequentialKDCOrder(ks []string) map[int]string {
	kdcs := make(map[int]string, len(ks))
	for i, kdc := range ks {
		kdcs[i+1] = kdc
	}
	return kdcs
}
