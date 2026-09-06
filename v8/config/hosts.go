package config

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/jcmturner/dnsutils/v2"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var orderedSRV = dnsutils.OrderedSRV

// GetKDCs returns the count of KDCs available and a map of KDC host names keyed on preference order.
func (c *Config) GetKDCs(realm string, tcp bool) (int, map[int]string, error) {
	if realm == "" {
		realm = c.LibDefaults.DefaultRealm
	}
	kdcs := make(map[int]string)
	var count int

	// Get the KDCs from the krb5.conf.
	var ks []string
	for _, r := range c.Realms {
		if !types.RealmEqual(r.Realm, realm) {
			continue
		}
		ks = r.KDC
	}
	count = len(ks)

	if count > 0 {
		// Order the kdcs randomly for preference.
		kdcs = randServOrder(ks)
		return count, kdcs, nil
	}

	if !c.LibDefaults.DNSLookupKDC {
		return count, kdcs, fmt.Errorf("no KDCs defined in configuration for realm %s", realm)
	}

	// Use DNS to resolve kerberos SRV records.
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	names := make([]string, 0, 3)
	if c.LibDefaults.ADSite != "" {
		names = append(names, c.LibDefaults.ADSite+"._sites.dc._msdcs."+realm)
	}
	names = append(names, "dc._msdcs."+realm, realm)
	index, addrs, err := firstSRV("kerberos", proto, names)
	if err != nil {
		return count, kdcs, err
	}
	if len(addrs) < 1 {
		return count, kdcs, fmt.Errorf("no KDC SRV records found for realm %s", realm)
	}
	count = index
	for k, v := range addrs {
		kdcs[k] = strings.TrimRight(v.Target, ".") + ":" + strconv.Itoa(int(v.Port))
	}
	return count, kdcs, nil
}

// GetKpasswdServers returns the count of kpasswd servers available and a map of kpasswd host names keyed on preference order.
// https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#realms - see kpasswd_server section
func (c *Config) GetKpasswdServers(realm string, tcp bool) (int, map[int]string, error) {
	kdcs := make(map[int]string)
	var count int

	// Use DNS to resolve kerberos SRV records if configured to do so in krb5.conf.
	if c.LibDefaults.DNSLookupKDC {
		proto := "udp"
		if tcp {
			proto = "tcp"
		}
		c, addrs, err := firstServiceSRV([]string{"kpasswd", "kerberos-adm"}, proto, realm)
		if err != nil {
			return count, kdcs, err
		}
		if len(addrs) < 1 {
			return count, kdcs, fmt.Errorf("no kpasswd or kadmin SRV records found for realm %s", realm)
		}
		count = c
		for k, v := range addrs {
			kdcs[k] = strings.TrimRight(v.Target, ".") + ":" + strconv.Itoa(int(v.Port))
		}
	} else {
		// Get the KDCs from the krb5.conf an order them randomly for preference.
		var ks []string
		var ka []string
		for _, r := range c.Realms {
			if types.RealmEqual(r.Realm, realm) {
				ks = r.KPasswdServer
				ka = r.AdminServer
				break
			}
		}
		if len(ks) < 1 {
			for _, k := range ka {
				h, _, err := net.SplitHostPort(k)
				if err != nil {
					continue
				}
				ks = append(ks, h+":464")
			}
		}
		count = len(ks)
		if count < 1 {
			return count, kdcs, fmt.Errorf("no kpasswd or kadmin defined in configuration for realm %s", realm)
		}
		kdcs = randServOrder(ks)
	}
	return count, kdcs, nil
}

func firstSRV(service, proto string, names []string) (int, map[int]*net.SRV, error) {
	var lastErr error
	for _, name := range names {
		count, addrs, err := orderedSRV(service, proto, name)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) > 0 {
			return count, addrs, nil
		}
	}
	if lastErr != nil {
		return 0, nil, lastErr
	}
	return 0, nil, nil
}

func firstServiceSRV(services []string, proto, name string) (int, map[int]*net.SRV, error) {
	var lastErr error
	for _, service := range services {
		count, addrs, err := orderedSRV(service, proto, name)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) > 0 {
			return count, addrs, nil
		}
	}
	if lastErr != nil {
		return 0, nil, lastErr
	}
	return 0, nil, nil
}

func randServOrder(ks []string) map[int]string {
	kdcs := make(map[int]string)
	count := len(ks)
	i := 1
	if count > 1 {
		l := len(ks)
		for l > 0 {
			ri := rand.Intn(l)
			kdcs[i] = ks[ri]
			if l > 1 {
				// Remove the entry from the source slice by swapping with the last entry and truncating
				ks[len(ks)-1], ks[ri] = ks[ri], ks[len(ks)-1]
				ks = ks[:len(ks)-1]
				l = len(ks)
			} else {
				l = 0
			}
			i++
		}
	} else {
		kdcs[i] = ks[0]
	}
	return kdcs
}
