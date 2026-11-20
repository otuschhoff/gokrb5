package config

import (
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	bitsPerByte           = 8
	maxCCacheType         = 4
	maxUDPPreferenceLimit = 32700
)

func (l *LibDefaults) parseOption(key, value, line string) error {
	if target := l.booleanOption(key); target != nil {
		v, err := parseBoolean(value)
		if err != nil {
			return InvalidErrorf("libdefaults section line (%s): %v", line, err)
		}
		*target = v
		return nil
	}
	if target := l.durationOption(key); target != nil {
		v, err := parseDuration(value)
		if err != nil {
			return InvalidErrorf("libdefaults section line (%s): %v", line, err)
		}
		*target = v
		return nil
	}
	if target := l.stringOption(key); target != nil {
		*target = strings.TrimSpace(value)
		return nil
	}
	return l.parseCollectionOption(key, value, line)
}

func (l *LibDefaults) booleanOption(key string) *bool {
	switch key {
	case "allow_weak_crypto":
		return &l.AllowWeakCrypto
	case "canonicalize":
		return &l.Canonicalize
	case "request_pac":
		return &l.RequestPAC
	case "pkinit_require_crl_checking":
		return &l.PKINITRequireCRLCheck
	case "dns_canonicalize_hostname":
		return &l.DNSCanonicalizeHostname
	case "dns_lookup_kdc":
		return &l.DNSLookupKDC
	case "dns_lookup_realm":
		return &l.DNSLookupRealm
	case "forwardable":
		return &l.Forwardable
	case "ignore_acceptor_hostname":
		return &l.IgnoreAcceptorHostname
	case "k5login_authoritative":
		return &l.K5LoginAuthoritative
	case "noaddresses":
		return &l.NoAddresses
	case "proxiable":
		return &l.Proxiable
	case "rdns":
		return &l.RDNS
	case "verify_ap_req_nofail":
		return &l.VerifyAPReqNofail
	default:
		return nil
	}
}

func (l *LibDefaults) durationOption(key string) *time.Duration {
	switch key {
	case "clockskew":
		return &l.Clockskew
	case "renew_lifetime":
		return &l.RenewLifetime
	case "ticket_lifetime":
		return &l.TicketLifetime
	default:
		return nil
	}
}

func (l *LibDefaults) stringOption(key string) *string {
	switch key {
	case "ad_site":
		return &l.ADSite
	case "pkinit_kdc_hostname":
		return &l.PKINITKDCHostname
	case "default_client_keytab_name":
		return &l.DefaultClientKeytabName
	case "default_ccache_name":
		return &l.DefaultCCacheName
	case "default_keytab_name":
		return &l.DefaultKeytabName
	case "default_realm":
		return &l.DefaultRealm
	case "k5login_directory":
		return &l.K5LoginDirectory
	default:
		return nil
	}
}

func (l *LibDefaults) parseCollectionOption(key, value, line string) error {
	if target := l.enctypeListOption(key); target != nil {
		*target = strings.Fields(value)
		return nil
	}
	if target := l.pkinitListOption(key); target != nil {
		*target = append(*target, strings.TrimSpace(value))
		return nil
	}
	switch key {
	case "extra_addresses":
		l.appendExtraAddresses(value)
		return nil
	case "preferred_preauth_types":
		return l.parsePreferredPreauthTypes(value, line)
	case "kdc_default_options":
		return l.parseKDCDefaultOptions(value, line)
	default:
		return l.parseConstrainedOption(key, value, line)
	}
}

func (l *LibDefaults) enctypeListOption(key string) *[]string {
	switch key {
	case "default_tgs_enctypes":
		return &l.DefaultTGSEnctypes
	case "default_tkt_enctypes":
		return &l.DefaultTktEnctypes
	case "permitted_enctypes":
		return &l.PermittedEnctypes
	default:
		return nil
	}
}

func (l *LibDefaults) pkinitListOption(key string) *[]string {
	switch key {
	case "pkinit_anchors":
		return &l.PKINITAnchors
	case "pkinit_identities":
		return &l.PKINITIdentities
	case "pkinit_pool":
		return &l.PKINITPool
	default:
		return nil
	}
}

func (l *LibDefaults) appendExtraAddresses(value string) {
	for ip := range strings.SplitSeq(strings.TrimSpace(value), ",") {
		if eip := net.ParseIP(ip); eip != nil {
			l.ExtraAddresses = append(l.ExtraAddresses, eip)
		}
	}
}

func (l *LibDefaults) parsePreferredPreauthTypes(value, line string) error {
	var types []int
	for s := range strings.SplitSeq(strings.TrimSpace(value), ",") {
		i, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return InvalidErrorf("libdefaults section line (%s): %v", line, err)
		}
		types = append(types, int(i))
	}
	l.PreferredPreauthTypes = types
	return nil
}

func (l *LibDefaults) parseKDCDefaultOptions(value, line string) error {
	value = strings.ReplaceAll(strings.TrimSpace(value), "0x", "")
	b, err := hex.DecodeString(value)
	if err != nil {
		return InvalidErrorf("libdefaults section line (%s): %v", line, err)
	}
	l.KDCDefaultOptions.Bytes = b
	l.KDCDefaultOptions.BitLength = len(b) * bitsPerByte
	return nil
}

func (l *LibDefaults) parseConstrainedOption(key, value, line string) error {
	switch key {
	case "ccache_type":
		return parseLibDefaultsUint(&l.CCacheType, value, line, maxCCacheType)
	case "udp_preference_limit":
		return parseLibDefaultsUint(&l.UDPPreferenceLimit, value, line, maxUDPPreferenceLimit)
	case "kdc_timesync":
		return parseLibDefaultsInt(&l.KDCTimeSync, value, line, 0)
	case "safe_checksum_type":
		return parseLibDefaultsInt(&l.SafeChecksumType, value, line, 0)
	case "realm_try_domains":
		return parseLibDefaultsInt(&l.RealmTryDomains, value, line, -1)
	case "pkinit_dh_min_bits":
		return l.parsePKINITDHMinBits(value, line)
	case "pkinit_eku_checking":
		return l.parsePKINITEKUChecking(value, line)
	}
	return nil
}

func parseLibDefaultsUint(target *int, value, line string, maximum uint64) error {
	v, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || v > maximum {
		return InvalidErrorf("libdefaults section line (%s)", line)
	}
	*target = int(v)
	return nil
}

func parseLibDefaultsInt(target *int, value, line string, minimum int64) error {
	v, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
	if err != nil || v < minimum {
		return InvalidErrorf("libdefaults section line (%s)", line)
	}
	*target = int(v)
	return nil
}

func (l *LibDefaults) parsePKINITDHMinBits(value, line string) error {
	v, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || v < 1024 {
		return InvalidErrorf("libdefaults section line (%s): invalid PKINIT DH minimum", line)
	}
	l.PKINITDHMinBits = v
	return nil
}

func (l *LibDefaults) parsePKINITEKUChecking(value, line string) error {
	value = strings.TrimSpace(value)
	if value != "kdc" && value != "kpServerAuth" && value != "none" {
		return InvalidErrorf("libdefaults section line (%s): invalid PKINIT EKU checking mode", line)
	}
	l.PKINITEKUChecking = value
	return nil
}
