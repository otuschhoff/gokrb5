package testdata

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestFixturesDecode(t *testing.T) {
	tests := map[string]struct {
		hex     string
		version byte
	}{
		"keytab all etypes":           {KEYTAB_KTUTIL_ALL_ETYPES, 2},
		"keytab kvno 300":             {KEYTAB_KTUTIL_KVNO_300, 2},
		"keytab unordered kvnos":      {KEYTAB_KTUTIL_MULTI_KVNO_UNORDERED, 2},
		"keytab multiple principals":  {KEYTAB_KTUTIL_MULTI_PRINCIPAL, 2},
		"keytab middle hole":          {KEYTAB_KADMIN_KTREMOVE_HOLES, 2},
		"keytab hole at eof":          {KEYTAB_KADMIN_KTREMOVE_HOLE_AT_EOF, 2},
		"keytab v1 little endian":     {KEYTAB_V1_LITTLE_ENDIAN, 1},
		"keytab v1 big endian":        {KEYTAB_V1_BIG_ENDIAN, 1},
		"keytab explicit AD salt":     {KEYTAB_AD_HOST_SALT, 2},
		"keytab enterprise principal": {KEYTAB_ENTERPRISE_PRINCIPAL, 2},
		"keytab without kvno32":       {KEYTAB_NO_KVNO32_TRAILER, 2},
		"ccache password":             {CCACHE_V4_KINIT_PASSWORD, 4},
		"ccache keytab":               {CCACHE_V4_KINIT_KEYTAB, 4},
		"ccache service ticket":       {CCACHE_V4_WITH_SERVICE_TICKET, 4},
		"ccache renewable":            {CCACHE_V4_RENEWABLE_FORWARDABLE, 4},
		"ccache v3":                   {CCACHE_V3, 3},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture, err := hex.DecodeString(test.hex)
			if err != nil {
				t.Fatalf("fixture is not valid hex: %v", err)
			}
			if len(fixture) < 2 || fixture[0] != 5 || fixture[1] != test.version {
				t.Fatalf("unexpected format header: %x", fixture)
			}
		})
	}

	for name, output := range map[string]string{
		"all etypes":          KLIST_KTE_ALL_ETYPES,
		"kvno 300":            KLIST_KTE_KVNO_300,
		"unordered kvnos":     KLIST_KTE_MULTI_KVNO_UNORDERED,
		"multiple principals": KLIST_KTE_MULTI_PRINCIPAL,
	} {
		if !strings.Contains(output, "KVNO Timestamp") || !strings.HasSuffix(output, "\n") {
			t.Errorf("%s klist fixture is incomplete", name)
		}
	}
}
