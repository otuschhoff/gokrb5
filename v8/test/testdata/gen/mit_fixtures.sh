#!/bin/sh
set -eu

umask 077

output_dir=${1:-}
if [ -z "$output_dir" ]; then
	printf 'usage: %s OUTPUT_DIR\n' "$0" >&2
	exit 2
fi

for command_name in go ktutil klist kinit kvno krb5-config xxd; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		printf 'missing required command: %s\n' "$command_name" >&2
		exit 1
	fi
done

principal=${MIT_FIXTURE_PRINCIPAL:-testuser1@TEST.GOKRB5}
password=${MIT_FIXTURE_PASSWORD:-passwordvalue}
service_principal=${MIT_FIXTURE_SERVICE_PRINCIPAL:-HTTP/host.test.gokrb5@TEST.GOKRB5}
realm=${principal##*@}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
mkdir -p "$output_dir"

run_ktutil() {
	ktutil >"$work_dir/ktutil.out" 2>"$work_dir/ktutil.err"
}

add_password_entry() {
	entry_principal=$1
	kvno=$2
	etype=$3
	keytab_path=$4
	salt=${5:-}
	if [ -n "$salt" ]; then
		printf 'addent -password -p %s -k %s -e %s -s %s\n%s\nwkt %s\nquit\n' \
			"$entry_principal" "$kvno" "$etype" "$salt" "$password" "$keytab_path" | run_ktutil
	else
		printf 'addent -password -p %s -k %s -e %s\n%s\nwkt %s\nquit\n' \
			"$entry_principal" "$kvno" "$etype" "$password" "$keytab_path" | run_ktutil
	fi
}

append_password_entry() {
	entry_principal=$1
	kvno=$2
	etype=$3
	keytab_path=$4
	printf 'rkt %s\naddent -password -p %s -k %s -e %s\n%s\nwkt %s.new\nquit\n' \
		"$keytab_path" "$entry_principal" "$kvno" "$etype" "$password" "$keytab_path" | run_ktutil
	mv "$keytab_path.new" "$keytab_path"
}

all_etypes="$work_dir/keytab_all_etypes"
for etype in \
	aes128-cts-hmac-sha1-96 \
	aes256-cts-hmac-sha1-96 \
	aes128-cts-hmac-sha256-128 \
	aes256-cts-hmac-sha384-192 \
	arcfour-hmac \
	des3-cbc-sha1; do
	if [ ! -f "$all_etypes" ]; then
		add_password_entry "$principal" 1 "$etype" "$all_etypes"
	else
		append_password_entry "$principal" 1 "$etype" "$all_etypes"
	fi
done

kvno_300="$work_dir/keytab_kvno_300"
add_password_entry "$principal" 300 aes256-cts-hmac-sha1-96 "$kvno_300"

unordered="$work_dir/keytab_multi_kvno_unordered"
add_password_entry "$principal" 3 aes256-cts-hmac-sha1-96 "$unordered"
append_password_entry "$principal" 4 aes256-cts-hmac-sha1-96 "$unordered"

multi_principal="$work_dir/keytab_multi_principal"
add_password_entry "$principal" 1 aes256-cts-hmac-sha1-96 "$multi_principal"
append_password_entry "$service_principal" 2 aes128-cts-hmac-sha1-96 "$multi_principal"
append_password_entry "host/host.other.example@OTHER.EXAMPLE" 3 arcfour-hmac "$multi_principal"

ad_salt="$work_dir/keytab_ad_host_salt"
add_password_entry "host/host.test.gokrb5@$realm" 1 aes256-cts-hmac-sha1-96 "$ad_salt" \
	"${MIT_FIXTURE_AD_SALT:-${realm}hosthost.test.gokrb5}"

enterprise="$work_dir/keytab_enterprise_principal"
add_password_entry "user\\@corp.example@$realm" 1 aes256-cts-hmac-sha1-96 "$enterprise"

helper="$work_dir/derive.go"
cat >"$helper" <<'EOF'
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func records(b []byte) ([][]byte, error) {
	if len(b) < 2 || b[0] != 5 || b[1] != 2 {
		return nil, fmt.Errorf("input is not a v2 keytab")
	}
	var out [][]byte
	for offset := 2; offset < len(b); {
		if len(b)-offset < 4 {
			return nil, fmt.Errorf("truncated record length at offset %d", offset)
		}
		length := int(binary.BigEndian.Uint32(b[offset : offset+4]))
		if length <= 0 || len(b)-offset-4 < length {
			return nil, fmt.Errorf("invalid record length %d at offset %d", length, offset)
		}
		record := append([]byte(nil), b[offset:offset+4+length]...)
		out = append(out, record)
		offset += 4 + length
	}
	return out, nil
}

func write(path string, version byte, rs [][]byte) error {
	b := []byte{5, version}
	for _, record := range rs {
		b = append(b, record...)
	}
	return os.WriteFile(path, b, 0600)
}

func principalEnd(record []byte) (int, error) {
	if len(record) < 10 {
		return 0, fmt.Errorf("record too short")
	}
	components := int(binary.BigEndian.Uint16(record[4:6]))
	offset := 6
	for index := 0; index < components+1; index++ {
		if len(record)-offset < 2 {
			return 0, fmt.Errorf("truncated principal")
		}
		length := int(binary.BigEndian.Uint16(record[offset : offset+2]))
		offset += 2 + length
		if offset > len(record) {
			return 0, fmt.Errorf("truncated principal data")
		}
	}
	if len(record)-offset < 4 {
		return 0, fmt.Errorf("missing name type")
	}
	return offset + 4, nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: derive MODE INPUT OUTPUT")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	rs, err := records(b)
	if err != nil {
		panic(err)
	}
	switch os.Args[1] {
	case "timestamp":
		for _, record := range rs {
			offset, offsetErr := principalEnd(record)
			if offsetErr != nil {
				panic(offsetErr)
			}
			binary.BigEndian.PutUint32(record[offset:offset+4], 1700000000)
		}
		err = write(os.Args[3], 2, rs)
	case "enterprise":
		if len(rs) != 1 {
			panic("enterprise fixture needs one record")
		}
		offset, offsetErr := principalEnd(rs[0])
		if offsetErr != nil {
			panic(offsetErr)
		}
		binary.BigEndian.PutUint32(rs[0][offset-4:offset], 10)
		err = write(os.Args[3], 2, rs)
	case "unordered":
		if len(rs) != 2 {
			panic("unordered fixture needs two records")
		}
		for index, timestamp := range []uint32{1700000200, 1700000100} {
			offset, offsetErr := principalEnd(rs[index])
			if offsetErr != nil {
				panic(offsetErr)
			}
			binary.BigEndian.PutUint32(rs[index][offset:offset+4], timestamp)
		}
		err = write(os.Args[3], 2, rs)
	case "middle-hole":
		if len(rs) < 3 {
			panic("middle-hole fixture needs at least three records")
		}
		length := binary.BigEndian.Uint32(rs[1][:4])
		binary.BigEndian.PutUint32(rs[1][:4], uint32(-int32(length)))
		err = write(os.Args[3], 2, rs)
	case "eof-hole":
		last := len(rs) - 1
		length := binary.BigEndian.Uint32(rs[last][:4])
		binary.BigEndian.PutUint32(rs[last][:4], uint32(-int32(length)))
		err = write(os.Args[3], 2, rs)
	case "no-kvno32":
		if len(rs) != 1 || len(rs[0]) < 8 {
			panic("no-kvno32 fixture needs one complete record")
		}
		rs[0] = rs[0][:len(rs[0])-4]
		binary.BigEndian.PutUint32(rs[0][:4], uint32(len(rs[0])-4))
		err = write(os.Args[3], 2, rs)
	default:
		panic("unknown mode: " + os.Args[1])
	}
	if err != nil {
		panic(err)
	}
}
EOF

for fixture in "$all_etypes" "$kvno_300" "$unordered" "$multi_principal" "$ad_salt" "$enterprise"; do
	go run "$helper" timestamp "$fixture" "$fixture.normalized"
	mv "$fixture.normalized" "$fixture"
done
go run "$helper" enterprise "$enterprise" "$enterprise.derived"
mv "$enterprise.derived" "$enterprise"
go run "$helper" unordered "$unordered" "$unordered.derived"
mv "$unordered.derived" "$unordered"
go run "$helper" middle-hole "$all_etypes" "$work_dir/keytab_kadmin_ktremove_holes"
go run "$helper" eof-hole "$all_etypes" "$work_dir/keytab_kadmin_ktremove_hole_at_eof"
go run "$helper" no-kvno32 "$kvno_300" "$work_dir/keytab_no_kvno32_trailer"

# MIT no longer writes v1 keytabs. These minimal fixtures are specification-derived
# in both byte orders and contain one AES128 key with fixed, non-secret key bytes.
printf '%s' '0501000000330002000b544553542e474f4b52423500097465737475736572316553f1000500110010000102030405060708090a0b0c0d0e0f' | \
	xxd -r -p >"$work_dir/keytab_v1_big_endian"
printf '%s' '05013300000002000b00544553542e474f4b524235090074657374757365723100f153650511001000000102030405060708090a0b0c0d0e0f' | \
	xxd -r -p >"$work_dir/keytab_v1_little_endian"

for fixture in \
	keytab_all_etypes \
	keytab_kvno_300 \
	keytab_multi_kvno_unordered \
	keytab_multi_principal \
	keytab_kadmin_ktremove_holes \
	keytab_kadmin_ktremove_hole_at_eof \
	keytab_v1_little_endian \
	keytab_v1_big_endian \
	keytab_ad_host_salt \
	keytab_enterprise_principal \
	keytab_no_kvno32_trailer; do
	xxd -p -c 1048576 "$work_dir/$fixture" >"$output_dir/${fixture}.hex"
done

for fixture in keytab_all_etypes keytab_kvno_300 keytab_multi_kvno_unordered keytab_multi_principal; do
	LC_ALL=C TZ=UTC klist -kte "$work_dir/$fixture" | \
		sed "1s|.*|Keytab name: FILE:$fixture|" >"$output_dir/klist_kte_${fixture#keytab_}.txt"
done

capture_ccache() {
	fixture_name=$1
	shift
	cache="$work_dir/$fixture_name"
	rm -f "$cache"
	KRB5CCNAME="FILE:$cache" "$@"
	xxd -p -c 1048576 "$cache" >"$output_dir/${fixture_name}.hex"
	kdestroy -c "FILE:$cache" >/dev/null 2>&1 || true
}

if [ -n "${MIT_FIXTURE_KRB5_CONFIG:-}" ]; then
	export KRB5_CONFIG=$MIT_FIXTURE_KRB5_CONFIG
	password_file="$work_dir/password"
	printf '%s\n' "$password" >"$password_file"
	capture_ccache ccache_v4_kinit_password sh -c 'kinit "$1" <"$2"' sh "$principal" "$password_file"
	capture_ccache ccache_v4_kinit_keytab kinit -kt "$all_etypes" "$principal"
	cache="$work_dir/ccache_v4_with_service_ticket"
	rm -f "$cache"
	KRB5CCNAME="FILE:$cache" kinit "$principal" <"$password_file"
	KRB5CCNAME="FILE:$cache" kvno "$service_principal"
	xxd -p -c 1048576 "$cache" >"$output_dir/ccache_v4_with_service_ticket.hex"
	kdestroy -c "FILE:$cache" >/dev/null 2>&1 || true
	capture_ccache ccache_v4_renewable_forwardable sh -c \
		'KRB5CCNAME="$1" kinit -f -r 7d "$2" <"$3"' sh "FILE:$work_dir/ccache_v4_renewable_forwardable" "$principal" "$password_file"

	config_v3="$work_dir/krb5-v3.conf"
	awk '
		/^\[libdefaults\]/ && !inserted { print; print " ccache_type = 3"; inserted=1; next }
		{ print }
	' "$MIT_FIXTURE_KRB5_CONFIG" >"$config_v3"
	KRB5_CONFIG="$config_v3" capture_ccache ccache_v3 sh -c 'kinit "$1" <"$2"' sh "$principal" "$password_file"
else
	printf '%s\n' 'ccache capture skipped: set MIT_FIXTURE_KRB5_CONFIG to a TEST.GOKRB5 configuration' >&2
fi

{
	printf 'MIT Kerberos version: '
	krb5-config --version
	printf 'Principal: %s\n' "$principal"
	printf 'Service principal: %s\n' "$service_principal"
	printf 'Generated (UTC): '
	date -u '+%Y-%m-%dT%H:%M:%SZ'
} >"$output_dir/METADATA.txt"

printf 'fixtures written to %s\n' "$output_dir"