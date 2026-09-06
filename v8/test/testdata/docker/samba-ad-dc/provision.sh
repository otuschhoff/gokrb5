#!/usr/bin/env bash
set -euo pipefail

# TEST-ONLY CREDENTIALS. Never use this disposable domain or its keys in production.
realm="${SAMBA_REALM:-SAMBA.GOKRB5.TEST}"
domain="${SAMBA_DOMAIN:-GOKRB5}"
hostname="${SAMBA_HOSTNAME:-dc}"
admin_password="${SAMBA_ADMIN_PASSWORD:-AdminPassw0rd!}"
test_user="${SAMBA_TEST_USER:-testuser}"
test_password="${SAMBA_TEST_PASSWORD:-TestPassw0rd!}"
delegator_user="${SAMBA_DELEGATOR_USER:-frontendsvc}"
delegator_password="${SAMBA_DELEGATOR_PASSWORD:-FrontendPassw0rd!}"
target_user="${SAMBA_TARGET_USER:-targetsvc}"
target_password="${SAMBA_TARGET_PASSWORD:-TargetPassw0rd!}"
denied_user="${SAMBA_DENIED_USER:-deniedsvc}"
denied_password="${SAMBA_DENIED_PASSWORD:-DeniedPassw0rd!}"
disabled_user="${SAMBA_DISABLED_USER:-disableduser}"
disabled_password="${SAMBA_DISABLED_PASSWORD:-DisabledPassw0rd!}"
artifact_dir="${SAMBA_ARTIFACT_DIR:-/artifacts}"

realm_lower="${realm,,}"
dc_fqdn="${hostname}.${realm_lower}"
host_spn="host/${dc_fqdn}"
service_spn="HTTP/frontend.${realm_lower}"
target_spn="HTTP/target.${realm_lower}"
denied_spn="HTTP/denied.${realm_lower}"
machine_account="${hostname^^}$"

for command in for-any-protocol add-service add-principal; do
    if ! samba-tool delegation "${command}" --help >/dev/null 2>&1; then
        echo "samba-tool delegation ${command} is required by the integration lab" >&2
        exit 1
    fi
done

if [[ ! -s /var/lib/samba/private/sam.ldb ]]; then
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --realm="${realm}" \
        --domain="${domain}" \
        --host-name="${hostname}" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="${admin_password}" \
        --use-rfc2307
fi
export KRB5_CONFIG=/var/lib/samba/private/krb5.conf

create_user() {
    local account="$1"
    local password="$2"
    if ! samba-tool user show "${account}" >/dev/null 2>&1; then
        samba-tool user create "${account}" "${password}"
    fi
}

add_spn() {
    local spn="$1"
    local account="$2"
    if ! samba-tool spn list "${account}" | grep -Fqi "${spn}"; then
        samba-tool spn add "${spn}" "${account}"
    fi
}

create_user "${test_user}" "${test_password}"
create_user "${delegator_user}" "${delegator_password}"
create_user "${target_user}" "${target_password}"
create_user "${denied_user}" "${denied_password}"
create_user "${disabled_user}" "${disabled_password}"
samba-tool user disable "${disabled_user}"
add_spn "${service_spn}" "${delegator_user}"
add_spn "${target_spn}" "${target_user}"
add_spn "${denied_spn}" "${denied_user}"

samba-tool delegation for-any-protocol "${delegator_user}" on
if ! samba-tool delegation show "${delegator_user}" | grep -Fq "${target_spn}"; then
    samba-tool delegation add-service "${delegator_user}" "${target_spn}"
fi
if ! samba-tool delegation show "${target_user}" | grep -Fq "${delegator_user}"; then
    samba-tool delegation add-principal "${target_user}" "${delegator_user}"
fi

mkdir -p "${artifact_dir}"
rm -f "${artifact_dir}/krb5.keytab"
samba-tool domain exportkeytab "${artifact_dir}/krb5.keytab"
for principal in "${host_spn}" "${service_spn}" "${target_spn}" "${denied_spn}"; do
    samba-tool domain exportkeytab "${artifact_dir}/krb5.keytab" --principal="${principal}"
done
if [[ ! -s "${artifact_dir}/krb5.keytab" ]]; then
    echo "samba-tool produced an empty keytab" >&2
    exit 1
fi
printf '%s@%s\n' "${test_user}" "${realm}" >"${artifact_dir}/user"
printf '%s\n' "${test_password}" >"${artifact_dir}/pw"
cat >"${artifact_dir}/environment" <<EOF
TESTAD=1
TESTAD_KIND=samba
TESTAD_REALM=${realm}
TESTAD_KDC=127.0.0.1:88
TESTAD_SERVICE_SPN=${service_spn}
TESTAD_DELEGATOR=${delegator_user}
TESTAD_TARGET_SPN=${target_spn}
TESTAD_DENIED_SPN=${denied_spn}
TESTAD_DISABLED_USER=${disabled_user}
TESTAD_DISABLED_PASSWORD=${disabled_password}
EOF
chmod 0644 "${artifact_dir}/krb5.keytab" "${artifact_dir}/user" "${artifact_dir}/pw" "${artifact_dir}/environment"

exec samba --foreground --no-process-group