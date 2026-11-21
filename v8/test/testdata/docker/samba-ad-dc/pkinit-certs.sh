#!/usr/bin/env bash
set -euo pipefail
umask 077

# Only for the disposable domain. The destination must not already exist.
dir=$1
mkdir -m 0700 -- "$dir"
cd -- "$dir"
trap 'rm -f -- ca.key ca.srl client.csr kdc.csr client.ext kdc.ext' EXIT

openssl req -new -x509 -newkey rsa:3072 -noenc -days 2 -sha256 \
    -subj '/CN=gokrb5 Samba PKINIT Test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout ca.key -out ca.pem

issue() {
    local name=$1 subject=$2 san=$3 eku=$4
    openssl req -new -newkey rsa:2048 -noenc \
        -subj "/CN=${subject}" -keyout "${name}.key" -out "${name}.csr"
    cat >"${name}.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=${eku}
subjectAltName=${san}
EOF
    openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 1 -sha256 -extfile "${name}.ext" -out "${name}.pem"
}

issue kdc dc.samba.gokrb5.test 'DNS:dc.samba.gokrb5.test' '1.3.6.1.5.2.3.5'
issue client testuser 'otherName:1.3.6.1.4.1.311.20.2.3;UTF8:testuser@SAMBA.GOKRB5.TEST' 'clientAuth,1.3.6.1.5.2.3.4'

mkdir -m 0700 kdc client
cp ca.pem kdc/ca.pem
mv ca.pem client.pem client.key client/
mv kdc.pem kdc.key kdc/
