#!/usr/bin/env bash
# Issues the certificates the tests use and writes them next to this script.
# Run it by hand, in a container that has the CryptoPro CSP; the tests
# themselves take the artefacts as they are.
#
#   EXTERNAL_CSP_LICENSE=<licence> ./make-pki.sh
#
# Two roots and six leaves, all good for forty-two years.  Longer was possible
# for RSA but not for GOST: the CSP wraps a validity over about 24700 days -
# 25000 comes back as 1959 - and this keeps well clear of that edge:
#
#   gost_ca      -> gost_server, gost_client            keys made in the CSP
#   rsa_ca       -> rsa_cpro_server, rsa_cpro_client    RSA keys made in the CSP
#                -> rsa_ossl_server, rsa_ossl_client    RSA keys made by OpenSSL
#
# The RSA root is OpenSSL's so that either stack can verify the chain, and its
# key is kept beside it on purpose: these are throwaway test certificates, and
# more leaves should be issuable without a CSP at hand.
set -euo pipefail

out=${OUT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
pass=${PFX_PASSWORD:-stunnel-test}
days=15330   # forty-two years
cpro=/opt/cprocsp/bin/amd64
prov='Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider'

: "${EXTERNAL_CSP_LICENSE:?set EXTERNAL_CSP_LICENSE}"
cpconfig=/opt/cprocsp/sbin/amd64/cpconfig
$cpconfig -license -set "$EXTERNAL_CSP_LICENSE" >/dev/null

# The CSP will not make a key without a random source of its own, and the
# pool it reads has a shape of its own: random bytes are refused.  It comes
# from the provider's own kit.
if [ ! -s /var/opt/cprocsp/dsrf/db1/kis_1 ]; then
	: "${CSP_DSRF:?point CSP_DSRF at the dsrf.tar of the provider kit}"
	$cpconfig -hardware rndm -add cpsd -name 'cpsd rng' -level 2 >/dev/null
	mkdir -p /var/opt/cprocsp/dsrf
	tar -xf "$CSP_DSRF" -C /var/opt/cprocsp/dsrf
	for db in db1 db2; do
		$cpconfig -hardware rndm -configure cpsd -add string "/$db/kis_1" \
			"/var/opt/cprocsp/dsrf/$db/kis_1" >/dev/null
	done
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/ext.cnf" <<'CNF'
[server]
subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
[client]
extendedKeyUsage=clientAuth
basicConstraints=CA:FALSE
CNF

thumb() { # store dn
	"$cpro/certmgr" -list -store "$1" -dn "CN=$2" 2>/dev/null |
		awk -F: '/SHA1 Thumbprint/{gsub(/[[:space:]]/,"",$2); print $2; exit}'
}

forget() { # dn container store
	"$cpro/certmgr" -delete -all -store "$3" -dn "CN=$1" </dev/null >/dev/null 2>&1 || true
	"$cpro/csptest" -passwd -deletekeyset -container "$2" </dev/null >/dev/null 2>&1 || true
}

echo "== GOST root =="
forget 'stunnel test GOST CA' '\\.\HDIMAGE\stunnel-test-gost-ca' uRoot
printf 'o\n' | "$cpro/csptest" -minica -root -silent -dn 'CN=stunnel test GOST CA' \
	-container '\\.\HDIMAGE\stunnel-test-gost-ca' -password '' -exportable \
	-provname "$prov" -provtype 80 -from 0 -until $days \
	-store uRoot -fcert "$out/gost_ca.cer" >/dev/null
gost_ca=$(thumb uRoot 'stunnel test GOST CA')
[ -n "$gost_ca" ] || { echo "no GOST root" >&2; exit 1; }
echo "gost_ca $gost_ca"

gost_leaf() { # name cn eku [altname...]
	local name=$1 cn=$2 eku=$3 cont="\\\\.\\HDIMAGE\\stunnel-test-$1"
	shift 3
	local alt=()
	for a in "$@"; do alt+=(-altname "$a"); done
	forget "$cn" "$cont" uMy
	"$cpro/csptest" -minica -request -silent -dn "CN=$cn" -container "$cont" \
		-password '' -exportable -provname "$prov" -provtype 80 -keytype both \
		-frequest "$work/$name.req" >/dev/null
	"$cpro/csptest" -minica -process -silent -frequest "$work/$name.req" \
		-issuer "$gost_ca" -istore uRoot -ipassword '' -eku "$eku" \
		"${alt[@]}" -from 0 -until $days -fcert "$out/$name.cer" >/dev/null
	"$cpro/certmgr" -install -store uMy -file "$out/$name.cer" -container "$cont" \
		-to-container -pin '' -silent >/dev/null
	"$cpro/certmgr" -export -pfx -silent -store uMy -thumbprint "$(thumb uMy "$cn")" \
		-dest "$out/$name.pfx" -pin "$pass" >/dev/null
	echo "$name $(thumb uMy "$cn")"
}

echo "== GOST leaves =="
gost_leaf gost_server '127.0.0.1' 1.3.6.1.5.5.7.3.1 127.0.0.1 localhost
gost_leaf gost_client 'stunnel test GOST client' 1.3.6.1.5.5.7.3.2

echo "== RSA root =="
openssl req -x509 -newkey rsa:2048 -nodes -days $days \
	-subj '/CN=stunnel test RSA CA' \
	-keyout "$out/rsa_ca.key" -out "$out/rsa_ca.cer" 2>/dev/null

sign() { # csr-file der|pem ext out
	local args=()
	[ "$2" = der ] && args=(-inform DER)
	openssl x509 -req "${args[@]}" -in "$1" -days $days \
		-CA "$out/rsa_ca.cer" -CAkey "$out/rsa_ca.key" -CAcreateserial \
		-extfile "$work/ext.cnf" -extensions "$3" -out "$4" 2>/dev/null
}

rsa_cpro_leaf() { # name cn ext
	local name=$1 cn=$2 ext=$3 cont="\\\\.\\HDIMAGE\\stunnel-test-$1"
	forget "$cn" "$cont" uMy
	"$cpro/csptest" -minica -request -silent -dn "CN=$cn" -container "$cont" \
		-password '' -exportable -provtype 24 -keytype both -length 2048 \
		-frequest "$work/$name.req" >/dev/null
	sign "$work/$name.req" der "$ext" "$out/$name.cer"
	"$cpro/certmgr" -install -store uMy -file "$out/$name.cer" -container "$cont" \
		-to-container -pin '' -silent >/dev/null
	"$cpro/certmgr" -export -pfx -silent -store uMy -thumbprint "$(thumb uMy "$cn")" \
		-dest "$out/$name.pfx" -pin "$pass" >/dev/null
	echo "$name $(thumb uMy "$cn")"
}

rsa_ossl_leaf() { # name cn ext
	local name=$1 cn=$2 ext=$3
	openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$cn" \
		-keyout "$out/$name.key" -out "$work/$name.csr" 2>/dev/null
	sign "$work/$name.csr" pem "$ext" "$out/$name.cer"
	openssl pkcs12 -export -inkey "$out/$name.key" -in "$out/$name.cer" \
		-certfile "$out/rsa_ca.cer" -passout "pass:$pass" -out "$out/$name.pfx"
	echo "$name $(openssl x509 -in "$out/$name.cer" -noout -fingerprint -sha1 |
		sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')"
}

echo "== RSA leaves, keys made in the CSP =="
rsa_cpro_leaf rsa_cpro_server '127.0.0.1' server
rsa_cpro_leaf rsa_cpro_client 'stunnel test RSA CSP client' client

echo "== RSA leaves, keys made by OpenSSL =="
rsa_ossl_leaf rsa_ossl_server '127.0.0.1' server
rsa_ossl_leaf rsa_ossl_client 'stunnel test RSA OpenSSL client' client

echo "== checks =="
openssl verify -CAfile "$out/rsa_ca.cer" \
	"$out/rsa_cpro_server.cer" "$out/rsa_cpro_client.cer" \
	"$out/rsa_ossl_server.cer" "$out/rsa_ossl_client.cer"
for f in "$out"/*.cer; do
	printf '%-24s %s\n' "$(basename "$f")" \
		"$(openssl x509 -in "$f" -noout -enddate 2>/dev/null || echo 'GOST, not readable by this openssl')"
done
for f in "$out"/*.pfx; do
	printf '%-24s ' "$(basename "$f")"
	if openssl pkcs12 -in "$f" -passin "pass:$pass" -noout >/dev/null 2>&1; then
		echo "PKCS#12 opens"
	else
		echo "PKCS#12 present (GOST content, not readable by this openssl)"
	fi
done
