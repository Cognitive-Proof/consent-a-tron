#!/usr/bin/env bash
# Generates test-only PKI into ./pki:
#   c2pa-root  -> claim-signer   (ES256, signs the C2PA claim)
#   cawg-root  -> participant    (Ed25519, signs the cawg.identity assertion)
# The participant's Ed25519 key is also used for their did:key, so the
# consent credential's participant proof can be matched to the identity
# assertion signer.
set -euo pipefail

OPENSSL="${OPENSSL:-$(brew --prefix openssl@3 2>/dev/null)/bin/openssl}"
[ -x "$OPENSSL" ] || OPENSSL=openssl
"$OPENSSL" version | grep -q '^OpenSSL 3' || { echo "OpenSSL 3 required"; exit 1; }

cd "$(dirname "$0")/.."
rm -rf pki && mkdir pki && cd pki

ca() { # name subject keyalg...
  local name=$1 subj=$2; shift 2
  "$OPENSSL" genpkey "$@" -out "$name.key"
  "$OPENSSL" req -new -x509 -key "$name.key" -out "$name.pem" -days 3650 -subj "$subj" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
}

leaf() { # name subject issuer eku keyalg...
  local name=$1 subj=$2 issuer=$3 eku=$4; shift 4
  "$OPENSSL" genpkey "$@" -out "$name.key"
  "$OPENSSL" req -new -key "$name.key" -out "$name.csr" -subj "$subj"
  cat > "$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$eku
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
  "$OPENSSL" x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" \
    -CAcreateserial -out "$name.pem" -days 825 -extfile "$name.ext"
  cat "$name.pem" "$issuer.pem" > "$name.chain.pem"
  rm "$name.csr" "$name.ext"
}

ca c2pa-root "/C=US/O=Consent Test/CN=Test C2PA Root" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf claim-signer "/C=US/O=Consent Test/CN=Test Claim Signer" c2pa-root \
  "1.3.6.1.5.5.7.3.36" -algorithm EC -pkeyopt ec_paramgen_curve:P-256

ca cawg-root "/C=US/O=Consent Test/CN=Test CAWG Root" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf participant "/C=US/O=Consent Test/CN=Alex Participant" cawg-root \
  "emailProtection,1.3.6.1.5.5.7.3.36" -algorithm ED25519

# The requester (issuer of the consent credential) only needs a did:key.
"$OPENSSL" genpkey -algorithm ED25519 -out requester.key

rm -f ./*.srl
echo "PKI written to $(pwd)"
