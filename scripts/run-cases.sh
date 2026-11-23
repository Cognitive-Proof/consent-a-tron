#!/usr/bin/env bash
# Runs the positive path and each negative case, checking that verify
# reports the expected status code. Needs network for the TSA only.
set -uo pipefail
cd "$(dirname "$0")/.."

cargo build -q --bins || exit 1
BIN=target/debug
OUT=out/cases
rm -rf "$OUT" && mkdir -p "$OUT"
[ -d pki ] || ./scripts/make-pki.sh >/dev/null

pass=0 fail=0
expect() { # name expected-code expected-exit verify-args...
  local name=$1 code=$2 want_exit=$3; shift 3
  local log="$OUT/$name.log"
  "$BIN/verify" "$@" >"$log" 2>&1
  local got_exit=$?
  if grep -q -- "$code" "$log" && [ "$got_exit" = "$want_exit" ]; then
    echo "PASS  $name  ($code)"; pass=$((pass + 1))
  else
    echo "FAIL  $name  wanted $code exit=$want_exit, got exit=$got_exit"; sed 's/^/      /' "$log"; fail=$((fail + 1))
  fi
}

case_dir() { mkdir -p "$OUT/$1"; echo "$OUT/$1"; }

# Base credential, minted before any manifest exists.
BASE=$(case_dir base)
"$BIN/mint" fixtures/sample.jpg "$BASE" >/dev/null || exit 1
"$BIN/sign" fixtures/sample.jpg "$BASE/credential.json" "$BASE/signed.jpg" >/dev/null || exit 1

expect valid             "credential.valid"              0 "$BASE/signed.jpg" --agreement "$BASE/private-agreement.json"
expect offline           "status_unchecked"              0 "$BASE/signed.jpg" --offline

# A different file signed with the same credential.
D=$(case_dir other-asset); cp "$BASE"/*.json "$D"/
{ cat fixtures/sample.jpg; printf 'trailing bytes after EOI'; } > "$D/other.jpg"
"$BIN/sign" "$D/other.jpg" "$D/credential.json" "$D/signed.jpg" >/dev/null
expect binding_mismatch  "binding_mismatch"              1 "$D/signed.jpg"

# Participant never cosigned.
D=$(case_dir no-participant-proof); cp "$BASE"/*.json "$D"/
jq '.proof |= .[:1]' "$BASE/credential.json" > "$D/credential.json"
"$BIN/sign" fixtures/sample.jpg "$D/credential.json" "$D/signed.jpg" >/dev/null
expect participant_proof "participant_proof_missing"     1 "$D/signed.jpg"

# Credential is for someone other than the identity assertion signer.
D=$(case_dir other-participant)
"$(brew --prefix openssl@3)/bin/openssl" genpkey -algorithm ED25519 -out "$D/someone-else.key" 2>/dev/null
MINT_PARTICIPANT_KEY="$D/someone-else.key" "$BIN/mint" fixtures/sample.jpg "$D" >/dev/null
"$BIN/sign" fixtures/sample.jpg "$D/credential.json" "$D/signed.jpg" >/dev/null
expect participant_mismatch "participant_mismatch"       1 "$D/signed.jpg"

# Guild registry does not authorize the requester.
D=$(case_dir not-authorized); cp "$BASE"/*.json "$BASE/signed.jpg" "$D"/
jq '.authorizations[0].authorized = false' "$BASE/trqp-registry.json" > "$D/trqp-registry.json"
expect not_authorized    "issuer_not_authorized"         1 "$D/signed.jpg"

# Consent withdrawn after publication: same file, new status list.
D=$(case_dir revoked); cp "$BASE"/*.json "$BASE/signed.jpg" "$D"/
"$BIN/revoke" "$D/credential.json" "$D/status-list.json" >/dev/null
expect revoked           "revoked"                       1 "$D/signed.jpg"
expect revoked_offline   "status_unchecked"              0 "$D/signed.jpg" --offline

# A public term edited after both parties signed.
D=$(case_dir tampered); cp "$BASE"/*.json "$D"/
jq '.credentialSubject.consent.aiTraining = "allowed"' "$BASE/credential.json" > "$D/credential.json"
"$BIN/sign" fixtures/sample.jpg "$D/credential.json" "$D/signed.jpg" >/dev/null
expect tampered_terms    "signature_invalid"             1 "$D/signed.jpg"

# Revealed private agreement does not match the digest.
D=$(case_dir wrong-agreement); cp "$BASE"/*.json "$BASE/signed.jpg" "$D"/
jq '.agreement.fee.amount = "150.00"' "$BASE/private-agreement.json" > "$D/private-agreement.json"
expect wrong_agreement   "private_terms_mismatch"        1 "$D/signed.jpg" --agreement "$D/private-agreement.json"

# Bare CAWG credential: no guild terms, trust registry or status list.
D=$(case_dir bare)
MINT_BARE=1 "$BIN/mint" fixtures/sample.jpg "$D" >/dev/null
"$BIN/sign" fixtures/sample.jpg "$D/credential.json" "$D/signed.jpg" >/dev/null
expect bare              "not_withdrawable"              0 "$D/signed.jpg"
expect bare_ungoverned   "issuer_ungoverned"             0 "$D/signed.jpg"
expect bare_offline      "not_withdrawable"              0 "$D/signed.jpg" --offline

# A bare credential past its expiry date.
D=$(case_dir bare-expired)
MINT_BARE=1 MINT_VALID_UNTIL=2026-01-01T00:00:00Z "$BIN/mint" fixtures/sample.jpg "$D" >/dev/null
"$BIN/sign" fixtures/sample.jpg "$D/credential.json" "$D/signed.jpg" >/dev/null
expect bare_expired      "expired"                       1 "$D/signed.jpg"

# Creative Commons license: one person licenses their own file, as both
# issuer and subject, with a single signature.
D=$(case_dir license)
MINT_LICENSE=1 "$BIN/mint" fixtures/sample.jpg "$D" >/dev/null
"$BIN/sign" fixtures/sample.jpg "$D/credential.json" "$D/signed.jpg" >/dev/null
expect license           "credential.valid"              0 "$D/signed.jpg"
expect license_one_proof "1 eddsa-jcs-2022 proofs"       0 "$D/signed.jpg"

# A license signed by someone other than the identity assertion signer.
D=$(case_dir license-other-signer)
MINT_LICENSE=1 "$BIN/mint" fixtures/sample.jpg "$D" >/dev/null
jq --arg did "$(jq -r .issuer "$BASE/credential.json")" '.issuer = $did' "$D/credential.json" > "$D/c.json" && mv "$D/c.json" "$D/credential.json"
"$BIN/sign" fixtures/sample.jpg "$D/credential.json" "$D/signed.jpg" >/dev/null
expect license_forged    "signature_invalid"             1 "$D/signed.jpg"

echo; echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
