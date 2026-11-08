# Shared helpers for prove.sh and check_stamps.sh.  Source, don't run.
# Each function prints one human-readable line and returns:
#   0 = verified, 1 = failed / mismatch, 2 = pending / not checkable

check_pin() {  # check_pin <cert> <pinfile>
  [ "$(openssl x509 -in "$1" -noout -fingerprint -sha256)" = "$(cat "$2")" ] \
    || { echo "FINGERPRINT MISMATCH: $1" >&2; exit 1; }
}

sha256_of() { sha256sum < "$1" | cut -c1-64; }

# --- RFC 3161 (FreeTSA) -----------------------------------------------------

tsr_time() { openssl ts -reply -in "$1" -text 2>/dev/null | sed -n 's/^Time stamp: //p'; }

tsr_imprint() {  # the SHA-256 the TSA signed, as hex
  openssl ts -reply -in "$1" -text 2>/dev/null \
    | sed -n '/^Message data:/,/^Serial number:/p' \
    | sed -n 's/^ *[0-9a-f]\{4\} - //p' | sed 's/   .*//; s/[- ]//g' | tr -d '\n'
}

tsr_check() {  # tsr_check <list> <tsr>
  if openssl ts -verify -data "$1" -in "$2" \
       -CAfile cacert.pem -untrusted tsa.crt >/dev/null 2>&1; then
    echo "verified, signed $(tsr_time "$2")"; return 0
  fi
  echo "FAILED: signature or data mismatch"; return 1
}

# --- OpenTimestamps (Bitcoin), via ots_mini.py + the apt python3-opentimestamps ---

OTS_PY="$(pwd)/ots_mini.py"   # callers cd here before sourcing
ots_mini() { python3 -I "$OTS_PY" "$@"; }

have_ots() { python3 -I -c 'import opentimestamps' 2>/dev/null; }

ots_digest() { ots_mini info "$1" 2>/dev/null | sed -n 's/^File sha256 hash: //p'; }

ots_check() {  # ots_check <list> <ots>: upgrades in memory only, never the file
  have_ots || { echo "python3-opentimestamps not installed; skipped"; return 2; }
  ots_mini verify "$1" "$2" 2>/dev/null
}
