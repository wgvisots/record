#!/bin/sh
# check_stamps.sh — confirm the latest submission was accepted everywhere:
#   FreeTSA: the signed reply in hashes.tsr is valid for hashes.txt
#   Bitcoin: fetch the completed OpenTimestamps proof (commit + push it), verify it
#   GitHub:  everything is committed and pushed
set -eu
export LC_ALL=C
cd "$(dirname "$0")"
. ./common.sh
check_pin cacert.pem cacert.sha256
check_pin tsa.crt    tsa.sha256

LIST=hashes.txt
status=0
fail() { status=1; }

# --- FreeTSA ---------------------------------------------------------------
if [ ! -f hashes.tsr ]; then
  echo "FreeTSA:  no hashes.tsr"; fail
else
  r=$(tsr_check "$LIST" hashes.tsr) || fail
  echo "FreeTSA:  $r"
fi

# --- OpenTimestamps --------------------------------------------------------
if [ ! -f "$LIST.ots" ]; then
  echo "Bitcoin:  no $LIST.ots yet"; fail
elif ! have_ots; then
  echo "Bitcoin:  python3-opentimestamps not installed; skipped"; fail
else
  # Fetch the Bitcoin attestation from the calendars, in place.  Upgrading
  # the proof is safe even when it belongs to an older list: that list is
  # in git history, and prove.sh will match the two up.
  ots_mini upgrade "$LIST.ots" >/dev/null 2>&1 || true   # exits 2 while pending
  if [ -n "$(git status --porcelain -- "$LIST.ots")" ]; then
    git add "$LIST.ots"
    git commit -q -m "Upgrade OpenTimestamps proof $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Bitcoin:  fetched completed proof from calendars and committed it"
  fi

  if [ "$(ots_digest "$LIST.ots")" = "$(sha256_of "$LIST")" ]; then
    r=$(ots_check "$LIST" "$LIST.ots") || fail
    echo "Bitcoin:  $r"
  else
    # Proof is for an earlier list version (e.g. ots wasn't installed for the
    # latest hasher run).  Still worth checking against the version it covers.
    d=$(ots_digest "$LIST.ots"); old=
    for c in $(git rev-list HEAD -- "$LIST"); do
      if [ "$(git show "$c:$LIST" | sha256sum | cut -c1-64)" = "$d" ]; then old=$c; break; fi
    done
    if [ -z "$old" ]; then
      echo "Bitcoin:  FAILED: $LIST.ots matches no committed version of $LIST"; fail
    else
      tmpl=$(mktemp)
      git show "$old:$LIST" > "$tmpl"
      r=$(ots_check "$tmpl" "$LIST.ots") || fail
      rm -f "$tmpl"
      echo "Bitcoin:  $r"
      echo "          (covers $LIST as of commit $(git rev-parse --short "$old"); the newest"
      echo "           hashes have no Bitcoin proof yet; the next hasher.sh run will add one)"
      fail
    fi
  fi
fi

# --- GitHub ----------------------------------------------------------------
if [ -n "$(git status --porcelain -- "$LIST" hashes.tsr "$LIST.ots")" ]; then
  echo "GitHub:   uncommitted changes to the list or proofs (re-run hasher.sh)"; fail
fi
git push -q 2>/dev/null || true
if ! git fetch -q origin 2>/dev/null; then
  echo "GitHub:   could not reach origin"; fail
elif [ -n "$(git rev-list '@{u}..HEAD' 2>/dev/null)" ]; then
  echo "GitHub:   $(git rev-list --count '@{u}..HEAD') commit(s) NOT pushed"; fail
else
  echo "GitHub:   up to date ($(git rev-parse --short HEAD) is on $(git rev-parse --abbrev-ref '@{u}'))"
fi

exit $status
