#!/bin/sh
# prove.sh <photo>...
# For each file: when was its hash first committed, and which timestamp
# proofs (FreeTSA, Bitcoin via OpenTimestamps) cover it.
set -eu
export LC_ALL=C
[ $# -gt 0 ] || { echo "usage: $0 <photo>..." >&2; exit 64; }

# Hash the files before changing directory, so relative paths work.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for f in "$@"; do
  [ -f "$f" ] && [ -r "$f" ] || { echo "cannot read: $f" >&2; exit 66; }
  h=$(sha256sum -- "$f")
  printf '%s\t%s\n' "${h%% *}" "$f"
done > "$tmp/targets"

cd "$(dirname "$0")"
. ./common.sh
check_pin cacert.pem cacert.sha256
check_pin tsa.crt    tsa.sha256

LIST=hashes.txt
repo=$(git remote get-url origin 2>/dev/null \
       | sed -n 's#^git@github.com:\(.*\)\.git$#https://github.com/\1#p; s#^\(https://github.com/.*\)\.git$#\1#p')

describe() {  # describe <commit>
  git log -1 --format='%h  %ad  "%s"' --date=format:'%Y-%m-%d %H:%M %z' "$1"
  if git branch -r --contains "$1" 2>/dev/null | grep -q .; then
    if [ -n "$repo" ]; then echo "              $repo/commit/$(git rev-parse "$1")"; fi
  else
    echo "              (NOT PUSHED to GitHub yet)"
  fi
}

# Index every committed version of the list: "<sha256 of list> <commit>",
# and each proof: "<digest it covers> <commit>", all oldest first.
git rev-list --reverse HEAD -- "$LIST" > "$tmp/list_commits"
while read -r c; do
  git show "$c:$LIST" > "$tmp/list.$c"
  echo "$(sha256_of "$tmp/list.$c") $c"
done < "$tmp/list_commits" > "$tmp/lists"

for c in $(git rev-list --reverse HEAD -- hashes.tsr); do
  git show "$c:hashes.tsr" > "$tmp/tsr.$c" 2>/dev/null || continue
  echo "$(tsr_imprint "$tmp/tsr.$c") $c"
done > "$tmp/tsrs"

: > "$tmp/otss"
if have_ots; then
  for c in $(git rev-list --reverse HEAD -- "$LIST.ots"); do
    git show "$c:$LIST.ots" > "$tmp/ots.$c" 2>/dev/null || continue
    echo "$(ots_digest "$tmp/ots.$c") $c"
  done > "$tmp/otss"
fi

status=0
while IFS="$(printf '\t')" read -r h f; do
  echo "File:         $f"
  echo "SHA-256:      $h"

  # Lists (oldest first) that contain this hash; the first is when it was recorded.
  : > "$tmp/mine"
  while read -r c; do
    if grep -q "^$h " "$tmp/list.$c"; then grep " $c\$" "$tmp/lists" >> "$tmp/mine"; fi
  done < "$tmp/list_commits"

  if [ ! -s "$tmp/mine" ]; then
    if grep -q "^$h " "$LIST" 2>/dev/null; then
      echo "Recorded:     in $LIST but NOT COMMITTED yet"
    else
      echo "Recorded:     NOT FOUND (only original camera files are recorded;"
      echo "              any edit or re-export changes the hash)"
    fi
    status=1; echo; continue
  fi
  echo "Recorded:     $(describe "$(head -1 "$tmp/mine" | cut -d' ' -f2)")"

  # Earliest TSA proof whose signed digest is one of those list versions.
  line="FreeTSA:      no proof covers it yet"
  while read -r d c; do
    lc=$(grep "^$d " "$tmp/mine" | head -1 | cut -d' ' -f2)
    [ -n "$lc" ] || continue
    if r=$(tsr_check "$tmp/list.$lc" "$tmp/tsr.$c"); then
      line="FreeTSA:      $r"; line="$line
              proof: $(describe "$c")"
      break
    fi
    line="FreeTSA:      $r (commit $c)"; status=1
  done < "$tmp/tsrs"
  echo "$line"

  # Earliest Bitcoin-confirmed OTS proof; otherwise report the first pending one.
  if ! have_ots; then
    echo "Bitcoin:      skipped (python3-opentimestamps not installed)"
  else
    line="Bitcoin:      no proof covers it yet"; pending=
    while read -r d c; do
      lc=$(grep "^$d " "$tmp/mine" | head -1 | cut -d' ' -f2)
      [ -n "$lc" ] || continue
      rc=0; r=$(ots_check "$tmp/list.$lc" "$tmp/ots.$c") || rc=$?
      if [ $rc -eq 0 ]; then
        line="Bitcoin:      $r
              proof: $(describe "$c")"; break
      fi
      if [ $rc -eq 1 ]; then status=1; fi
      if [ -z "$pending" ]; then   # remember the earliest unconfirmed one
        line="Bitcoin:      $r
              proof: $(describe "$c")"; pending=1
      fi
    done < "$tmp/otss"
    echo "$line"
  fi
  echo
done < "$tmp/targets"
exit $status
