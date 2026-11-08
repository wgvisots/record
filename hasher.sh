#!/bin/sh
# Record SHA-256 hashes of new raw files, timestamp the list with an
# RFC 3161 TSA (and OpenTimestamps if installed), then commit and push.
set -eu
export LC_ALL=C                      # stable sort/comm behaviour

cd "$(dirname "$0")"                 # works no matter where it's run from

PHOTOS=${PHOTOS:-..}                 # photo tree to scan (this repo lives inside it)
LIST=hashes.txt                     # public, append-only, committed
SEEN=.hashed_paths                   # local cache of paths already hashed (gitignored)
TSA_URL=https://freetsa.org/tsr

check() {  # check <cert> <pinfile>
  [ "$(openssl x509 -in "$1" -noout -fingerprint -sha256)" = "$(cat "$2")" ] \
    || { echo "FINGERPRINT MISMATCH: $1" >&2; exit 1; }
}

check cacert.pem cacert.sha256
check tsa.crt    tsa.sha256

touch "$LIST" "$SEEN"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1. Find raw files whose path hasn't been hashed before.
#    (Assumes no newlines in filenames, which camera files never have.)
here=$(basename "$PWD")
find "$PHOTOS" -path "$PHOTOS/$here" -prune -o -type f -iname '*.nef' -print \
  | sort > "$tmp/all"
sort -u "$SEEN" > "$tmp/seen"
comm -13 "$tmp/seen" "$tmp/all" > "$tmp/new"

# 2. Hash them, strip directories, keep only hashes not already in the list.
#    -r: don't run sha256sum at all (and hash empty stdin) when nothing is new.
tr '\n' '\0' < "$tmp/new" \
  | xargs -0 -r sha256sum \
  | sed 's#^\([0-9a-f]\{64\}\)  .*/#\1  #' \
  | awk 'FILENAME == ARGV[1] { seen[$1]; next }
         !($1 in seen)       { seen[$1]; print }' "$LIST" - \
  > "$tmp/add"

added=$(wc -l < "$tmp/add")
cat "$tmp/add" >> "$LIST"
cat "$tmp/seen" "$tmp/new" | sort -u > "$SEEN"
echo "$(wc -l < "$tmp/new") new file(s), $added new hash(es)"

# 3. Only timestamp/commit if the list differs from what's committed.
#    (Also catches a previous run that died after appending.)
if [ -z "$(git status --porcelain -- "$LIST" 2>/dev/null || echo changed)" ]; then
  echo "Nothing new to timestamp."
  git push -q 2>/dev/null || true    # flush any commits from an offline run
  exit 0
fi

# 4. RFC 3161 timestamp of the list.
openssl ts -query -data "$LIST" -sha256 -cert -out "$tmp/hashes.tsq"
curl -sSf -H "Content-Type: application/timestamp-query" \
     --data-binary @"$tmp/hashes.tsq" "$TSA_URL" -o "$tmp/hashes.tsr"
openssl ts -verify -data "$LIST" -in "$tmp/hashes.tsr" \
     -CAfile cacert.pem -untrusted tsa.crt
mv "$tmp/hashes.tsr" hashes.tsr      # only replace the old proof once verified

# 5. Second, independent timestamp (Bitcoin) if the client is installed.
#    Run `ots upgrade hashes.txt.ots` a few hours later to complete it.
if command -v ots >/dev/null 2>&1; then
  rm -f "$LIST.ots"
  ots stamp "$LIST"
fi

# 6. Commit list + proofs together, so each commit is a verifiable pair.
git add "$LIST" hashes.tsr
[ -f "$LIST.ots" ] && git add "$LIST.ots"
git commit -q -m "Add $added hash(es) $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push -q || echo "WARNING: push failed; commit is local, will retry next run" >&2
