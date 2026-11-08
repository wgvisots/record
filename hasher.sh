#!/bin/sh

check() {  # check <cert> <pinfile>
  [ "$(openssl x509 -in "$1" -noout -fingerprint -sha256)" = "$(cat "$2")" ] \
    || { echo "FINGERPRINT MISMATCH: $1" >&2; exit 1; }
}

LIST=hashes.txt
touch "$LIST"

find . -type f -name '*.NEF' -print0 \
  | xargs -0 sha256sum \
  | sed 's#^\([0-9a-f]\{64\}\)  .*/#\1  #' \
  | awk 'FILENAME == ARGV[1] { seen[$1]; next }
         !($1 in seen)       { seen[$1]; print }' "$LIST" - \
  > "$LIST.new"

cat "$LIST.new" >> "$LIST"
rm "$LIST.new"


#!/bin/sh
set -eu


check cacert.pem cacert.sha256
check tsa.crt    tsa.sha256

openssl ts -query -data hashes.txt -sha256 -cert -out hashes.tsq
curl -sf -H "Content-Type: application/timestamp-query" \
     --data-binary @hashes.tsq https://freetsa.org/tsr -o hashes.tsr
openssl ts -verify -data hashes.txt -in hashes.tsr \
     -CAfile cacert.pem -untrusted tsa.crt

