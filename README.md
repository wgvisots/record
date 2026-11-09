# Photo authenticity record

A public, append-only list of SHA-256 hashes of my original camera RAW files,
with independent timestamps proving each hash existed by a given date.

## How it works

1. **`hasher.sh`** finds new `.nef` files in the photo folder (the folder that
   contains `record/`), hashes them, and appends any new hashes to `hashes.txt`.
2. The whole list is timestamped twice:
   - **FreeTSA** (RFC 3161): a signed reply, `hashes.tsr`, available right away.
   - **OpenTimestamps** (Bitcoin): `hashes.txt.ots`, pending for a few hours
     until it is included in a Bitcoin block.
3. The list and both proofs are committed together and pushed to GitHub.
   Old versions stay in git history, so every photo keeps the proof from the
   day it was added.

A proof shows a photo **existed by** that date. It doesn't show who took it,
but being first with the original RAW file is strong evidence.

## Everyday use

After copying photos from the camera, **wait for the copy to finish**, then:

```sh
record/hasher.sh          # hash new files, timestamp, commit, push
```

A few hours later (or the next day):

```sh
record/check_stamps.sh    # confirm FreeTSA, finish the Bitcoin proof, check GitHub
```

The scripts can be run from any directory.

## Commands

| Command | What it does |
|---|---|
| `hasher.sh` | Hash new files, timestamp the list, commit and push. Shows `[n/total]` progress while hashing. |
| `check_stamps.sh` | Check that the current FreeTSA reply is valid, fetch and verify the Bitcoin proof (committing and pushing it once complete), and confirm everything is on GitHub. Exits with 0 only when all three are good. |
| `prove.sh PHOTO...` | For each photo: the commit that first recorded its hash, and the earliest FreeTSA and Bitcoin proofs covering it, with GitHub links. |
| `ots_mini.py info\|stamp\|upgrade\|verify` | Minimal OpenTimestamps client (see below). Normally called by the scripts. |

Example:

```
$ record/prove.sh swamp/20261025/223NZ6_3/_DSC6406.NEF
File:         swamp/20261025/223NZ6_3/_DSC6406.NEF
SHA-256:      4bf9e072...
Recorded:     f838522  2026-11-08 17:06 -0600  "Add 157 hash(es) ..."
FreeTSA:      verified, signed Nov  8 23:06:49 2026 GMT
Bitcoin:      verified, Bitcoin block 972xxx (...)
```

**"NOT FOUND"** means the file isn't an original that was recorded. Any edit,
re-export, or metadata change produces a different hash.

## Files

| File | Purpose |
|---|---|
| `hashes.txt` | `<sha256>  <filename>`, one line per original, append-only |
| `hashes.tsr` | FreeTSA signed timestamp of `hashes.txt` |
| `hashes.txt.ots` | OpenTimestamps (Bitcoin) proof of `hashes.txt` |
| `cacert.pem`, `tsa.crt` | FreeTSA certificates, needed to verify `.tsr` files |
| `*.sha256` | Pinned fingerprints of those certificates; the scripts stop if they change |
| `.hashed_paths` | Local only (not committed): paths already hashed, so they aren't re-read |
| `common.sh` | Helper functions shared by `prove.sh` and `check_stamps.sh` |

## Verifying without these scripts

Anyone can check a photo with standard tools:

1. `sha256sum PHOTO`, then find that hash in `hashes.txt` on GitHub (commit history shows when it was added).
2. FreeTSA: download `hashes.txt`, `hashes.tsr` and the certificates from the same commit, then:
   `openssl ts -verify -data hashes.txt -in hashes.tsr -CAfile cacert.pem -untrusted tsa.crt`
   (get `cacert.pem` and `tsa.crt` from freetsa.org directly for an independent check).
3. Bitcoin: drop `hashes.txt` and `hashes.txt.ots` into the verifier at opentimestamps.org,
   or run `ots verify` with the official client and a Bitcoin node.

## About `ots_mini.py`

It uses only the Ubuntu package `python3-opentimestamps` (`sudo apt install python3-opentimestamps`)
and the Python standard library. Nothing comes from pip or pipx.

- Calendar servers only ever see a randomized hash, never the list's real hash.
- It only contacts the library's built-in trusted list of calendar servers.
- Bitcoin proofs are checked against two public block explorers (blockstream.info,
  mempool.space), which must agree. This is the one thing taken on trust; a local
  Bitcoin node would remove it.

Exit status for every command: `0` = OK / verified, `1` = error / failed,
`2` = pending or couldn't check (for example, offline).

## Troubleshooting

- **Ran `hasher.sh` while files were still copying:** a partly copied file gets
  recorded under a wrong hash and is never re-read. Delete its line(s) from
  `.hashed_paths` and run `hasher.sh` again. Its correct hash will be added;
  nothing is overwritten.
- **Re-hash everything** (for example, after moving the repo): delete `.hashed_paths`.
  Hashes already in the list won't be added twice.
- **Offline:** the commit is made locally, and the next `hasher.sh` or
  `check_stamps.sh` run pushes it.
- **Push rejected:** GitHub only accepts signed commits added on top of `main`
  (ruleset "protect main": no force-push, no deletion, signatures required,
  no bypass). A rejected push usually means a commit wasn't signed; check that
  `git config commit.gpgsign` is `true` and the signing key is available.
- **`FINGERPRINT MISMATCH`:** a FreeTSA certificate file changed. Don't continue
  until you know why. An OpenSSL upgrade that changes the fingerprint output
  format can also cause this (a false alarm, but check).
- **Photo folder elsewhere:** `PHOTOS=/path/to/photos record/hasher.sh`.
- **Other file types:** only `.nef` is recorded. To add more, in `hasher.sh`
  change `-iname '*.nef'` to `\( -iname '*.nef' -o -iname '*.jpg' \)`.
- **Duplicate filenames:** Nikon numbering wraps at 9999, so the same
  `DSC_####.NEF` name may appear with different hashes. That's expected; the
  hash is what identifies a photo.
