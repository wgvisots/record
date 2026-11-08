#!/usr/bin/env python3
"""ots_mini.py: minimal OpenTimestamps client built only on the distro's
python3-opentimestamps library (apt), standard library otherwise.

  stamp   FILE            create FILE.ots (calendars only ever see a salted hash)
  upgrade FILE.ots        fetch Bitcoin attestations from the calendars, rewrite in place
  verify  FILE FILE.ots   check FILE matches the proof, then check the Bitcoin block's
                          merkle root against two public block explorers
  info    FILE.ots        show the digest the proof covers and its attestations

Exit status: 0 = ok / complete / verified, 1 = error / failed, 2 = pending / unverifiable.

Trust model: the proof itself is math (hash operations from your digest up to a
Bitcoin block's merkle root).  The only thing taken on trust is the block
explorers' report of that block's merkle root; two independent explorers must
agree.  A local Bitcoin node would remove even that.
"""
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

from opentimestamps.calendar import (DEFAULT_AGGREGATORS, DEFAULT_CALENDAR_WHITELIST,
                                     CommitmentNotFoundError, RemoteCalendar)
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import (DeserializationError, StreamDeserializationContext,
                                           StreamSerializationContext)
from opentimestamps.core.timestamp import DetachedTimestampFile

EXPLORERS = ("https://blockstream.info/api", "https://mempool.space/api")
TIMEOUT = 15
UA = "ots-mini"
MIN_CALENDARS = 2


def warn(msg):
    print("warning: " + msg, file=sys.stderr)


def load(path):
    with open(path, "rb") as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def save(path, dtf, overwrite):
    """Write atomically: a temp file in the same directory, then rename/link."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".ots-")
    try:
        with os.fdopen(fd, "wb") as f:
            dtf.serialize(StreamSerializationContext(f))
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp, 0o666 & ~umask)  # mkstemp makes 0600; use normal permissions
        if overwrite:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)  # raises FileExistsError rather than clobbering
            os.unlink(tmp)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def walk(ts):
    yield ts
    for sub in ts.ops.values():
        yield from walk(sub)


def attestations(ts):
    return set(att for _, att in ts.all_attestations())


def is_complete(ts):
    return any(isinstance(att, BitcoinBlockHeaderAttestation) for att in attestations(ts))


def upgrade_timestamp(ts):
    """Ask whitelisted calendars about each pending attestation; merge answers.
    Returns True if anything new was learned."""
    before = attestations(ts)
    for sub in list(walk(ts)):
        for att in list(sub.attestations):
            if not isinstance(att, PendingAttestation):
                continue
            if att.uri not in DEFAULT_CALENDAR_WHITELIST:
                warn("ignoring calendar not on whitelist: %r" % att.uri)
                continue
            try:
                sub.merge(RemoteCalendar(att.uri, UA).get_timestamp(sub.msg, timeout=TIMEOUT))
            except CommitmentNotFoundError:
                pass  # the normal "pending confirmation" answer
            except Exception as e:  # network trouble or a malformed answer
                warn("%s: %s" % (att.uri, e))
    return attestations(ts) != before


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read(100_000).decode()


def check_block(height, msg):
    """Compare a Bitcoin attestation with the explorers' view of that block.
    Returns (status, text) using the exit-status convention."""
    if len(msg) != 32:
        return 1, "FAILED: malformed Bitcoin attestation"
    root = msg[::-1].hex()  # explorers display merkle roots byte-reversed
    agree, when = 0, None
    for api in EXPLORERS:
        site = api.rsplit("/api", 1)[0]
        try:
            bhash = http_get("%s/block-height/%d" % (api, height)).strip()
            if not re.fullmatch(r"[0-9a-f]{64}", bhash):
                raise ValueError("unexpected block hash %r" % bhash[:80])
            block = json.loads(http_get("%s/block/%s" % (api, bhash)))
            if block.get("id") != bhash or block.get("height") != height:
                raise ValueError("explorer returned a different block")
        except Exception as e:
            warn("%s: %s" % (site, e))
            continue
        if block.get("merkle_root") != root:
            return 1, "FAILED: block %d merkle root mismatch at %s" % (height, site)
        agree += 1
        when = block["timestamp"]
    if not agree:
        return 2, "could not reach any block explorer"
    t = datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return 0, "verified, Bitcoin block %d (%s, %d explorer(s) agree)" % (height, t, agree)


# --- commands ----------------------------------------------------------------

def cmd_stamp(path):
    if os.path.exists(path + ".ots"):
        print("error: %s.ots already exists" % path, file=sys.stderr)
        return 1
    with open(path, "rb") as f:
        dtf = DetachedTimestampFile.from_fd(OpSHA256(), f)
    # Random nonce so the calendars never learn the file's actual hash.
    tip = dtf.timestamp.ops.add(OpAppend(os.urandom(16))).ops.add(OpSHA256())
    ok = 0
    for url in DEFAULT_AGGREGATORS:
        try:
            tip.merge(RemoteCalendar(url, UA).submit(tip.msg, timeout=TIMEOUT))
            ok += 1
        except Exception as e:
            warn("%s: %s" % (url, e))
    if ok < MIN_CALENDARS:
        print("error: only %d calendar(s) accepted the submission; need %d"
              % (ok, MIN_CALENDARS), file=sys.stderr)
        return 1
    save(path + ".ots", dtf, overwrite=False)
    print("submitted to %d calendar(s); wrote %s.ots (pending until a Bitcoin block, "
          "usually a few hours)" % (ok, path))
    return 0


def cmd_upgrade(otspath):
    dtf = load(otspath)
    if is_complete(dtf.timestamp):
        print("complete (already has a Bitcoin attestation)")
        return 0
    if upgrade_timestamp(dtf.timestamp):
        save(otspath, dtf, overwrite=True)
    if is_complete(dtf.timestamp):
        print("complete; Bitcoin attestation saved to %s" % otspath)
        return 0
    print("pending (calendars have it; not in a Bitcoin block yet)")
    return 2


def cmd_verify(target, otspath):
    dtf = load(otspath)
    with open(target, "rb") as f:
        if dtf.file_hash_op.hash_fd(f) != dtf.file_digest:
            print("FAILED: proof is for different data")
            return 1
    if not is_complete(dtf.timestamp):
        upgrade_timestamp(dtf.timestamp)  # in memory only; the file is untouched
    btc = sorted((att.height, msg) for msg, att in dtf.timestamp.all_attestations()
                 if isinstance(att, BitcoinBlockHeaderAttestation))
    if not btc:
        print("pending (calendars have it; not in a Bitcoin block yet, usually takes a few hours)")
        return 2
    worst, text = 2, None
    for height, msg in btc:  # earliest block first; one good attestation suffices
        status, text = check_block(height, msg)
        if status == 0:
            print(text)
            return 0
        worst = min(worst, status)
    print(text)
    return worst


def cmd_info(otspath):
    dtf = load(otspath)
    print("File sha256 hash: %s" % dtf.file_digest.hex())
    for msg, att in sorted(dtf.timestamp.all_attestations(), key=lambda x: repr(x[1])):
        if isinstance(att, BitcoinBlockHeaderAttestation):
            print("  Bitcoin block %d (merkle root %s)" % (att.height, msg[::-1].hex()))
        elif isinstance(att, PendingAttestation):
            print("  pending at %s" % att.uri)
        else:
            print("  %r" % att)
    return 0


COMMANDS = {"stamp": (cmd_stamp, 1), "upgrade": (cmd_upgrade, 1),
            "verify": (cmd_verify, 2), "info": (cmd_info, 1)}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS or len(argv) - 2 != COMMANDS[argv[1]][1]:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 1
    func, _ = COMMANDS[argv[1]]
    try:
        return func(*argv[2:])
    except (OSError, DeserializationError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
