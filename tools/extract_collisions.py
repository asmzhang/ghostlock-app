#!/usr/bin/env python3
"""Extract per-attempt kernelsnitch evidence from a ghostlock run log.

An "attempt" = one prepare_kernel_page retry: pile formation, collision
collection, ground-truth probes and the vote-bruteforce verdict.
"""
import re
import sys
import json

COLL = re.compile(r"collision ([0-9a-f]{16}) t=(\d+) \(thresh=(\d+)\)")
PROBE = re.compile(r"probe collision ([0-9a-f]{16}) t=(\d+)")
A_INC = re.compile(r"after increase: threads=(\d+) futex_word=(\d+)")
A_TGT = re.compile(r"pile t_target=(\d+) base=(\d+) thresh=(\d+)")
A_FOUND = re.compile(r"found (\d+) collisisons")
A_PTGT = re.compile(r"probe target=([0-9a-f]{16}) t=(\d+) base_probe=(\d+)")
A_VOTE = re.compile(
    r"vote best_mm=([0-9a-f]{16}) agree=(\d+)/(\d+) probe=([0-9a-f]{16}) "
    r"t_probe=(\d+) t_target=(\d+) t_base=(\d+)")
A_WEAK = re.compile(r"pile signal too weak")
A_ONLY = re.compile(r"only found (\d+) collisions")


def parse(path):
    attempts = []
    cur = None
    for line in open(path, "r", errors="replace"):
        m = A_INC.search(line)
        if m:
            cur = {"threads": int(m.group(1)), "futex_word": int(m.group(2)),
                   "collisions": [], "probes": []}
            attempts.append(cur)
            continue
        if cur is None:
            continue
        for rx, key in ((A_TGT, "target"), (A_FOUND, "found"),
                        (A_PTGT, "probe_target"), (A_VOTE, "vote")):
            m = rx.search(line)
            if m:
                cur[key] = [int(x) if x.isdigit() else x for x in m.groups()]
        m = COLL.search(line)
        if m:
            cur["collisions"].append((m.group(1), int(m.group(2))))
        m = PROBE.search(line)
        if m:
            cur["probes"].append((m.group(1), int(m.group(2))))
        if A_WEAK.search(line):
            cur["weak"] = True
        m = A_ONLY.search(line)
        if m:
            cur["only_found"] = int(m.group(1))
    return attempts


def main():
    for path in sys.argv[1:]:
        print("=" * 70)
        print(path)
        for i, a in enumerate(parse(path)):
            tgt = a.get("target")
            print(f"--- attempt {i+1} --- threads={a['threads']} "
                  f"futex_word={a['futex_word']} "
                  f"t_target={tgt[0] if tgt else '?'} "
                  f"base={tgt[1] if tgt else '?'} "
                  f"thresh={tgt[2] if tgt else '?'}"
                  + (" WEAK" if a.get("weak") else ""))
            cs = a["collisions"]
            if cs:
                times = [t for _, t in cs]
                print(f"    collected {len(cs)} hits, t range "
                      f"{min(times)}-{max(times)}")
                print("    addrs: " + " ".join(x for x, _ in cs))
            if a.get("probes"):
                pt = [t for _, t in a["probes"]]
                print(f"    re-probe t range {min(pt)}-{max(pt)}")
            if a.get("probe_target"):
                print(f"    probe_target={a['probe_target']}")
            if a.get("vote"):
                v = a["vote"]
                print(f"    VOTE best_mm={v[0]} agree={v[1]}/{v[2]} "
                      f"t_probe={v[4]} t_target={v[5]} t_base={v[6]}")


if __name__ == "__main__":
    main()
