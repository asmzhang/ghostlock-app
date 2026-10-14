#!/usr/bin/env python3
"""Tally a trials_ps*.ps1 summary.txt and compare two batches with Fisher's exact test.

Usage: tally.py <control-summary.txt> [<candidate-summary.txt>]

Argument order matters: the FIRST summary is the control/baseline batch, the SECOND is the
candidate. The one-tailed Fisher test asks "is the candidate at least this good by chance?",
so swapping the arguments changes the p-value.

Statistics per batch (one round = one line "round N : <verdict> | W1=.. W2=.. W3=.. hold=.."):
  W1 landing   W1=ok                          -- SELinux became permissive
  W2 entered   W2=entered                     -- the credential write was attempted
  HIT-ROOT     verdict == HIT-ROOT            -- child reached uid=0
  hit|W2       HIT-ROOT / W2 entered          -- given the write was attempted, did it land
"""
import re
import sys
from math import comb


def parse(path):
    rounds, hits, w1, w2, verdicts = [], 0, 0, 0, {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"^round (\d+) : (\S+) \| W1=(\S+) W2=(\S+) W3=(\S+) hold=(\S+)", line)
        if not m:
            continue
        rounds.append(int(m.group(1)))
        verdict = m.group(2)
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        if verdict == "HIT-ROOT":
            hits += 1
        if m.group(3) == "ok":
            w1 += 1
        if m.group(4) == "entered":
            w2 += 1
    return {"n": len(rounds), "hits": hits, "w1": w1, "w2": w2, "verdicts": verdicts}


def fisher_ge(a, b, c, d):
    """One-tailed P(X >= a) for the table [[a,b],[c,d]] with fixed margins."""
    n, k, n1 = a + b + c + d, a + c, a + b
    total = sum(comb(k, x) * comb(n - k, n1 - x) for x in range(a, min(k, n1) + 1)
                if 0 <= n1 - x <= n - k)
    return total / comb(n, n1)


def compare(label, hit_c, n_c, hit_v, n_v):
    p = fisher_ge(hit_v, n_v - hit_v, hit_c, n_c - hit_c)
    print(f"{label:<10} control {hit_c}/{n_c} vs candidate {hit_v}/{n_v}: p={p:.3g}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    for path in sys.argv[1:]:
        s = parse(path)
        print(f"{path}: rounds={s['n']} hits={s['hits']} W1=ok {s['w1']} W2=entered {s['w2']}")
        print(f"  verdicts: {s['verdicts']}")
    if len(sys.argv) == 3:
        c, v = parse(sys.argv[1]), parse(sys.argv[2])
        print(f"control  : rounds={c['n']} hits={c['hits']} W1=ok {c['w1']} W2={c['w2']}")
        print(f"candidate: rounds={v['n']} hits={v['hits']} W1=ok {v['w1']} W2={v['w2']}")
        compare("hit rate", c["hits"], c["n"], v["hits"], v["n"])
        compare("W1 landing", c["w1"], c["n"], v["w1"], v["n"])
        compare("hit|W2", c["hits"], c["w2"], v["hits"], v["w2"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
