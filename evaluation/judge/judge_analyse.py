"""Analyse the LLM-judge scores for RQ3.

Reads (from results\\judge\\): judge_key.csv, judge_scores.txt (the judge's replies, pasted in), human_check_template.csv (your scores)
Writes: judge_summary.txt
Groups: codeql = CodeQL alert messages; with = CheckGate with references; neutral = CheckGate neutral control.
"""
import os
import csv, json, random, re, statistics, sys
from collections import defaultdict
from pathlib import Path

RESULTS = Path(os.environ.get("CHECKGATE_RESULTS", "results"))   # or pass --results
if "--results" in sys.argv:
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])
J = RESULTS / "judge"
B, SEED = 5000, 907
OUT = []
def say(s=""):
    print(s); OUT.append(s)

key = {r["item"]: r for r in csv.DictReader(open(J / "judge_key.csv", encoding="utf-8", newline=""))}

# ---- parse the judge's replies: any JSON object that has an item id, tolerant of fences and commentary
scores, bad = {}, []
text = open(J / "judge_scores.txt", encoding="utf-8").read()
# copying through a word processor or a chat window can turn straight quotes into curly ones, which JSON cannot read
text = text.replace("\u201c", '"').replace("\u201d", '"').replace("\u2018", "'").replace("\u2019", "'")
for m in re.finditer(r"\{[^{}]*\"item\"[^{}]*\}", text):
    try:
        o = json.loads(m.group(0))
        c, t = int(o["clarity"]), int(o["trust"])
        if o["item"] in key and 1 <= c <= 5 and 1 <= t <= 5:
            scores[o["item"]] = {"clarity": c, "trust": t, "note": o.get("note", "")}
        else:
            bad.append(m.group(0)[:60])
    except Exception:
        bad.append(m.group(0)[:60])
missing = sorted(set(key) - set(scores))
say(f"items in the key: {len(key)}   scored by the judge: {len(scores)}   missing: {len(missing)}   unusable replies: {len(bad)}")
if missing: say("   missing items: " + ", ".join(missing))
if bad: say("   unusable: " + " | ".join(bad[:5]))
say()

def mean(xs): return sum(xs) / len(xs) if xs else float("nan")
def boot_mean(xs, rng): 
    ds = sorted(mean([rng.choice(xs) for _ in xs]) for _ in range(B)); return ds[int(.025 * B)], ds[int(.975 * B)]
def boot_diff(a, b, rng):
    ds = sorted(mean([rng.choice(a) for _ in a]) - mean([rng.choice(b) for _ in b]) for _ in range(B)); return ds[int(.025 * B)], ds[int(.975 * B)]
def ranks(xs):
    order = sorted(range(len(xs)), key=lambda i: xs[i]); r = [0.0] * len(xs); i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]: j += 1
        for k in range(i, j + 1): r[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return r
def spearman(x, y):
    if len(x) < 3: return float("nan")
    rx, ry = ranks(x), ranks(y); mx, my = mean(rx), mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry)); den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** .5
    return num / den if den else float("nan")

groups = defaultdict(list)
for i, s in scores.items(): groups[key[i]["group"]].append((i, s))
rng = random.Random(SEED)
names = {"codeql": "CodeQL messages", "with": "CheckGate with references", "neutral": "CheckGate neutral control"}

say("A. Scores by group (1 to 5; 95% interval in brackets)")
say(f"   {'group':28} {'n':>3}   {'clarity':22} {'trustworthiness':22} {'words per explanation'}")
vals = {}
for g in ("codeql", "with", "neutral"):
    if g not in groups: continue
    c = [s["clarity"] for _, s in groups[g]]; t = [s["trust"] for _, s in groups[g]]; w = [int(key[i]["n_words"]) for i, _ in groups[g]]
    vals[g] = (c, t)
    cl, tl = boot_mean(c, rng), boot_mean(t, rng)
    say(f"   {names[g]:28} {len(c):>3}   {mean(c):.2f} [{cl[0]:.2f}, {cl[1]:.2f}]     {mean(t):.2f} [{tl[0]:.2f}, {tl[1]:.2f}]     {mean(w):.0f}")
say()
say("B. Differences in mean score (first minus second; an interval that includes 0 means it could be chance)")
for a, b, label in (("with", "codeql", "CheckGate with references minus CodeQL (RQ3)"), ("neutral", "codeql", "CheckGate neutral control minus CodeQL"), ("with", "neutral", "with references minus neutral control (does grounding change the explanation?)")):
    if a in vals and b in vals:
        for k, name in ((0, "clarity"), (1, "trustworthiness")):
            d = mean(vals[a][k]) - mean(vals[b][k]); lo, hi = boot_diff(vals[a][k], vals[b][k], rng)
            say(f"   {label:78} {name:16} {d:+.2f} [{lo:+.2f}, {hi:+.2f}]")
say()

say("C. Does the score just follow explanation length? (Spearman correlation across all scored items)")
ids = sorted(scores)
w = [int(key[i]["n_words"]) for i in ids]
for k, name in (("clarity", "clarity"), ("trust", "trustworthiness")):
    say(f"   words against {name:16} {spearman(w, [scores[i][k] for i in ids]):+.2f}")
say("   Near 0 means length is not driving the scores. Above about +0.4 means the judge rewards length and the results need that caveat.")
say()

human = {}
for r in csv.DictReader(open(J / "human_check_template.csv", encoding="utf-8", newline="")):
    try: human[r["item"]] = {"clarity": int(r["clarity"]), "trust": int(r["trust"])}
    except (ValueError, TypeError): pass
both = sorted(set(human) & set(scores))
say(f"D. Your scores against the judge's ({len(both)} items you scored that the judge also scored)")
if both:
    for k, name in (("clarity", "clarity"), ("trust", "trustworthiness")):
        h = [human[i][k] for i in both]; j = [scores[i][k] for i in both]
        exact = sum(a == b for a, b in zip(h, j)) / len(h); within = sum(abs(a - b) <= 1 for a, b in zip(h, j)) / len(h)
        say(f"   {name:16} exact agreement {100*exact:.0f}%   within 1 point {100*within:.0f}%   rank correlation {spearman(h, j):+.2f}   mean judge minus you {mean([b - a for a, b in zip(h, j)]):+.2f}")
    say("   A positive 'judge minus you' means the judge is more generous than you are.")
say()
with open(J / "judge_summary.txt", "w", encoding="utf-8") as fh: fh.write("\n".join(OUT))
print(f"written: {J / 'judge_summary.txt'}")
