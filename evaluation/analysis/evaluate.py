"""Evaluation tables for the capstone: CheckGate with and without references, against CodeQL.

Reads (from results\\): eval_set.jsonl, gemini_results.jsonl (conditions with, without and, if present, neutral), codeql_detections.csv
Writes:                 evaluation_summary.txt (everything printed here) and per_function.csv

Definitions (state these in the report)
  detected     a function counts as detected when the tool reports at least one finding in it.
               For CheckGate each run is scored separately and the three runs are averaged.
  recall       share of vulnerable functions detected.      false positive rate  share of non-vulnerable functions detected.
  precision, F1 computed from the same averaged counts.
  line exact   a finding sits on a labelled vulnerable line;  line within 2  a finding is within 2 lines of one.
               Reported both over all vulnerable functions and over the detected ones.
  intervals    95% percentile intervals from a bootstrap that resamples whole fix commits (functions from the same
               commit are related, so the commit is the unit that is resampled).
"""
import os
import csv, json, random, re, statistics, sys
from collections import defaultdict
from pathlib import Path

RESULTS = Path(os.environ.get("CHECKGATE_RESULTS", "results"))   # or pass --results
if "--results" in sys.argv:
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])
B, SEED = 2000, 907
CWE_RE = re.compile(r"CWE-\d+", re.I)
OUT = []


def say(s=""):
    print(s); OUT.append(s)


# ------------------------------------------------------------------ load
funcs = {}
for line in open(RESULTS / "eval_set.jsonl", encoding="utf-8"):
    r = json.loads(line); funcs[r["id"]] = r
ids = sorted(funcs)
vul_ids = [i for i in ids if funcs[i]["label"] == 1]
non_ids = [i for i in ids if funcs[i]["label"] == 0]

raw = {}
errors = 0
for line in open(RESULTS / "gemini_results.jsonl", encoding="utf-8"):
    if not line.strip(): continue
    r = json.loads(line)
    if r.get("error"):
        errors += 1; continue
    raw[(r["id"], r["condition"], r["run"])] = r          # a later success replaces an earlier line

runs = defaultdict(list)                                   # (id, condition) -> list of per-run dicts
for (i, c, k), r in sorted(raw.items(), key=lambda kv: kv[0][2]):
    if i not in funcs: continue
    vl = set(funcs[i].get("vul_lines", []))
    fs = r["findings"]
    runs[(i, c)].append({
        "run": k, "det": 1.0 if fs else 0.0,
        "exact": 1.0 if any(f["line"] in vl for f in fs) else 0.0,
        "pm2": 1.0 if any(abs(f["line"] - v) <= 2 for f in fs for v in vl) else 0.0,
        "names": 1.0 if any(CWE_RE.search(f["type"] or "") for f in fs) else 0.0,
        "match": 1.0 if any(funcs[i]["cwe"].upper() in [m.upper() for m in CWE_RE.findall(f["type"] or "")] for f in fs) else 0.0,
        "grounded": 1.0 if r.get("grounded") else 0.0,
        "relevant": 1.0 if funcs[i]["cwe"] in [x["id"] for x in r.get("retrieved", [])] else 0.0,
        "none": 1.0 if (r.get("description") or "").strip().upper() == "NONE" else 0.0})

def mean_of(i, c, key):
    rs = runs.get((i, c), [])
    return sum(x[key] for x in rs) / len(rs) if rs else None

CONDS = ["with", "without"] + (["neutral"] if any(k[1] == "neutral" for k in raw) else [])
complete = [i for i in ids if all(len(runs.get((i, c), [])) > 0 for c in CONDS)]
missing = len(ids) - len(complete)
cq = {}
for r in csv.DictReader(open(RESULTS / "codeql_detections.csv", encoding="utf-8")):
    if r["located"] == "1":
        cq[r["id"]] = {"det": float(r["detected"]), "exact": float(r["line_exact"] or 0), "pm2": float(r["line_pm2"] or 0)}

say(f"functions in the evaluation set: {len(ids)} ({len(vul_ids)} vulnerable, {len(non_ids)} non-vulnerable) from {len({funcs[i]['rank'] for i in ids})} fix commits")
say(f"Gemini result lines used: {len(raw)}   error lines ignored: {errors}   functions missing a condition: {missing}")
nruns = sorted({len(runs[(i, 'with')]) for i in complete}) if complete else []
say(f"runs per function and condition: {nruns}   functions CodeQL could be located in: {len(cq)}\n")
ids = complete
vul_ids = [i for i in ids if funcs[i]["label"] == 1]
non_ids = [i for i in ids if funcs[i]["label"] == 0]

val = {c: {k: {i: mean_of(i, c, k) for i in ids} for k in ("det", "exact", "pm2", "names", "match", "grounded", "relevant", "none")} for c in CONDS}
val["codeql"] = {k: {i: cq[i][k] for i in cq} for k in ("det", "exact", "pm2")}


# ------------------------------------------------------------------ metrics and bootstrap
def metrics(sample, v):
    """v = dict with det / exact / pm2 per function. sample = list of ids (may repeat)."""
    sv = [i for i in sample if funcs[i]["label"] == 1]; sn = [i for i in sample if funcs[i]["label"] == 0]
    out = {}
    if not sv or not sn: return out
    tp = sum(v["det"][i] for i in sv); fp = sum(v["det"][i] for i in sn)
    out["recall"] = tp / len(sv); out["fpr"] = fp / len(sn)
    out["precision"] = tp / (tp + fp) if tp + fp else None
    out["f1"] = 2 * tp / (2 * tp + fp + (len(sv) - tp)) if tp + fp else None
    for k in ("exact", "pm2"):
        h = sum(v[k][i] for i in sv)
        out[f"line_{k}_all"] = h / len(sv)
        out[f"line_{k}_det"] = h / tp if tp else None
    return out


def boot(sample_ids, fn, label=None):
    """Point estimate and 95% commit-cluster bootstrap interval for every number fn(sample) returns."""
    by_rank = defaultdict(list)
    for i in sample_ids: by_rank[funcs[i]["rank"]].append(i)
    ranks = sorted(by_rank)
    point = fn(sample_ids)
    rng = random.Random(SEED); draws = defaultdict(list)
    for _ in range(B):
        s = [i for r in (rng.choice(ranks) for _ in ranks) for i in by_rank[r]]
        for k, x in fn(s).items():
            if x is not None: draws[k].append(x)
    ci = {}
    for k, xs in draws.items():
        xs.sort()
        ci[k] = (xs[int(0.025 * len(xs))], xs[min(len(xs) - 1, int(0.975 * len(xs)))]) if len(xs) > 20 else (None, None)
    return point, ci


def f(x, ci=None, pct=False):
    if x is None: return "n/a"
    s = f"{x:.3f}"
    if ci and ci[0] is not None: s += f" [{ci[0]:.3f}, {ci[1]:.3f}]"
    return s


# ------------------------------------------------------------------ A. with vs without
say("A. CheckGate under each condition (all functions, runs averaged; 95% interval in brackets)")
say("   with = references where retrieval is strong enough; without = standard caution wording, no references; neutral = plain line, no references, no instruction")
def both(sample):
    a = metrics(sample, val["with"]); b = metrics(sample, val["without"])
    out = {}
    for c in CONDS:
        out.update({f"{c}_{k}": x for k, x in metrics(sample, val[c]).items()})
    for k in ("recall", "fpr", "f1", "line_exact_all"):
        if a.get(k) is not None and b.get(k) is not None: out[f"diff_{k}"] = a[k] - b[k]
    return out
P, C = boot(ids, both)
say(f"   {'':9} {'recall':22} {'false positive rate':22} {'precision':8} {'F1':22}")
for c in CONDS:
    say(f"   {c:9} {f(P.get(c+'_recall'), C.get(c+'_recall')):22} {f(P.get(c+'_fpr'), C.get(c+'_fpr')):22} {f(P.get(c+'_precision')):8} {f(P.get(c+'_f1'), C.get(c+'_f1')):22}")
say(f"   line accuracy, share of ALL vulnerable functions with a finding on a labelled line:")
for c in CONDS:
    say(f"   {c:9} exact {f(P.get(c+'_line_exact_all'), C.get(c+'_line_exact_all'))}   within 2 lines {f(P.get(c+'_line_pm2_all'), C.get(c+'_line_pm2_all'))}")
say(f"   line accuracy, share of DETECTED vulnerable functions (the finding lands on a labelled line):")
for c in CONDS:
    say(f"   {c:9} exact {f(P.get(c+'_line_exact_det'))}   within 2 lines {f(P.get(c+'_line_pm2_det'))}")
say("   difference (with minus without):")
for k, name in (("recall", "recall"), ("fpr", "false positive rate"), ("f1", "F1"), ("line_exact_all", "line exact (all vulnerable)")):
    say(f"      {name:30} {P.get('diff_'+k, float('nan')):+.3f} " + (f"[{C['diff_'+k][0]:+.3f}, {C['diff_'+k][1]:+.3f}]" if 'diff_'+k in C and C['diff_'+k][0] is not None else ""))
say("   An interval that includes 0 means the difference could be chance at this sample size.\n")

# ------------------------------------------------------------------ B. retrieval dose
say("B. Retrieval dose (condition 'with')")
fr = [(i, k) for i in ids for k in [x for x in runs[(i, 'with')]]]
tot = len(fr)
g = int(sum(k["grounded"] for _, k in fr)); nn = int(sum(k["none"] for _, k in fr))
say(f"   function-runs where references reached the model (grounded): {g} of {tot} ({100*g/tot:.0f}%)")
say(f"   function-runs where the first step answered NONE: {nn} of {tot} ({100*nn/tot:.0f}%)")
vr = [k for i in vul_ids for k in runs[(i, 'with')]]
rel = [k for k in vr if k["relevant"]]
say(f"   vulnerable function-runs with the labelled CWE among the 5 retrieved: {len(rel)} of {len(vr)} ({100*len(rel)/len(vr):.0f}%)")
for name, grp in (("labelled CWE retrieved", rel), ("not retrieved", [k for k in vr if not k["relevant"]])):
    if grp:
        say(f"      {name:24} n={len(grp):4}  detected {100*sum(k['det'] for k in grp)/len(grp):.0f}%   exact line {100*sum(k['exact'] for k in grp)/len(grp):.0f}%")
major = [i for i in ids if val["with"]["grounded"][i] >= 0.5]
rest = [i for i in ids if val["with"]["grounded"][i] < 0.5]
say(f"   functions grounded in most runs: {len(major)}; the rest: {len(rest)}. With-minus-without on each group:")
for name, grp in (("grounded in most runs", major), ("not grounded", rest)):
    sv = [i for i in grp if funcs[i]["label"] == 1]; sn = [i for i in grp if funcs[i]["label"] == 0]
    if sv and sn:
        dr = sum(val["with"]["det"][i] - val["without"]["det"][i] for i in sv) / len(sv)
        df = sum(val["with"]["det"][i] - val["without"]["det"][i] for i in sn) / len(sn)
        say(f"      {name:24} {len(sv)} vulnerable / {len(sn)} non-vulnerable   recall difference {dr:+.3f}   false positive difference {df:+.3f}")
    else:
        say(f"      {name:24} too few of one class ({len(sv)} vulnerable / {len(sn)} non-vulnerable)")
say("   Where nothing was grounded the two conditions send the same prompt, so those differences are run-to-run noise.\n")

# ------------------------------------------------------------------ C. CheckGate vs CodeQL
loc = [i for i in ids if i in cq]
say(f"C. CheckGate against CodeQL, on the {len(loc)} functions CodeQL could be located in")
def vs(sample):
    out = {}
    for name, v in (("with", val["with"]), ("without", val["without"]), ("codeql", val["codeql"])):
        for k, x in metrics(sample, v).items(): out[f"{name}_{k}"] = x
    for k in ("recall", "fpr", "f1", "line_exact_all"):
        a, b = out.get(f"with_{k}"), out.get(f"codeql_{k}")
        if a is not None and b is not None: out[f"dq_{k}"] = a - b
    return out
P2, C2 = boot(loc, vs)
say(f"   {'':9} {'recall':22} {'false positive rate':22} {'precision':8} {'F1':22} {'line exact (all vuln)':22}")
for c in ("with", "without", "codeql"):
    say(f"   {c:9} {f(P2.get(c+'_recall'), C2.get(c+'_recall')):22} {f(P2.get(c+'_fpr'), C2.get(c+'_fpr')):22} {f(P2.get(c+'_precision')):8} {f(P2.get(c+'_f1'), C2.get(c+'_f1')):22} {f(P2.get(c+'_line_exact_all'), C2.get(c+'_line_exact_all')):22}")
say("   CheckGate (with) minus CodeQL:")
for k, name in (("recall", "recall"), ("fpr", "false positive rate"), ("f1", "F1"), ("line_exact_all", "line exact (all vulnerable)")):
    if 'dq_'+k in P2:
        say(f"      {name:30} {P2['dq_'+k]:+.3f} " + (f"[{C2['dq_'+k][0]:+.3f}, {C2['dq_'+k][1]:+.3f}]" if 'dq_'+k in C2 and C2['dq_'+k][0] is not None else ""))
say("   CodeQL counts a function as detected when any of its alerts falls inside it, which is generous to CodeQL.\n")

# ------------------------------------------------------------------ D. stability
say("D. Stability across the runs")
for c in CONDS:
    dis = [i for i in ids if 0 < val[c]["det"][i] < 1]
    per_run = defaultdict(lambda: [0, 0, 0, 0])
    for i in ids:
        for k in runs[(i, c)]:
            a = per_run[k["run"]]
            if funcs[i]["label"] == 1: a[0] += k["det"]; a[1] += 1
            else: a[2] += k["det"]; a[3] += 1
    rec = [a[0] / a[1] for a in per_run.values() if a[1]]; fp = [a[2] / a[3] for a in per_run.values() if a[3]]
    say(f"   {c:9} functions where the runs disagree on detection: {len(dis)} of {len(ids)} ({100*len(dis)/len(ids):.0f}%)   "
        f"recall by run {', '.join(f'{x:.3f}' for x in rec)}   false positive rate by run {', '.join(f'{x:.3f}' for x in fp)}")
say()

# ------------------------------------------------------------------ E. length bands
med = statistics.median(funcs[i]["n_chars"] for i in ids)
say(f"E. Results by function length (median length {med:.0f} characters; vulnerable functions are longer in the data, so check that results do not just follow length)")
for name, grp in (("shorter half", [i for i in ids if funcs[i]["n_chars"] <= med]), ("longer half", [i for i in ids if funcs[i]["n_chars"] > med])):
    sv = [i for i in grp if funcs[i]["label"] == 1]; sn = [i for i in grp if funcs[i]["label"] == 0]
    parts = []
    for c in ("with", "without"):
        m = metrics(grp, val[c]); parts.append(f"{c}: recall {f(m.get('recall'))} false pos {f(m.get('fpr'))}")
    lg = [i for i in grp if i in cq]; m = metrics(lg, val["codeql"]) if lg else {}
    parts.append(f"codeql: recall {f(m.get('recall'))} false pos {f(m.get('fpr'))}")
    say(f"   {name:13} ({len(sv)} vulnerable, {len(sn)} non-vulnerable)  " + "   ".join(parts))
say()

# ------------------------------------------------------------------ F. naming CWEs
say("F. Naming a CWE (the labelled CWE can be broader or narrower than what the model names; 'without' is told not to guess a CWE, so compare with 'neutral', not 'without')")
for c in CONDS:
    vf = [k for i in vul_ids for k in runs[(i, c)] if k["det"]]; nf = [k for i in non_ids for k in runs[(i, c)] if k["det"]]
    say(f"   {c:9} vulnerable runs with a finding: {len(vf):4}  name a CWE {100*sum(k['names'] for k in vf)/max(1,len(vf)):.0f}%  name the labelled CWE {100*sum(k['match'] for k in vf)/max(1,len(vf)):.0f}%")
    say(f"   {'':9} non-vulnerable runs with a finding: {len(nf):4}  name a CWE {100*sum(k['names'] for k in nf)/max(1,len(nf)):.0f}%")


# ------------------------------------------------------------------ G. references versus the caution sentence
if "neutral" in CONDS:
    say()
    say("G. Separating the effect of the references from the effect of the caution sentence")
    say("   'without' tells the model not to guess a CWE; 'neutral' says only that no entries are provided.")
    def pair(a, b):
        def fn(sample):
            ma, mb = metrics(sample, val[a]), metrics(sample, val[b])
            return {k: ma[k] - mb[k] for k in ("recall", "fpr", "f1", "line_exact_all") if ma.get(k) is not None and mb.get(k) is not None}
        return fn
    def show(title, grp, a, b):
        sv = sum(1 for i in grp if funcs[i]["label"] == 1); sn = len(grp) - sv
        say(f"   {title}  ({sv} vulnerable, {sn} non-vulnerable functions)")
        if not sv or not sn:
            say("      too few of one class to compare"); return
        P3, C3 = boot(grp, pair(a, b))
        for k, name in (("recall", "recall"), ("fpr", "false positive rate"), ("f1", "F1"), ("line_exact_all", "line exact (all vulnerable)")):
            if k in P3:
                ci = C3.get(k)
                say(f"      {name:30} {P3[k]:+.3f} " + (f"[{ci[0]:+.3f}, {ci[1]:+.3f}]" if ci and ci[0] is not None else ""))
    show("references effect: with minus neutral, functions grounded in most runs", major, "with", "neutral")
    show("caution effect: without minus neutral, all functions", ids, "without", "neutral")
    show("caution effect again: with minus neutral, functions NOT grounded (same prompts as 'without' versus 'neutral')", rest, "with", "neutral")
    say("   Levels on the grounded functions:")
    for c in CONDS:
        m = metrics(major, val[c])
        say(f"      {c:9} recall {f(m.get('recall'))}   false positive rate {f(m.get('fpr'))}")
    say("   Reading: if 'with minus neutral' on the grounded functions is still clearly above 0, the reference text itself pushes the model to report more.")
    say("   If 'without minus neutral' is clearly below 0, the caution sentence suppresses findings.")

with open(RESULTS / "evaluation_summary.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(OUT))
with open(RESULTS / "per_function.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    extra = ["neutral_detected", "neutral_exact"] if "neutral" in CONDS else []
    w.writerow(["id", "rank", "label", "cwe", "n_chars", "with_detected", "without_detected", "with_exact", "without_exact", "with_grounded", "codeql_detected", "codeql_exact"] + extra)
    for i in ids:
        w.writerow([i, funcs[i]["rank"], funcs[i]["label"], funcs[i]["cwe"], funcs[i]["n_chars"],
                    round(val["with"]["det"][i], 3), round(val["without"]["det"][i], 3), round(val["with"]["exact"][i], 3),
                    round(val["without"]["exact"][i], 3), round(val["with"]["grounded"][i], 3),
                    val["codeql"]["det"].get(i, ""), val["codeql"]["exact"].get(i, "")]
                   + ([round(val["neutral"]["det"][i], 3), round(val["neutral"]["exact"][i], 3)] if "neutral" in CONDS else []))
print(f"\nwritten: evaluation_summary.txt and per_function.csv in {RESULTS}")
