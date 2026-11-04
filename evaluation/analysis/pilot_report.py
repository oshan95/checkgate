"""Read the pilot run (references on, one run per function) and report what it says about the similarity floor.

Reads results\\pilot_results.jsonl and results\\pilot.jsonl. Prints:
  1. how often the first step answered NONE (retrieval skipped), by class
  2. the spread of top similarity scores, by class
  3. for each vulnerable function: was the labelled CWE among the retrieved entries?
  4. what each candidate floor would do: how many functions get references, and how many of them are relevant
  5. a first look at detection and line hits (a preview only: 20 + 20 functions is too few to report)
Relevance = the labelled CWE id appears among the 5 retrieved entries. Retrieved CVE entries cannot match a CWE
label, so relevance is slightly under-counted.
"""
import os
import json, statistics, sys
from pathlib import Path

RESULTS = Path(os.environ.get("CHECKGATE_RESULTS", "results"))   # or pass --results
if "--results" in sys.argv:
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])

pilot = {}
for line in open(RESULTS / "pilot.jsonl", encoding="utf-8"):
    r = json.loads(line); pilot[r["id"]] = r
rows = [json.loads(l) for l in open(RESULTS / "pilot_results.jsonl", encoding="utf-8") if l.strip()]
errors = [r for r in rows if r.get("error")]
last = {}
for r in rows:                      # a later successful line replaces an earlier one for the same function
    if not r.get("error"):
        last[r["id"]] = r
res = list(last.values())
vul = [r for r in res if r["label"] == 1]
non = [r for r in res if r["label"] == 0]
print(f"pilot results: {len(res)} functions ({len(vul)} vulnerable, {len(non)} non-vulnerable); lines with errors: {len(errors)}\n")


def is_none(r):
    return (r.get("description") or "").strip().upper() == "NONE"


def spread(vals):
    if not vals: return "none"
    v = sorted(vals)
    return f"min {v[0]:.3f}  median {statistics.median(v):.3f}  max {v[-1]:.3f}  (n={len(v)})"


print("1. First step answered NONE (retrieval skipped)")
for name, grp in (("vulnerable", vul), ("non-vulnerable", non)):
    n = sum(is_none(r) for r in grp)
    print(f"   {name}: {n} of {len(grp)}")
print()

print("2. Top similarity score where retrieval ran")
for name, grp in (("vulnerable", vul), ("non-vulnerable", non)):
    print(f"   {name}: " + spread([r["top_similarity"] for r in grp if r.get("top_similarity") is not None]))
print()

print("3. Vulnerable functions: labelled CWE vs what was retrieved")
print(f"   {'id':10} {'label':8} {'top sim':8} {'top-1':10} labelled CWE in top 5?")
rel = {}
for r in sorted(vul, key=lambda x: x["id"]):
    ids = [x["id"] for x in r.get("retrieved", [])]
    rel[r["id"]] = r["cwe"] in ids
    top = f"{r['top_similarity']:.3f}" if r.get("top_similarity") is not None else "NONE" if is_none(r) else "-"
    print(f"   {r['id']:10} {r['cwe']:8} {top:8} {(ids[0] if ids else '-'):10} {'yes' if rel[r['id']] else 'no'}")
n_rel = sum(rel.values())
print(f"   labelled CWE found among the 5 retrieved: {n_rel} of {len(vul)} vulnerable functions\n")

print("4. Candidate floors (a function is grounded if its top similarity is at or above the floor)")
print(f"   {'floor':6} {'grounded vuln':14} {'  of which relevant':20} {'relevant but dropped':22} {'grounded non-vuln'}")
for f in [0.70, 0.72, 0.74, 0.76, 0.78, 0.80, 0.82, 0.84, 0.86]:
    g = [r for r in vul if r.get("top_similarity") is not None and r["top_similarity"] >= f]
    g_rel = sum(rel[r["id"]] for r in g)
    dropped = sum(1 for r in vul if rel[r["id"]] and r not in g)
    gn = sum(1 for r in non if r.get("top_similarity") is not None and r["top_similarity"] >= f)
    mark = "  <- current" if abs(f - 0.80) < 1e-9 else ""
    print(f"   {f:<6.2f} {len(g):<14} {g_rel:<20} {dropped:<22} {gn}{mark}")
print()

print("5. Preview of detection (references on, floor as run; far too few functions to report as results)")
def hit(r, tol):
    vl = set(pilot[r["id"]].get("vul_lines", []))
    return any(abs(f["line"] - v) <= tol for f in r["findings"] for v in vl)
print(f"   vulnerable functions with at least one finding: {sum(bool(r['findings']) for r in vul)} of {len(vul)}")
print(f"   ...with a finding on a labelled line: exact {sum(hit(r, 0) for r in vul)}, within 2 lines {sum(hit(r, 2) for r in vul)}")
print(f"   non-vulnerable functions with a finding: {sum(bool(r['findings']) for r in non)} of {len(non)}")
print(f"   mean time per function: retrieval {statistics.mean(r['retrieval_ms'] for r in res)/1000:.1f} s, analysis {statistics.mean(r['analysis_ms'] for r in res)/1000:.1f} s")
