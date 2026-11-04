"""Turn CodeQL alerts into per-function detections for the evaluation set.

Reads (from results\\):  codeql\\status.csv, sample_v2.jsonl, codeql\\locations_NNN.json, codeql\\sarif_NNN.sarif
Writes:                  eval_set.jsonl            the 400 functions from commits where CodeQL finished OK
                         codeql_detections.csv     one row per function: did CodeQL alert inside it, and on a labelled line?

Rules (state these in the report):
  detected      = CodeQL has at least one alert whose primary location is inside the function (same file, line within it)
  line_exact    = for a vulnerable function: an alert sits exactly on a labelled vulnerable line
  line_pm2      = same, allowing 2 lines either side
Labelled vulnerable lines = the lines the fixing commit removed (numbers within the function, converted to file lines).
Functions CodeQL could not locate in their file are left blank and excluded from CodeQL's counts.
"""
import os
import csv, json, sys
from pathlib import Path

RESULTS = Path(os.environ.get("CHECKGATE_RESULTS", "results"))   # or pass --results
if "--results" in sys.argv:           # test hook
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])
CQ = RESULTS / "codeql"


def norm(p):
    p = (p or "").replace("\\", "/")
    return p[2:] if p.startswith("./") else p


def main():
    last = {}
    with open(CQ / "status.csv", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            last[int(r["rank"])] = r["status"]
    ok_ranks = sorted(k for k, v in last.items() if v == "ok")

    funcs = {}
    for line in open(RESULTS / "sample_v2.jsonl", encoding="utf-8"):
        r = json.loads(line); funcs[r["id"]] = r

    eval_rows, out = [], []
    for rank in ok_ranks:
        locs = json.loads((CQ / f"locations_{rank:03d}.json").read_text(encoding="utf-8"))
        sarif = json.loads((CQ / f"sarif_{rank:03d}.sarif").read_text(encoding="utf-8"))
        alerts = []
        for res in sarif["runs"][0]["results"]:
            try:
                loc = res["locations"][0]["physicalLocation"]
                alerts.append((norm(loc["artifactLocation"]["uri"]), loc["region"]["startLine"], res.get("ruleId", "")))
            except (KeyError, IndexError):
                continue
        for lc in locs:
            fn = funcs[lc["id"]]
            eval_rows.append(fn)
            row = {"id": lc["id"], "rank": rank, "label": lc["label"], "located": int(lc["start"] is not None),
                   "start": lc["start"] if lc["start"] is not None else "", "end": lc["end"] if lc["end"] is not None else "",
                   "n_alerts": "", "detected": "", "line_exact": "", "line_pm2": "", "rules": ""}
            if lc["start"] is not None:
                path = norm(lc["file_path"])
                inside = [a for a in alerts if a[0] == path and lc["start"] <= a[1] <= lc["end"]]
                row["n_alerts"] = len(inside)
                row["detected"] = int(bool(inside))
                row["rules"] = ";".join(sorted({a[2] for a in inside}))
                if lc["label"] == 1:
                    vul = {lc["start"] + v - 1 for v in lc.get("vul_lines", [])}
                    lines = [a[1] for a in inside]
                    row["line_exact"] = int(any(l in vul for l in lines))
                    row["line_pm2"] = int(any(abs(l - v) <= 2 for l in lines for v in vul))
            out.append(row)

    with open(RESULTS / "eval_set.jsonl", "w", encoding="utf-8") as f:
        for r in eval_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    cols = ["id", "rank", "label", "located", "start", "end", "n_alerts", "detected", "line_exact", "line_pm2", "rules"]
    with open(RESULTS / "codeql_detections.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(out)

    loc_rows = [r for r in out if r["located"]]
    v = [r for r in loc_rows if r["label"] == 1]; n = [r for r in loc_rows if r["label"] == 0]
    tp = sum(r["detected"] for r in v); fp = sum(r["detected"] for r in n)
    print(f"commits with CodeQL results: {len(ok_ranks)}   functions in evaluation set: {len(eval_rows)}   located: {len(loc_rows)}")
    print(f"vulnerable located: {len(v)}   non-vulnerable located: {len(n)}")
    if v and n:
        prec = tp / (tp + fp) if tp + fp else float("nan")
        print(f"CodeQL  detected {tp} of {len(v)} vulnerable (recall {tp / len(v):.3f}),  flagged {fp} of {len(n)} non-vulnerable (false positive rate {fp / len(n):.3f})")
        print(f"        precision {prec:.3f}")
        print(f"        alert on a labelled line: exact {sum(r['line_exact'] for r in v)}  within 2 lines {sum(r['line_pm2'] for r in v)}  (of {len(v)})")
    print("files written to", RESULTS)


if __name__ == "__main__":
    main()
