"""Build the blinded batches for the LLM judge (RQ3).

Reads (from results\\): eval_set.jsonl, gemini_results.jsonl, codeql\\status.csv, codeql\\locations_NNN.json, codeql\\sarif_NNN.sarif
Writes (to results\\judge\\):
  judge_batch_01.txt ...      paste each one into a fresh Claude chat, in order
  judge_key.csv               which item is which (do not open until all batches are scored)
  human_check_template.csv    24 items for YOU to score yourself, before you look at the judge's scores
Groups: codeql = one alert message per function CodeQL raised an alert in; with / neutral = one CheckGate finding per function,
matched to the CodeQL group's mix of vulnerable and non-vulnerable functions.
"""
import os
import csv, json, random, re, sys
from pathlib import Path

RESULTS = Path(os.environ.get("CHECKGATE_RESULTS", "results"))   # or pass --results
if "--results" in sys.argv:
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])
SEED, BATCH, HUMAN_N = 907, 9, 24
OUT = RESULTS / "judge"; OUT.mkdir(parents=True, exist_ok=True)
CQ = RESULTS / "codeql"

HEADER = """You are an independent judge scoring explanations of reported security issues in Java code.
You will see several items. Each item has a Java function (with line numbers), the line that was reported, and an explanation of the issue.
Score every item on its own. Do not compare items, and do not try to guess who or what wrote an explanation.

Score two things, each from 1 to 5:

CLARITY: can a developer understand what is wrong, where, and why it matters?
  1 = confusing, or never says plainly what is wrong
  3 = the problem is named, but it takes effort to follow or is vague about where or why
  5 = states plainly what is wrong, where, and why it matters, so a developer could act on it

TRUSTWORTHINESS: are the claims supported by the code shown?
  1 = the claims are wrong, or are not supported by the code shown (including invented code or behaviour)
  3 = mostly supported, with some unsupported detail, or the reported line is questionable
  5 = every claim can be checked against the code shown, and the reported line is right

Rules:
- Judge only against the code shown. Do not use outside knowledge of what the project does.
- Do not reward length. A short explanation can score 5, and a long one can score 1.
- If the explanation says there is a problem that the code does not show, TRUSTWORTHINESS is at most 2.
- Trustworthiness is about whether the explanation is supported by the code, not about whether you think the function is truly vulnerable.

Reply with one JSON object per line and nothing else, in the same order as the items, like this:
{"item": "J001", "clarity": 4, "trust": 3, "note": "at most 15 words"}
"""


def clean(text):
    text = re.sub(r"\[([^\]]*)\]\(\d+\)", r"\1", text or "")      # CodeQL link markup [text](1) -> text
    return re.sub(r"\s+", " ", text).strip()


def norm(p):
    p = (p or "").replace("\\", "/")
    return p[2:] if p.startswith("./") else p


funcs = {}
for line in open(RESULTS / "eval_set.jsonl", encoding="utf-8"):
    r = json.loads(line); funcs[r["id"]] = r

# ---- CodeQL items: the first alert inside each function that has one
last = {}
for r in csv.DictReader(open(CQ / "status.csv", encoding="utf-8", newline="")):
    last[int(r["rank"])] = r["status"]
cq_items = []
for rank in sorted(k for k, v in last.items() if v == "ok"):
    locs = json.loads((CQ / f"locations_{rank:03d}.json").read_text(encoding="utf-8"))
    sarif = json.loads((CQ / f"sarif_{rank:03d}.sarif").read_text(encoding="utf-8"))
    alerts = []
    for res in sarif["runs"][0]["results"]:
        try:
            pl = res["locations"][0]["physicalLocation"]
            alerts.append((norm(pl["artifactLocation"]["uri"]), pl["region"]["startLine"], res["message"]["text"]))
        except (KeyError, IndexError):
            continue
    for lc in locs:
        if lc["start"] is None: continue
        inside = sorted((a for a in alerts if a[0] == norm(lc["file_path"]) and lc["start"] <= a[1] <= lc["end"]), key=lambda a: a[1])
        if inside:
            a = inside[0]
            cq_items.append({"group": "codeql", "fid": lc["id"], "label": lc["label"], "run": "", "line": a[1] - lc["start"] + 1, "text": clean(a[2])})
n_v = sum(1 for i in cq_items if i["label"] == 1); n_n = len(cq_items) - n_v

# ---- CheckGate items: matched to the CodeQL group's mix
rng = random.Random(SEED)
pool = {"with": [], "neutral": []}
for line in open(RESULTS / "gemini_results.jsonl", encoding="utf-8"):
    if not line.strip(): continue
    r = json.loads(line)
    if r.get("error") or r["condition"] not in pool or not r["findings"] or r["id"] not in funcs: continue
    f = r["findings"][0]
    if clean(f.get("reasoning")):
        pool[r["condition"]].append({"group": r["condition"], "fid": r["id"], "label": funcs[r["id"]]["label"], "run": r["run"], "line": f["line"], "text": clean(f["reasoning"])})
cg_items = []
for g in ("with", "neutral"):
    rng.shuffle(pool[g]); seen = set(); counts = {1: 0, 0: 0}; need = {1: n_v, 0: n_n}
    for it in pool[g]:
        if it["fid"] in seen or counts[it["label"]] >= need[it["label"]]: continue
        seen.add(it["fid"]); counts[it["label"]] += 1; cg_items.append(it)
    print(f"{g}: {counts[1]} vulnerable + {counts[0]} non-vulnerable items (wanted {n_v} + {n_n})")
print(f"codeql: {n_v} vulnerable + {n_n} non-vulnerable items")

items = cq_items + cg_items
rng.shuffle(items)
for i, it in enumerate(items, 1):
    it["item"] = f"J{i:03d}"
    it["n_words"] = len(it["text"].split())


def render(it):
    code = funcs[it["fid"]]["code"].replace("\r\n", "\n").split("\n")
    body = "\n".join(f"{n:>3}: {l}" for n, l in enumerate(code, 1))
    return f"=== ITEM {it['item']} ===\nJava function (line numbers added):\n{body}\n\nReported issue on line {it['line']}:\n{it['text']}\n"


for b in range(0, len(items), BATCH):
    chunk = items[b:b + BATCH]
    (OUT / f"judge_batch_{b // BATCH + 1:02d}.txt").write_text(HEADER + "\nItems: " + ", ".join(i["item"] for i in chunk) + "\n\n" + "\n".join(render(i) for i in chunk), encoding="utf-8")

with open(OUT / "judge_key.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["item", "group", "function_id", "label", "run", "reported_line", "n_words"])
    for it in sorted(items, key=lambda x: x["item"]):
        w.writerow([it["item"], it["group"], it["fid"], it["label"], it["run"], it["line"], it["n_words"]])
human = sorted(rng.sample([i["item"] for i in items], min(HUMAN_N, len(items))))
with open(OUT / "human_check_template.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["item", "clarity", "trust"])
    for h in human: w.writerow([h, "", ""])
print(f"{len(items)} items in {-(-len(items) // BATCH)} batches; {len(human)} items for your own check. Written to {OUT}")
