"""Build the evaluation sample from MegaVul (Java subset). Reproduces the sample used in the final report.

Input : megavul_simple.json (download from the MegaVul project; not included here because MegaVul is GPL-3.0)
Output (in the output folder):
  sample.jsonl, sample_manifest.csv   a first 200 + 200 draw. It is only used to keep the pilot set separate.
  pilot.jsonl,  pilot_manifest.csv    40 functions (20 + 20) used to check the 0.80 similarity floor
  sample_v2.jsonl                     the final draw: 4 vulnerable + 4 length-matched non-vulnerable functions per fix commit
  commits_ranked.csv                  fix commits in the order CodeQL is run (the first 50 that finish form the evaluation set)

Usage:  python build_sample.py --data path/to/megavul_simple.json --out path/to/results [--compare old_sample_v2.jsonl]
The random seed is fixed (907), so the same input file gives the same sample.
"""
import argparse, collections, csv, hashlib, json, random, re, statistics
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--data", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--compare", help="an existing sample_v2.jsonl; report whether this run reproduces it")
args = ap.parse_args()
PATH, OUT = args.data, Path(args.out)
OUT.mkdir(parents=True, exist_ok=True)

SEED, N_PER_CLASS, N_PILOT_PER_CLASS = 907, 200, 20
MIN_CHARS, MAX_CHARS, MAX_PER_REPO = 100, 8000, 10
COMMITS_WANTED, RESERVE, PAIRS_PER_COMMIT, MAX_COMMITS_PER_REPO = 50, 40, 4, 3

HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@")


def deleted_lines(diff, code):
    """Line numbers (within the function) of the lines the fix removed; kept only if the text matches func_before."""
    lines, found, old = code.split("\n"), [], None
    for ln in (diff or "").split("\n"):
        m = HUNK.match(ln)
        if m:
            old = int(m.group(1)); continue
        if old is None or ln.startswith("\\"):
            continue
        if ln.startswith("-"):
            if 1 <= old <= len(lines) and lines[old - 1].strip() == ln[1:].strip():
                found.append(old)
            old += 1
        elif not ln.startswith("+"):
            old += 1
    return found


def key(code):
    return hashlib.md5(re.sub(r"\s+", " ", code).encode()).hexdigest()


with open(PATH, encoding="utf-8") as f:
    data = json.load(f)

# ---------------------------------------------------------------- eligible functions
seen, vul, non, dropped = set(), [], [], collections.Counter()
for r in data:
    code = r["func_before"] if r.get("is_vul") else r["func"]
    if not code or not (MIN_CHARS <= len(code) <= MAX_CHARS):
        dropped["length"] += 1; continue
    k = key(code)
    if k in seen:
        dropped["duplicate"] += 1; continue
    seen.add(k)
    rec = dict(label=1 if r["is_vul"] else 0, code=code, cve_id=r["cve_id"], cwe=(r["cwe_ids"] or ["unknown"])[0],
               repo=r["repo_name"], commit=r["commit_hash"], func_name=r["func_name"], file_path=r["file_path"],
               n_chars=len(code), n_lines=code.count("\n") + 1)
    if r["is_vul"]:
        rec["vul_lines"] = deleted_lines(r.get("diff_func"), code)
        if not rec["vul_lines"]:
            dropped["no labelled line"] += 1; continue
        vul.append(rec)
    else:
        rec["vul_lines"] = []
        non.append(rec)
print("eligible vulnerable:", len(vul), " eligible non-vulnerable:", len(non), " dropped:", dict(dropped))


def pick_vulnerable(pool, n, rng):
    by_cwe = collections.defaultdict(list)
    for r in pool: by_cwe[r["cwe"]].append(r)
    for lst in by_cwe.values(): rng.shuffle(lst)
    order, chosen, per_repo = sorted(by_cwe), [], collections.Counter()
    while len(chosen) < n and any(by_cwe.values()):
        for c in order:
            while by_cwe[c]:
                r = by_cwe[c].pop()
                if per_repo[r["repo"]] < MAX_PER_REPO:
                    chosen.append(r); per_repo[r["repo"]] += 1; break
            if len(chosen) >= n: break
    return chosen


def match_non(vuls, pool, rng):
    pool, out, same = pool[:], [], 0
    for v in vuls:
        same_repo = [p for p in pool if p["repo"] == v["repo"]]
        cand = same_repo or pool
        best = min(cand, key=lambda p: abs(p["n_chars"] - v["n_chars"]) + rng.random())
        same += bool(same_repo)
        out.append(best); pool.remove(best)
    return out, same


def build(name, n, seed, vpool, npool):
    rng = random.Random(seed)
    vs = pick_vulnerable(vpool, n, rng)
    ns, same = match_non(vs, npool, rng)
    rows = []
    for i, r in enumerate(vs): rows.append({**r, "id": f"{name}-V{i+1:03d}"})
    for i, r in enumerate(ns): rows.append({**r, "id": f"{name}-N{i+1:03d}"})
    with open(OUT / f"{name}.jsonl", "w", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(OUT / f"{name}_manifest.csv", "w", newline="", encoding="utf-8") as f:
        cols = ["id", "label", "cve_id", "cwe", "repo", "commit", "func_name", "file_path", "n_chars", "n_lines", "vul_lines"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)
    print(f"\n[{name}] vulnerable {len(vs)}, non-vulnerable {len(ns)}, same-repo matches {same}/{len(ns)}")
    print(f"  repos: {len({r['repo'] for r in rows})}, CWE types among vulnerable: {len({r['cwe'] for r in vs})}")
    return rows


# ---------------------------------------------------------------- first draw, then the pilot (kept separate from it)
first = build("sample", N_PER_CLASS, SEED, vul, non)
used = {r["code"] for r in first}
pilot = build("pilot", N_PILOT_PER_CLASS, SEED + 1, [r for r in vul if r["code"] not in used], [r for r in non if r["code"] not in used])

# ---------------------------------------------------------------- final draw, by fix commit (CodeQL needs one database per commit)
pilot_codes = {r["code"] for r in pilot}
pilot_commits = {(r["repo"], r["commit"]) for r in pilot}
vul2 = [r for r in vul if r["code"] not in pilot_codes]
non2 = [r for r in non if r["code"] not in pilot_codes]

url_of = {(r["repo_name"], r["commit_hash"]): r["git_url"] for r in data}
vul_by_c, non_by_c = collections.defaultdict(list), collections.defaultdict(list)
for r in vul2: vul_by_c[(r["repo"], r["commit"])].append(r)
for r in non2: non_by_c[(r["repo"], r["commit"])].append(r)


def best_pairs(vs, ns, n):
    cand = sorted((abs(v["n_chars"] - x["n_chars"]) / max(v["n_chars"], x["n_chars"]), i, j)
                  for i, v in enumerate(vs) for j, x in enumerate(ns))
    used_v, used_n, out = set(), set(), []
    for d, i, j in cand:
        if i in used_v or j in used_n: continue
        out.append((vs[i], ns[j], d)); used_v.add(i); used_n.add(j)
        if len(out) == n: break
    return out


eligible = [k for k, v in vul_by_c.items()
            if len(v) >= PAIRS_PER_COMMIT and len(non_by_c.get(k, [])) >= PAIRS_PER_COMMIT
            and k not in pilot_commits and url_of[k].startswith("https://github.com/")]
print("\neligible commits:", len(eligible))

rng = random.Random(SEED)
groups = collections.defaultdict(list)
for k in eligible:
    groups[collections.Counter(r["cwe"] for r in vul_by_c[k]).most_common(1)[0][0]].append(k)
for g in groups.values(): rng.shuffle(g)

target = COMMITS_WANTED + RESERVE
ranked, per_repo = [], collections.Counter()
while len(ranked) < target and any(groups.values()):
    for c in sorted(groups):
        while groups[c]:
            k = groups[c].pop()
            if per_repo[k[0]] < MAX_COMMITS_PER_REPO:
                ranked.append(k); per_repo[k[0]] += 1; break
        if len(ranked) >= target: break

rows = []
for rank, k in enumerate(ranked, 1):
    clone_url = url_of[k].split("/commit/")[0] + ".git"
    for i, (v, n, d) in enumerate(best_pairs(vul_by_c[k], non_by_c[k], PAIRS_PER_COMMIT), 1):
        rows.append({**v, "id": f"C{rank:03d}-V{i}", "rank": rank, "clone_url": clone_url})
        rows.append({**n, "id": f"C{rank:03d}-N{i}", "rank": rank, "clone_url": clone_url})

with open(OUT / "sample_v2.jsonl", "w", encoding="utf-8") as f:
    for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")
with open(OUT / "commits_ranked.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["rank", "repo", "commit", "clone_url", "checkout"])
    for rank, k in enumerate(ranked, 1):
        w.writerow([rank, k[0], k[1], url_of[k].split("/commit/")[0] + ".git", k[1] + "^"])

first50 = [r for r in rows if r["rank"] <= COMMITS_WANTED]
fv, fn = [r for r in first50 if r["label"] == 1], [r for r in first50 if r["label"] == 0]
print(f"ranked commits: {len(ranked)}; functions in sample_v2: {len(rows)}")
if fv and fn:
    print(f"first {COMMITS_WANTED} commits: {len(fv)} vulnerable + {len(fn)} non-vulnerable; "
          f"mean chars vulnerable {statistics.mean(r['n_chars'] for r in fv):.0f}, non-vulnerable {statistics.mean(r['n_chars'] for r in fn):.0f}")

if args.compare:
    old = {json.loads(l)["id"]: json.loads(l)["code"] for l in open(args.compare, encoding="utf-8") if l.strip()}
    new = {r["id"]: r["code"] for r in rows}
    same = old == new
    print("\nreproduces the existing sample_v2.jsonl exactly:", same)
    if not same:
        print("  only in old:", len(set(old) - set(new)), " only in new:", len(set(new) - set(old)),
              " same id, different code:", sum(1 for k in old if k in new and old[k] != new[k]))
print("\nFiles written to", OUT)
