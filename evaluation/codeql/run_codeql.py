"""Run CodeQL over the ranked fix commits (pre-fix version of each), unattended and resumable.

For each commit: fetch only that commit's parent, record where every sampled function sits in its file,
create a CodeQL database (no build), run the security-extended queries, keep the SARIF, delete the checkout.

  python run_codeql.py            full run (skips finished commits, retries failed ones)
  python run_codeql.py --dry      fetch and locate functions only; no CodeQL
  python run_codeql.py --only 2   run just commit rank 2 (for testing settings)
"""
import csv, json, os, shutil, stat, subprocess, sys, time
from collections import Counter, defaultdict
from pathlib import Path

RESULTS = Path(os.environ.get("CHECKGATE_RESULTS", "results"))   # or pass --results
WORK = Path(os.environ.get("CHECKGATE_WORK", "work/runs"))      # scratch folder for checkouts and databases
CODEQL = os.environ.get("CODEQL_CLI", "codeql")                      # path to the CodeQL CLI if it is not on PATH
SUITE = "codeql/java-queries:codeql-suites/java-security-extended.qls"
STEP_TIMEOUT_MIN = 20     # per step (create database, analyse)
RAM_MB = 6000             # memory for each CodeQL step. Close Chrome and other big programs first.
THREADS = 4               # CPU threads for CodeQL (0 would use every core)
MAX_JAVA_FILES = 1500     # skip projects with more Java files than this (too slow on this machine)
TARGET_OK = 50            # stop after this many commits succeed
NET_WAIT_S = int(os.environ.get("CQ_NET_WAIT", 60))    # wait between retries when the network is down
NET_TRIES = int(os.environ.get("CQ_NET_TRIES", 30))    # about 30 minutes in total
NET_ERRORS = ("Could not resolve host", "Failed to connect", "Connection timed out", "Connection reset",
              "Network is unreachable", "Temporary failure in name resolution")

DRY = "--dry" in sys.argv
ONLY = int(sys.argv[sys.argv.index("--only") + 1]) if "--only" in sys.argv else None
if "--results" in sys.argv:           # test hook
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])
if os.name == "nt":   # below-normal priority so the PC stays usable; CodeQL inherits it
    import ctypes
    ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x4000)

OUTDIR = RESULTS / "codeql"
LOGDIR = OUTDIR / "logs"
LOGDIR.mkdir(parents=True, exist_ok=True)
STATUS = OUTDIR / ("status_dry.csv" if DRY else "status.csv")
COLS = ["rank", "repo", "commit", "status", "java_files", "fetch_min", "db_min", "analysis_min", "alerts", "located", "functions"]
RETRY = {"", "fetch_failed", "analysis_failed", "db_failed", "error"}   # retried on the next start


def avail_mb():
    try:
        class M(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong), ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong),
                        ("tpf", ctypes.c_ulonglong), ("apf", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong),
                        ("av", ctypes.c_ulonglong), ("ave", ctypes.c_ulonglong)]
        m = M(); m.l = ctypes.sizeof(m)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return int(m.ap // (1024 * 1024))
    except Exception:
        return None


def run(cmd, cwd=None, timeout_min=STEP_TIMEOUT_MIN):
    """Run a command. Returns (returncode, full output). returncode None means timeout."""
    kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", **kw)
    try:
        out, _ = p.communicate(timeout=timeout_min * 60)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)
            else:
                os.killpg(p.pid, 9)
            p.communicate(timeout=30)
        except Exception:
            pass
        time.sleep(5)          # let child processes release their files
        return None, "timeout"


def _force(func, p, _):
    try:
        os.chmod(p, stat.S_IWRITE); func(p)
    except Exception:
        pass


def rmtree(path):
    """Delete a folder without ever raising (leftovers are cleaned at the next start)."""
    for _ in range(3):
        if not Path(path).exists():
            return
        try:
            shutil.rmtree(path, onerror=_force)
        except Exception:
            pass
        if not Path(path).exists():
            return
        time.sleep(3)


def fetch_parent(url, commit, dest):
    rmtree(dest); dest.mkdir(parents=True, exist_ok=True)
    for cmd in (["git", "init", "-q"], ["git", "config", "core.longpaths", "true"], ["git", "remote", "add", "origin", url],
                ["git", "fetch", "-q", "--depth", "2", "origin", commit],
                ["git", "checkout", "-q", "--detach", "FETCH_HEAD~1"]):
        rc, out = run(cmd, cwd=dest, timeout_min=30)
        if rc != 0:
            return False, f"{' '.join(cmd[:2])}: {out.strip()[-200:]}"
    return True, ""


def count_java(repo_dir, limit):
    n = 0
    for root, dirs, files in os.walk(repo_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        n += sum(f.endswith(".java") for f in files)
        if n > limit:
            return n
    return n


def locate(func, repo_dir):
    """Find the function's lines in the checked-out file. Returns (start, end) or None. Lines are 1-based."""
    path = repo_dir / func["file_path"]
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    code = func["code"].replace("\r\n", "\n")
    i = text.find(code)
    if i >= 0:
        start = text.count("\n", 0, i) + 1
        return start, start + code.count("\n")
    want = [l.strip() for l in code.split("\n")]
    have = [l.strip() for l in text.split("\n")]
    for s in range(len(have) - len(want) + 1):
        if have[s] == want[0] and have[s:s + len(want)] == want:
            return s + 1, s + len(want)
    return None


def read_status():
    """Last status per rank. Rewrites an older status file if its columns are out of date."""
    if not STATUS.exists():
        return {}
    with open(STATUS, encoding="utf-8", newline="") as f:
        rd = csv.DictReader(f)
        rows, old_cols = list(rd), rd.fieldnames
    if old_cols != COLS:
        with open(STATUS, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore", restval="")
            w.writeheader(); w.writerows(rows)
    return {int(r["rank"]): r["status"] for r in rows}


def log_row(row):
    new = not STATUS.exists()
    with open(STATUS, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        if new:
            w.writeheader()
        w.writerow(row)


def short(out, n=250):
    return out[-n:].replace("\n", " ").strip()


def main():
    commits = list(csv.DictReader(open(RESULTS / "commits_ranked.csv", encoding="utf-8")))
    funcs = defaultdict(list)
    for line in open(RESULTS / "sample_v2.jsonl", encoding="utf-8"):
        r = json.loads(line); funcs[int(r["rank"])].append(r)

    rmtree(WORK)                                   # leftovers from an interrupted run
    status = {k: v for k, v in read_status().items() if v not in RETRY}
    ok = sum(1 for s in status.values() if s == "ok")
    print(f"already done: {ok} ok of {len(status)} finished. Target {TARGET_OK}. RAM {RAM_MB} MB, {THREADS} threads, max {MAX_JAVA_FILES} Java files.")
    for c in commits:
        rank = int(c["rank"])
        if ONLY is not None:
            if rank != ONLY: continue
        else:
            if ok >= TARGET_OK: break
            if rank in status: continue
        t0 = time.time()
        row = {k: "" for k in COLS}
        row.update(rank=rank, repo=c["repo"], commit=c["commit"], functions=len(funcs[rank]))
        repo_dir, db_dir = WORK / f"r{rank:03d}", WORK / f"db{rank:03d}"
        am = avail_mb()
        print(f"[{rank}] {c['repo']}  (available memory {am if am is not None else '?'} MB)")
        try:
            t = time.time()
            good, err = fetch_parent(c["clone_url"], c["commit"], repo_dir)
            tries = 0
            while not good and any(e in err for e in NET_ERRORS) and tries < NET_TRIES:
                tries += 1
                print(f"   network seems to be down, waiting {NET_WAIT_S} s ({tries}/{NET_TRIES})")
                time.sleep(NET_WAIT_S)
                good, err = fetch_parent(c["clone_url"], c["commit"], repo_dir)
            if not good and any(e in err for e in NET_ERRORS):
                print("Network is still down. Stopping without recording a result; run the script again when it is back.")
                sys.exit(1)
            row["fetch_min"] = round((time.time() - t) / 60, 1)
            if not good:
                row["status"] = "fetch_failed"; print("   FETCH FAILED", err); continue

            n_java = count_java(repo_dir, MAX_JAVA_FILES)
            row["java_files"] = n_java if n_java <= MAX_JAVA_FILES else f">{MAX_JAVA_FILES}"
            if n_java > MAX_JAVA_FILES:
                row["status"] = "too_large"; print(f"   skipped: more than {MAX_JAVA_FILES} Java files"); continue

            locs, found = [], 0
            for fn in funcs[rank]:
                loc = locate(fn, repo_dir)
                found += loc is not None
                locs.append({"id": fn["id"], "label": fn["label"], "file_path": fn["file_path"],
                             "start": loc[0] if loc else None, "end": loc[1] if loc else None,
                             "vul_lines": fn.get("vul_lines", [])})
            row["located"] = found
            (OUTDIR / f"locations_{rank:03d}.json").write_text(json.dumps(locs), encoding="utf-8")

            if DRY:
                row["status"] = "dry"; print(f"   located {found}/{len(locs)}  ({n_java} Java files)"); continue

            t = time.time()
            rc, out = run([CODEQL, "database", "create", str(db_dir), "--language=java", "--build-mode=none",
                           f"--source-root={repo_dir}", "--overwrite", f"--ram={RAM_MB}", f"--threads={THREADS}"])
            (LOGDIR / f"{rank:03d}_create.log").write_text(out, encoding="utf-8", errors="replace")
            row["db_min"] = round((time.time() - t) / 60, 1)
            if rc != 0:
                row["status"] = "db_timeout" if rc is None else "db_failed"
                print("  ", row["status"], short(out)); continue

            t = time.time()
            sarif = OUTDIR / f"sarif_{rank:03d}.sarif"
            rc, out = run([CODEQL, "database", "analyze", str(db_dir), SUITE, "--format=sarif-latest",
                           f"--output={sarif}", f"--ram={RAM_MB}", f"--threads={THREADS}"])
            (LOGDIR / f"{rank:03d}_analyze.log").write_text(out, encoding="utf-8", errors="replace")
            row["analysis_min"] = round((time.time() - t) / 60, 1)
            if rc != 0:
                row["status"] = "analysis_timeout" if rc is None else "analysis_failed"
                print("  ", row["status"], short(out)); continue

            row["alerts"] = len(json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"])
            row["status"] = "ok"; ok += 1
            print(f"   ok  alerts {row['alerts']}  located {found}/{len(locs)}  {n_java} Java files  "
                  f"{(time.time() - t0) / 60:.1f} min   [{ok}/{TARGET_OK}]")
        except Exception as e:
            row["status"] = "error"; print("   ERROR", repr(e))
        finally:
            if row["status"]:
                log_row(row)
            rmtree(repo_dir); rmtree(db_dir)
    final = {}
    if STATUS.exists():
        final = {int(r["rank"]): r["status"] for r in csv.DictReader(open(STATUS, encoding="utf-8"))}
    print("finished:", dict(Counter(final.values())))


if __name__ == "__main__":
    main()
