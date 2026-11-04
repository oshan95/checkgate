# Evaluation

The scripts use only the Python standard library (Python 3.10 or later). The Java side is the evaluation runner in `checkgate-service` (`com.oshan.checkgate.evaluation`), which only exists under the `eval` Spring profile and never posts to GitHub.

Set where results are read and written (a folder outside git):

```
# PowerShell
$env:CHECKGATE_RESULTS = "C:\path\to\results"
# bash
export CHECKGATE_RESULTS=/path/to/results
```

Every script also accepts `--results <folder>`.

## Data and licences

- **MegaVul** (Java subset, `megavul_simple.json`) is not included, because it is GPL-3.0 and large: https://github.com/Icyrockton/MegaVul. Do not commit the generated `.jsonl` files either, since they contain MegaVul code.
- **CodeQL** is not included. It was used under its terms for open-source code and academic research. Set `CODEQL_CLI` to the CLI path if it is not on `PATH`.

## Steps

1. **Sample.** Builds the pilot set and the final sample, by fix commit.
   `python evaluation/sampling/build_sample.py --data megavul_simple.json --out results`
   Add `--compare old_sample_v2.jsonl` to check that you reproduce an existing sample. The seed is fixed (907).
2. **CodeQL.** Fetches each fix commit's parent, builds a CodeQL database without a build, runs the `java-security-extended` queries, and keeps the SARIF. It is resumable, skips projects with more than 1,500 Java files, and stops after 50 commits succeed.
   `python evaluation/codeql/run_codeql.py` (use `--dry` first to check fetching, `--only N` to test one commit)
3. **Detections.** Turns CodeQL alerts into per-function detections and writes `eval_set.jsonl` (the functions from the commits that finished) and `codeql_detections.csv`.
   `python evaluation/codeql/codeql_detections.py`
4. **Pilot run** (similarity floor check, references on, one run):
   `java -jar target/checkgate-service-0.0.1-SNAPSHOT.jar --spring.profiles.active=eval --eval.input=<results>/pilot.jsonl --eval.output=<results>/pilot_results.jsonl --eval.conditions=with --eval.runs=1`
   then `python evaluation/analysis/pilot_report.py`
5. **Main run** (three conditions, three runs each; the runner skips finished runs and retries failed ones):
   `java -jar target/checkgate-service-0.0.1-SNAPSHOT.jar --spring.profiles.active=eval --eval.input=<results>/eval_set.jsonl --eval.output=<results>/gemini_results.jsonl --eval.conditions=with,without,neutral --eval.runs=3 --eval.threads=4`
   then `python evaluation/analysis/evaluate.py`
   Conditions: `with` is the production path (references when the best match is 0.80 or higher); `without` uses the standard "no reliable reference entries" wording; `neutral` uses a plain line with no instruction.
6. **Explanation scoring.** `python evaluation/judge/make_judge_batches.py` builds shuffled, blinded batches. Paste each batch into a fresh chat with the judge model, save all replies to `<results>/judge/judge_scores.txt`, then run `python evaluation/judge/judge_analyse.py`. Optionally score some items yourself first with `make_human_check.py` to measure agreement.

## Settings used

| Setting | Value |
|---|---|
| Model | `gemini-3.5-flash-lite` (retrieval thinking `MEDIUM`, analysis thinking `LOW`); embeddings `gemini-embedding-001` |
| Similarity floor, entries retrieved | 0.80, 5 |
| Temperature and other sampling settings | not set (model defaults) |
| Sample | 400 functions (200 vulnerable, 200 non-vulnerable) from 50 fix commits, matched by length within each commit |
| CodeQL | bundle 2.27.3, `java-security-extended`, extraction without a build |
| Runs | 3 per function and condition (3,600 runs) |
| Judge | Claude Sonnet 5.5 in a fresh chat, 72 items in 8 batches of 9 |

## Results summary

`results-summary/` holds the aggregate outputs of the runs reported in the final report (no source code): `evaluation_summary.txt`, `per_function.csv`, `codeql_detections.csv`, `judge_summary.txt` and `judge_key.csv`.
