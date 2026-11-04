"""Collect the items you score yourself into one readable file.

Reads results\\judge\\human_check_template.csv and judge_batch_*.txt; writes results\\judge\\human_check_items.txt
(the rubric once at the top, then your items in order). Fill in the scores in human_check_template.csv.
"""
import os
import csv, re, sys
from pathlib import Path

RESULTS = Path(os.environ.get("CHECKGATE_RESULTS", "results"))   # or pass --results
if "--results" in sys.argv:
    RESULTS = Path(sys.argv[sys.argv.index("--results") + 1])
J = RESULTS / "judge"

wanted = [r["item"] for r in csv.DictReader(open(J / "human_check_template.csv", encoding="utf-8", newline=""))]
blocks, header = {}, None
for f in sorted(J.glob("judge_batch_*.txt")):
    text = f.read_text(encoding="utf-8")
    head, _, rest = text.partition("\nItems:")
    header = header or head
    for m in re.finditer(r"=== ITEM (J\d+) ===\n(.*?)(?=\n=== ITEM J\d+ ===|\Z)", rest, re.S):
        blocks[m.group(1)] = m.group(2).rstrip() + "\n"
missing = [w for w in wanted if w not in blocks]
if missing:
    raise SystemExit(f"These items were not found in the batch files: {missing}")

intro = ("YOUR OWN SCORING (do this before you read any judge scores).\n"
         "For each item, write a clarity score and a trust score, 1 to 5, in human_check_template.csv.\n"
         "Use the rubric below exactly as the judge does.\n\n")
body = "\n".join(f"=== ITEM {w} ===\n{blocks[w]}" for w in wanted)
(J / "human_check_items.txt").write_text(intro + header + "\n\n" + body, encoding="utf-8")
print(f"{len(wanted)} items written to {J / 'human_check_items.txt'}")
