"""Script to perform exhaustive static audit searches for Phase ML-4 Section L."""

import os
import re
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SEARCH_TERMS = [
    "training_dataset_legacy",
    "ground_truth_raw_events",
    "labeled_events_remediated",
    "remediated_dataset_v3",
    "threat_score",
    "is_malicious",
    "label",
    "target",
    "train_test_split",
    "StratifiedKFold",
    "StandardScaler",
    "fit_transform",
    "transform",
    "random_state",
    "seed",
    "iloc",
    "[:, :12]",
]


def classify_file_occurrence(filepath: str, term: str) -> str:
    fp = filepath.replace("\\", "/").lower()
    if fp.startswith("docs/") or fp.endswith(".md") or "evidence" in fp or "report" in fp:
        return "DOCUMENTATION"
    elif fp.startswith("tests/"):
        return "TEST"
    elif "legacy" in fp or "baseline_preservation" in fp or "complete" in fp or "v2" in fp or "evaluation_output" in fp or "ai_engine" in fp:
        return "QUARANTINED"
    elif "lstm" in fp:
        return "EXPERIMENTAL"
    elif fp.startswith("backend/") or fp.startswith("experiments/") or fp.startswith("scripts/"):
        return "ACTIVE"
    else:
        return "SAFE/IRRELEVANT"


def main():
    findings = defaultdict(lambda: defaultdict(int))
    file_matches = defaultdict(lambda: defaultdict(list))

    # Scan python and markdown files
    for p in PROJECT_ROOT.glob("**/*"):
        if not p.is_file():
            continue
        rel_p = str(p.relative_to(PROJECT_ROOT)).replace("\\", "/")
        if any(ign in rel_p for ign in [".git", "__pycache__", ".pytest_cache", ".venv", "node_modules"]):
            continue
        if p.suffix.lower() not in [".py", ".md", ".json", ".csv", ".txt"]:
            continue

        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        for term in SEARCH_TERMS:
            pattern = re.escape(term)
            matches = len(re.findall(pattern, content))
            if matches > 0:
                classification = classify_file_occurrence(rel_p, term)
                findings[term][classification] += matches
                file_matches[term][classification].append((rel_p, matches))

    print("===========================================================================")
    print("           PHANTOMNET PHASE ML-4: STATIC REPOSITORY SEARCH AUDIT           ")
    print("===========================================================================\n")
    for term in SEARCH_TERMS:
        print(f"Query: '{term}'")
        for cls, count in sorted(findings[term].items()):
            print(f"  - {cls:<16}: {count} occurrences")
        print()


if __name__ == "__main__":
    main()
