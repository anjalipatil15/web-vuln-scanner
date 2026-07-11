"""
Risk scoring for a completed scan's findings.

Two problems with a purely additive score (sum of severity weights):
  1. Spam inflation: 20 "missing header" (info/low) findings can rack up
     the same score as 2-3 real SQL injections, since it's just addition.
  2. Dilution: a single critical finding can get averaged away into
     "Medium" if there are enough low-severity findings alongside it.

Fix:
  - Diminishing returns *within* a severity tier: the Nth finding of the
    same severity contributes less than the first (via sqrt scaling), so
    repeated low-value findings don't dominate the score.
  - A severity-driven floor: certain severity *counts* force a minimum
    level regardless of the aggregate score (e.g. any critical finding
    means the report can never read below "Critical").

Final level = the worse of (score-based level, severity-floor level).
"""

import math


SEVERITY_SCORE = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 1
}

# Order used anywhere findings need to be sorted "worst first"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

LEVEL_RANK = {
    "None": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


def _score_based_level(score: float) -> str:
    if score >= 60:
        return "Critical"
    if score >= 30:
        return "High"
    if score >= 12:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def _severity_floor_level(counts: dict) -> str:
    """
    Escalation floor based on how many findings of each severity exist,
    independent of the aggregate score. Tune the thresholds below to
    match your risk appetite.
    """
    if counts["critical"] >= 1:
        return "Critical"
    if counts["high"] >= 3:
        return "Critical"
    if counts["high"] >= 1:
        return "High"
    if counts["medium"] >= 3:
        return "High"
    if counts["medium"] >= 1:
        return "Medium"
    if counts["low"] >= 1 or counts["info"] >= 1:
        return "Low"
    return "None"


def calculate_risk(findings):

    counts = {sev: 0 for sev in SEVERITY_ORDER}

    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1

    # Diminishing returns per severity tier: weight * sqrt(count) instead
    # of weight * count. First finding of a severity = full weight; each
    # additional one of the SAME severity adds progressively less.
    score = 0.0

    for severity, count in counts.items():
        if count <= 0:
            continue
        score += SEVERITY_SCORE[severity] * math.sqrt(count)

    score = round(score, 1)

    score_level = _score_based_level(score)
    floor_level = _severity_floor_level(counts)

    # Take whichever level is worse - a single critical finding can't get
    # diluted into "Medium" just because the additive formula says so.
    level = max(score_level, floor_level, key=lambda lvl: LEVEL_RANK[lvl])

    return {
        "score": score,
        "level": level,
        "counts": counts
    }