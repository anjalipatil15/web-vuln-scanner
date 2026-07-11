SEVERITY_SCORE = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
    "info": 1
}

# Order used anywhere findings need to be sorted "worst first"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def calculate_risk(findings):

    score = 0
    counts = {sev: 0 for sev in SEVERITY_ORDER}

    for finding in findings:
        severity = finding.severity.lower()

        score += SEVERITY_SCORE.get(
            severity,
            0
        )

        if severity in counts:
            counts[severity] += 1


    if score >= 20:
        level = "Critical"

    elif score >= 10:
        level = "High"

    elif score >= 5:
        level = "Medium"

    elif score > 0:
        level = "Low"

    else:
        level = "None"


    return {
        "score": score,
        "level": level,
        "counts": counts
    }