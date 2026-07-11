SEVERITY_SCORE = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
    "info": 1
}


def calculate_risk(findings):

    score = 0

    for finding in findings:
        severity = finding.severity.lower()

        score += SEVERITY_SCORE.get(
            severity,
            0
        )


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
        "level": level
    }