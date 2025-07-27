def project_severity(vulns: list) -> str:
    """Return severity based on the highest CVSS score."""
    if not vulns:
        return "None"

    scores = []
    for v in vulns:
        score = v.get("score", 0)
        if isinstance(score, str):
            try:
                score = float(score)
            except ValueError:
                score = 0
        scores.append(score or 0)

    max_score = max(scores)

    if max_score >= 7.0:
        return "High"
    elif max_score >= 5.0:
        return "Medium"
    elif max_score > 0:
        return "Low"
    return "None"
