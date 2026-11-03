"""
Report Exporter Utility.

Generates downloadable reports in:
- Plaintext TXT (Cybersecurity Incident Triage Report format)
- Structured JSON format
"""

import json


def export_scan_to_txt(scan: dict) -> str:
    """Formats an email scan report into a clean plaintext security report."""
    border = "=" * 70
    sub_border = "-" * 70

    indicators = scan.get("indicators", [])
    if isinstance(indicators, str):
        try:
            indicators = json.loads(indicators)
        except Exception:
            indicators = []

    ai_analysis = scan.get("ai_analysis", {})
    if isinstance(ai_analysis, str):
        try:
            ai_analysis = json.loads(ai_analysis)
        except Exception:
            ai_analysis = {}

    recommendations = scan.get("recommended_actions", [])
    if isinstance(recommendations, str):
        try:
            recommendations = json.loads(recommendations)
        except Exception:
            recommendations = []

    lines = [
        border,
        "   AI-POWERED PHISHING EMAIL DETECTION SYSTEM - THREAT REPORT",
        border,
        f"Report ID        : #{scan.get('id', 'N/A')}",
        f"Generated On     : {scan.get('timestamp', 'N/A')}",
        f"Verdict          : {scan.get('verdict', 'Unknown').upper()}",
        f"Risk Score       : {scan.get('risk_score', 0)} / 100",
        f"Risk Category    : {scan.get('risk_category', 'Unknown').upper()}",
        sub_border,
        "EMAIL DETAILS",
        sub_border,
        f"Sender           : {scan.get('sender', '(Not provided)')}",
        f"Subject          : {scan.get('subject', '(No subject)')}",
        f"Snippet          : {scan.get('body_snippet', '')[:120]}...",
        sub_border,
        "SCORE BREAKDOWN",
        sub_border,
        f"Rule Engine Score: {scan.get('rule_score', 0)} / 60 points",
        f"AI Model Score   : {scan.get('ai_score', 'N/A')} / 40 points (Status: {scan.get('ai_status', 'offline')})",
        sub_border,
        f"RULE-BASED THREAT INDICATORS DETECTED ({len(indicators)})",
        sub_border
    ]

    if not indicators:
        lines.append("  [+] No overt rule-based phishing patterns detected.")
    else:
        for idx, ind in enumerate(indicators, 1):
            lines.append(f"  {idx}. [{ind.get('severity', 'info').upper()}] {ind.get('name', 'Indicator')}")
            lines.append(f"     Description : {ind.get('description', '')}")
            evidence = ind.get("evidence", [])
            if evidence:
                lines.append(f"     Evidence    : {', '.join(evidence)}")
            lines.append("")

    lines.extend([
        sub_border,
        "AI MODEL REASONING & CONFIDENCE",
        sub_border,
        f"AI Status        : {scan.get('ai_status', 'offline')}",
        f"AI Reasoning     : {ai_analysis.get('reasoning', scan.get('ai_reasoning', 'Not available'))}",
        f"AI Confidence    : {int((ai_analysis.get('confidence') or 0) * 100)}% (analytical certainty)",
        sub_border,
        "RECOMMENDED DEFENSIVE ACTIONS",
        sub_border
    ])

    if not recommendations:
        lines.append("  - Maintain standard email security vigilance.")
    else:
        for act in recommendations:
            lines.append(f"  [!] {act}")

    lines.extend([
        sub_border,
        "DISCLAIMER",
        sub_border,
        "This automated report is advisory and produced for cybersecurity triage.",
        "Assessments are probabilistic and should be verified alongside SPF/DKIM/DMARC",
        "and direct out-of-band communication with the purported sender.",
        border
    ])

    return "\n".join(lines)


def export_scan_to_json(scan: dict) -> str:
    """Formats an email scan report into formatted JSON string."""
    clean_dict = dict(scan)

    for field in ["indicators", "ai_analysis", "recommended_actions"]:
        if isinstance(clean_dict.get(field), str):
            try:
                clean_dict[field] = json.loads(clean_dict[field])
            except Exception:
                pass

    return json.dumps(clean_dict, indent=2, ensure_ascii=False)
