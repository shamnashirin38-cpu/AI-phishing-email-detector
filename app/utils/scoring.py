"""
Risk Scoring System for AI Phishing Email Detector.

Scoring Formula:
- Rule-Based Checks: 0 to 60 points
  * URLs: up to 15 pts
  * Urgency / Threats: up to 10 pts
  * Password / OTP / 2FA: up to 15 pts
  * Financial / Wire / Crypto: up to 10 pts
  * Sender / Domain Mismatch: up to 10 pts
- AI Model Assessment: 0 to 40 points
- Total Score: 0 to 100 points

Risk Categories:
- 0 to 24: Low (Minimal or no threat signals detected)
- 25 to 49: Medium (Anomalies or low-confidence indicators present)
- 50 to 74: High (Significant phishing indicators detected)
- 75 to 100: Critical (Definite malicious campaign, credential harvesting, or active fraud)

Also provides clear distinction between Risk Score vs. AI Confidence.
"""

ADVISORY_WARNING = (
    "Advisory Notice: This assessment is an automated screening tool intended for guidance "
    "and educational threat analysis. Results are probabilistic and not guaranteed. "
    "Always exercise caution and verify sensitive requests via official, out-of-band channels."
)

CONFIDENCE_VS_RISK_EXPLANATION = {
    "risk_score_definition": (
        "Risk Score (0-100) measures how dangerous and malicious the email is based on detected "
        "attack indicators (e.g. deceptive links, urgency, credential harvesting)."
    ),
    "confidence_definition": (
        "AI Confidence (0%-100%) measures how certain the AI model is about its classification, "
        "regardless of whether the email is benign or malicious. For example, a clearly safe email "
        "can have 98% confidence with a risk score of 0."
    )
}


def get_risk_category(score: int) -> tuple[str, str, str]:
    """
    Returns (category_name, badge_css_class, description) based on score.
    0-24: Low
    25-49: Medium
    50-74: High
    75-100: Critical
    """
    if score <= 24:
        return (
            "Low",
            "badge-low",
            "Minimal threat indicators detected. The email appears consistent with legitimate correspondence."
        )
    elif score <= 49:
        return (
            "Medium",
            "badge-medium",
            "Caution advised. Contains ambiguous signals, marketing trackers, or mild urgency."
        )
    elif score <= 74:
        return (
            "High",
            "badge-high",
            "High risk of phishing. Multiple deceptive patterns or brand impersonation detected."
        )
    else:
        return (
            "Critical",
            "badge-critical",
            "Critical security threat! Direct credential harvesting, coercive threats, or malicious URLs detected."
        )


def determine_verdict(total_score: int, rule_indicators: list = None) -> str:
    """
    Determines the categorical verdict: 'Phishing', 'Suspicious', or 'Safe'.
    """
    rule_indicators = rule_indicators or []
    has_critical_indicator = any(ind.get("severity") == "critical" for ind in rule_indicators)

    if total_score >= 50 or (has_critical_indicator and total_score >= 35):
        return "Phishing"
    elif total_score >= 25:
        return "Suspicious"
    else:
        return "Safe"


def generate_recommended_actions(rule_indicators: list, ai_actions: list = None, verdict: str = "Safe") -> list[str]:
    """
    Aggregates and prioritizes security recommendations based on specific threats detected.
    """
    actions = []
    category_set = {ind.get("category") for ind in (rule_indicators or [])}

    if "credentials" in category_set:
        actions.append("NEVER share passwords, 2FA codes, or OTPs. Legitimate providers will never ask for them via email.")
        actions.append("If you already submitted credentials, change your password immediately and revoke active sessions.")

    if "urls" in category_set:
        actions.append("Do NOT click any links in this email. If you must inspect them, copy the link and analyze in a sandbox.")
        actions.append("Bookmark official organization portals rather than navigating through email links.")

    if "financial" in category_set:
        actions.append("Verify invoice or payment details directly by calling the known official accounting representative.")
        actions.append("Never purchase gift cards or wire money based solely on email instructions.")

    if "sender" in category_set:
        actions.append("Inspect the actual email domain header carefully for subtle spelling changes or free webmail addresses.")

    # Incorporate AI suggestions if valid
    if ai_actions and isinstance(ai_actions, list):
        for act in ai_actions:
            act_str = str(act).strip()
            if act_str and act_str not in actions and len(act_str) > 5:
                actions.append(act_str)

    # Default fallback actions if none triggered
    if not actions:
        if verdict == "Safe":
            actions.append("No immediate threats found. Standard email hygiene is still recommended.")
            actions.append("Always double-check recipient address before replying with confidential information.")
        else:
            actions.append("Report this email to your organization's IT / Cybersecurity security operations team.")
            actions.append("Mark the email as Spam/Phishing in your email client to update gateway filters.")

    return actions[:5]  # Keep top 5 most actionable


def compute_final_risk(rule_analysis: dict, ai_analysis: dict) -> dict:
    """
    Combines rule engine score (0-60) and AI model score (0-40) into a final unified assessment.
    Gracefully adapts when AI is offline by normalizing rule scores.
    """
    rule_score = rule_analysis.get("rule_score", 0)
    rule_indicators = rule_analysis.get("indicators", [])

    ai_available = ai_analysis.get("available", False)
    ai_raw_score = ai_analysis.get("ai_risk_score")

    if ai_available and ai_raw_score is not None:
        ai_score = max(0, min(40, int(ai_raw_score)))
        total_score = min(100, max(0, rule_score + ai_score))
        scoring_mode = "hybrid"
        scoring_note = (
            f"Hybrid Assessment: Rule-based checks contributed {rule_score}/60 points; "
            f"Ollama AI ({ai_analysis.get('model', 'local')}) contributed {ai_score}/40 points."
        )
    else:
        # AI is offline or unavailable: normalize rule score (0-60) to 100-point scale
        ai_score = None
        total_score = min(100, round((rule_score / 60.0) * 100))
        scoring_mode = "rule_only"
        scoring_note = (
            f"Rule-Only Assessment: Local AI was offline/unavailable. Score is calculated by normalizing "
            f"rule detections ({rule_score}/60) to a 100-point scale."
        )

    risk_category, badge_class, category_description = get_risk_category(total_score)
    verdict = determine_verdict(total_score, rule_indicators)
    recommendations = generate_recommended_actions(
        rule_indicators,
        ai_analysis.get("recommended_actions"),
        verdict
    )

    return {
        "final_risk_score": total_score,
        "risk_category": risk_category,
        "risk_category_badge": badge_class,
        "risk_category_description": category_description,
        "verdict": verdict,
        "scoring_mode": scoring_mode,
        "scoring_note": scoring_note,
        "rule_score": rule_score,
        "max_rule_score": 60,
        "ai_score": ai_score,
        "max_ai_score": 40,
        "ai_confidence": ai_analysis.get("confidence"),
        "ai_available": ai_available,
        "ai_status": ai_analysis.get("status", "offline"),
        "ai_model": ai_analysis.get("model", "llama3.2:3b"),
        "ai_reasoning": ai_analysis.get("reasoning", ""),
        "indicators": rule_indicators,
        "recommended_actions": recommendations,
        "advisory_warning": ADVISORY_WARNING,
        "confidence_vs_risk_explanation": CONFIDENCE_VS_RISK_EXPLANATION
    }
