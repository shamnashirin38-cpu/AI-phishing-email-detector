"""
Unit tests for the Risk Scoring Engine.
Tests boundaries, categorization, hybrid calculations, offline normalization, and confidence decoupling.
"""

from app.utils.scoring import (
    get_risk_category,
    determine_verdict,
    compute_final_risk,
    generate_recommended_actions
)


def test_risk_category_boundaries():
    """Tests exact score boundaries for Low, Medium, High, and Critical categories."""
    # 0 - 24: Low
    assert get_risk_category(0)[0] == "Low"
    assert get_risk_category(24)[0] == "Low"

    # 25 - 49: Medium
    assert get_risk_category(25)[0] == "Medium"
    assert get_risk_category(49)[0] == "Medium"

    # 50 - 74: High
    assert get_risk_category(50)[0] == "High"
    assert get_risk_category(74)[0] == "High"

    # 75 - 100: Critical
    assert get_risk_category(75)[0] == "Critical"
    assert get_risk_category(100)[0] == "Critical"


def test_determine_verdict():
    """Tests verdict categorization based on score and critical indicators."""
    assert determine_verdict(10) == "Safe"
    assert determine_verdict(35) == "Suspicious"
    assert determine_verdict(55) == "Phishing"
    assert determine_verdict(85) == "Phishing"

    # Critical indicator elevates verdict even at lower scores
    crit_ind = [{"severity": "critical"}]
    assert determine_verdict(38, crit_ind) == "Phishing"


def test_hybrid_scoring_calculation():
    """Tests combination of rule engine (0-60) and AI model (0-40) into 0-100 scale."""
    rule_result = {
        "rule_score": 40,
        "indicators": [{"name": "Suspicious URL", "category": "urls", "severity": "high"}]
    }
    ai_result = {
        "available": True,
        "ai_risk_score": 35,
        "confidence": 0.95,
        "reasoning": "High confidence phishing intent.",
        "recommended_actions": ["Do not click links"]
    }

    final = compute_final_risk(rule_result, ai_result)
    assert final["final_risk_score"] == 75
    assert final["risk_category"] == "Critical"
    assert final["verdict"] == "Phishing"
    assert final["scoring_mode"] == "hybrid"
    assert final["rule_score"] == 40
    assert final["ai_score"] == 35


def test_offline_ai_fallback_normalization():
    """Verifies that when AI is offline, rule score is normalized safely without crashing."""
    rule_result = {
        "rule_score": 30,  # 30 / 60 points
        "indicators": [{"name": "Urgency Deadline", "category": "urgency", "severity": "medium"}]
    }
    ai_result = {
        "available": False,
        "status": "offline",
        "error": "Connection refused"
    }

    final = compute_final_risk(rule_result, ai_result)
    # 30/60 is 50% -> 50 / 100
    assert final["final_risk_score"] == 50
    assert final["scoring_mode"] == "rule_only"
    assert final["ai_available"] is False
    assert final["ai_score"] is None
    assert "Rule-Only Assessment" in final["scoring_note"]


def test_confidence_vs_risk_score_independence():
    """
    Verifies that AI confidence and Risk score are completely distinct.
    A safe email can have 98% confidence with 0 risk score.
    """
    rule_result = {"rule_score": 0, "indicators": []}
    ai_result = {
        "available": True,
        "ai_risk_score": 0,
        "confidence": 0.98,
        "reasoning": "Completely benign message.",
        "recommended_actions": []
    }

    final = compute_final_risk(rule_result, ai_result)
    assert final["final_risk_score"] == 0
    assert final["ai_confidence"] == 0.98
    assert final["verdict"] == "Safe"
    assert "confidence_vs_risk_explanation" in final
