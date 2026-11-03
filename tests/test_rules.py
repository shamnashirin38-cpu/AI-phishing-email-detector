"""
Unit tests for the Rule-Based Phishing Detection Engine.
Verifies all 5 core threat vectors, deduplication, point capping, and benign email handling.
"""

from app.rules import RuleEngine, defang_url, extract_sender_parts


def test_defang_url():
    """Verifies that malicious URLs are properly disarmed."""
    raw = "http://192.168.1.1/login"
    defanged = defang_url(raw)
    assert defanged == "hxxp://192[.]168[.]1[.]1/login"
    assert "http://" not in defanged


def test_extract_sender_parts():
    """Verifies parsing of sender display names, local parts, and domains."""
    display, local, domain = extract_sender_parts('PayPal Security <alerts@support-paypa1.xyz>')
    assert display == "PayPal Security"
    assert local == "alerts"
    assert domain == "support-paypa1.xyz"

    # Bare email
    d2, l2, dom2 = extract_sender_parts("admin@evil.com")
    assert dom2 == "evil.com"


def test_indicator_suspicious_urls():
    """Tests detection of IP hosts, shortened URLs, risky TLDs, and brand spoofing."""
    engine = RuleEngine()

    # 1. IP Host
    res = engine.analyze(
        sender="service@normal.com",
        subject="Notice",
        body="Please verify at http://192.168.1.100/verify"
    )
    assert any(ind["id"] == "URL_IP_HOST" for ind in res["indicators"])
    assert res["category_scores"]["urls"] >= 15

    # 2. URL Shortener
    res_short = engine.analyze(
        sender="service@normal.com",
        subject="Notice",
        body="Track your package at http://bit.ly/secret-deal"
    )
    assert any(ind["id"] == "URL_SHORTENER" for ind in res_short["indicators"])

    # 3. Risky TLD
    res_tld = engine.analyze(
        sender="service@normal.com",
        subject="Notice",
        body="Visit our website at http://secure-update.xyz/login"
    )
    assert any(ind["id"] == "URL_RISKY_TLD" for ind in res_tld["indicators"])

    # 4. Brand Spoofing in Host
    res_brand = engine.analyze(
        sender="service@normal.com",
        subject="Notice",
        body="Login via http://paypal.com.account-update.xyz/login"
    )
    assert any(ind["id"] == "URL_BRAND_SPOOF" for ind in res_brand["indicators"])


def test_indicator_urgency_and_threats():
    """Tests detection of account suspension threats and artificial ultimatums."""
    engine = RuleEngine()

    res = engine.analyze(
        sender="support@company.com",
        subject="URGENT: Action Required within 24 hours",
        body="Your account will be permanently closed unless you act now."
    )
    assert any(ind["id"] == "URG_SUSPENSION_THREAT" for ind in res["indicators"])
    assert res["category_scores"]["urgency"] > 0


def test_indicator_credentials_and_otp():
    """Tests detection of password and one-time password (OTP) solicitation."""
    engine = RuleEngine()

    # OTP Request
    res_otp = engine.analyze(
        sender="security@auth.com",
        subject="Your Code",
        body="Please reply with your one-time password and 2FA code."
    )
    assert any(ind["id"] == "CRED_OTP_REQUEST" for ind in res_otp["indicators"])
    assert res_otp["category_scores"]["credentials"] >= 15

    # Password Request
    res_pwd = engine.analyze(
        sender="security@auth.com",
        subject="Password Check",
        body="Please enter your current password to confirm your identity."
    )
    assert any(ind["id"] == "CRED_PASSWORD_REQUEST" for ind in res_pwd["indicators"])


def test_indicator_financial_and_payment():
    """Tests detection of cryptocurrency demands, gift cards, and wire transfers."""
    engine = RuleEngine()

    res_crypto = engine.analyze(
        sender="billing@invoice.com",
        subject="Overdue",
        body="Send payment to our bitcoin wallet address or buy iTunes gift cards immediately."
    )
    assert any(ind["id"] == "FIN_CRYPTO_GIFT_CARD" for ind in res_crypto["indicators"])
    assert res_crypto["category_scores"]["financial"] >= 10

    res_wire = engine.analyze(
        sender="ceo@corp.com",
        subject="Quick Request",
        body="Please initiate a wire transfer for the overdue invoice."
    )
    assert any(ind["id"] == "FIN_WIRE_INVOICE_FRAUD" for ind in res_wire["indicators"])


def test_indicator_sender_spoofing():
    """Tests detection of display name impersonation and lookalike domains."""
    engine = RuleEngine()

    # Display name says PayPal, but domain is gmail
    res_spoof = engine.analyze(
        sender="PayPal Security <fraudster123@gmail.com>",
        subject="Security Notice",
        body="Please review your account."
    )
    assert any(ind["id"] == "SND_DISPLAY_NAME_SPOOF" for ind in res_spoof["indicators"])
    assert res_spoof["category_scores"]["sender"] >= 10

    # Typosquatting (paypa1)
    res_typo = engine.analyze(
        sender="support@paypa1.com",
        subject="Notice",
        body="Hello customer."
    )
    assert any(ind["id"] == "SND_TYPOSQUATTING" for ind in res_typo["indicators"])


def test_deduplication_prevents_duplicate_counting():
    """Ensures repeated instances of the exact same signal do not inflate points."""
    engine = RuleEngine()

    # Repeat same phrase 5 times
    repeated_body = "within 24 hours " * 5
    res = engine.analyze(sender="a@b.com", subject="Notice", body=repeated_body)
    urgency_indicators = [ind for ind in res["indicators"] if ind["category"] == "urgency"]
    # Should produce at most 1 deadline indicator, not 5
    assert len(urgency_indicators) <= 1
    assert res["category_scores"]["urgency"] <= 10


def test_rule_score_maximum_cap():
    """Verifies that the total rule score never exceeds 60 points."""
    engine = RuleEngine()

    # Overwhelming email triggering all 5 indicators simultaneously
    res = engine.analyze(
        sender="PayPal Support <hacker@paypa1.xyz>",
        subject="URGENT: Account Suspended within 24 hours",
        body="""Your PayPal account has been permanently closed.
        Enter your password and verify your OTP at http://192.168.1.1/login.php
        Also remit payment to our bitcoin wallet."""
    )
    assert res["rule_score"] <= 60


def test_legitimate_clean_email():
    """Verifies that a legitimate business/academic email triggers zero indicators."""
    engine = RuleEngine()

    res = engine.analyze(
        sender="Prof. Alan Turing <alan@cambridge.ac.uk>",
        subject="Lecture notes for Wednesday's session",
        body="Hi class, please read chapter 4 of the textbook before Wednesday's lecture. Best regards, Alan."
    )
    assert res["rule_score"] == 0
    assert len(res["indicators"]) == 0
