"""
Rule-Based Phishing Detection Engine.

Analyzes an incoming email (sender, subject, body) against 5 core phishing indicators:
1. Suspicious URLs (IP host, shorteners, risky TLDs, deceptive subdomains/paths) [Max 15 pts]
2. Urgent or threatening language (account suspension, legal action, 24h deadline) [Max 10 pts]
3. Password or OTP requests (credential harvesting, 2FA codes, PIN prompts) [Max 15 pts]
4. Payment or financial requests (crypto wallets, gift cards, overdue invoices, wire transfer) [Max 10 pts]
5. Suspicious sender email or domain mismatch (brand spoofing via free mail, typosquatting) [Max 10 pts]

Total Maximum Rule Score: 60 points.
Features:
- Evidence extraction with deduplication (no repeat counting for identical signals)
- Robust URL parsing and sender address extraction
- Defensive link sanitization (defangs URLs in reports)
"""

import re
from urllib.parse import urlparse
from app.rules.patterns import (
    URL_REGEX,
    DEFANGED_URL_REGEX,
    IP_HOST_REGEX,
    URL_SHORTENERS,
    RISKY_TLDS,
    SUSPICIOUS_URL_KEYWORDS,
    TARGETED_BRANDS,
    URGENT_PHRASES,
    CREDENTIAL_PHRASES,
    FINANCIAL_PHRASES,
    FREE_MAIL_PROVIDERS,
    TYPOSQUAT_PATTERNS,
)


def defang_url(url: str) -> str:
    """Disarms a malicious URL so it cannot be accidentally clicked."""
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def extract_sender_parts(sender_str: str) -> tuple[str, str, str]:
    """
    Extracts display name, local part, and domain from a sender string.
    Example: 'PayPal Security <alerts@support-paypa1.xyz>'
    Returns: ('PayPal Security', 'alerts', 'support-paypa1.xyz')
    """
    if not sender_str:
        return "", "", ""

    sender_clean = sender_str.strip()
    match = re.match(r'^(?:["\']?([^"\'<>]*)["\']?\s*)?(?:<([^>]+)>)?$', sender_clean)
    
    display_name = ""
    email_addr = ""

    if match:
        name_group, email_group = match.groups()
        if email_group:
            display_name = (name_group or "").strip()
            email_addr = email_group.strip()
        elif "@" in (name_group or ""):
            email_addr = (name_group or "").strip()
        else:
            display_name = (name_group or "").strip()
    else:
        # Fallback search for email pattern
        email_search = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender_clean)
        if email_search:
            email_addr = email_search.group(0)
            display_name = sender_clean.replace(email_addr, "").replace("<", "").replace(">", "").strip()

    local_part, _, domain = email_addr.partition("@")
    return display_name, local_part.lower(), domain.lower()


class RuleEngine:
    """Engine for rule-based phishing indicators evaluation."""

    def __init__(self):
        self.max_url_pts = 15
        self.max_urgency_pts = 10
        self.max_cred_pts = 15
        self.max_fin_pts = 10
        self.max_sender_pts = 10

    def analyze(self, sender: str, subject: str, body: str) -> dict:
        """
        Runs all rule-based checks across the email fields.
        Returns a structured dictionary with rule score, indicators, and evidence.
        """
        subject = subject or ""
        body = body or ""
        sender = sender or ""
        combined_text = f"{subject}\n{body}"

        indicators = []
        category_scores = {
            "urls": 0,
            "urgency": 0,
            "credentials": 0,
            "financial": 0,
            "sender": 0,
        }

        # 1. Analyze URLs
        url_findings, url_pts = self._analyze_urls(body)
        if url_findings:
            category_scores["urls"] = min(self.max_url_pts, url_pts)
            indicators.extend(url_findings)

        # 2. Analyze Urgent / Threatening Language
        urgency_findings, urgency_pts = self._analyze_urgency(combined_text)
        if urgency_findings:
            category_scores["urgency"] = min(self.max_urgency_pts, urgency_pts)
            indicators.extend(urgency_findings)

        # 3. Analyze Password / OTP Requests
        cred_findings, cred_pts = self._analyze_credentials(combined_text)
        if cred_findings:
            category_scores["credentials"] = min(self.max_cred_pts, cred_pts)
            indicators.extend(cred_findings)

        # 4. Analyze Payment / Financial Requests
        fin_findings, fin_pts = self._analyze_financial(combined_text)
        if fin_findings:
            category_scores["financial"] = min(self.max_fin_pts, fin_pts)
            indicators.extend(fin_findings)

        # 5. Analyze Sender / Domain Mismatch
        sender_findings, sender_pts = self._analyze_sender(sender, body)
        if sender_findings:
            category_scores["sender"] = min(self.max_sender_pts, sender_pts)
            indicators.extend(sender_findings)

        # Total rule score capped at 60
        total_rule_score = sum(category_scores.values())
        total_rule_score = min(60, total_rule_score)

        return {
            "rule_score": total_rule_score,
            "max_possible_rule_score": 60,
            "category_scores": category_scores,
            "indicators": indicators,
            "total_indicators_found": len(indicators),
            "summary": self._generate_summary(category_scores, total_rule_score)
        }

    def _analyze_urls(self, text: str) -> tuple[list, int]:
        """Detects suspicious URLs, IP hosts, URL shorteners, risky TLDs, and deceptive paths."""
        findings = []
        raw_urls = set(URL_REGEX.findall(text) + DEFANGED_URL_REGEX.findall(text))
        if not raw_urls:
            return findings, 0

        score = 0
        ip_hosts = set()
        shortened_urls = set()
        risky_tld_urls = set()
        brand_spoof_urls = set()
        auth_keyword_urls = set()
        credential_trick_urls = set()

        for url in raw_urls:
            # Check IP address as host
            if IP_HOST_REGEX.search(url):
                ip_hosts.add(defang_url(url))

            # Normalize for parsing
            parsed_candidate = url
            if not parsed_candidate.startswith(("http://", "https://")):
                parsed_candidate = "http://" + parsed_candidate
            
            try:
                parsed = urlparse(parsed_candidate)
                hostname = (parsed.hostname or "").lower()
                path = (parsed.path or "").lower()
                query = (parsed.query or "").lower()
            except Exception:
                continue

            # Check @ symbol in URL (credential injection trick)
            if "@" in parsed.netloc:
                credential_trick_urls.add(defang_url(url))

            # Check URL shorteners
            if hostname in URL_SHORTENERS:
                shortened_urls.add(defang_url(url))

            # Check Risky TLDs
            for tld in RISKY_TLDS:
                if hostname.endswith(tld):
                    risky_tld_urls.add(defang_url(url))
                    break

            # Check Brand spoofing in domain / subdomains (e.g. paypal.com.evil.xyz)
            for brand in TARGETED_BRANDS:
                if brand in hostname:
                    # Legitimate if it's the exact domain (e.g. paypal.com)
                    official_domains = (f"{brand}.com", f"www.{brand}.com", f"mail.{brand}.com")
                    if not hostname.endswith(official_domains):
                        brand_spoof_urls.add(defang_url(url))
                        break

            # Check deceptive auth keywords in path
            for kw in SUSPICIOUS_URL_KEYWORDS:
                if kw in path or kw in query:
                    auth_keyword_urls.add(defang_url(url))
                    break

        if ip_hosts:
            score += 15
            findings.append({
                "id": "URL_IP_HOST",
                "category": "urls",
                "name": "Direct IP Address Used in URL",
                "severity": "critical",
                "points": 15,
                "description": "Legitimate organizations use registered domain names. IP address hosts bypass domain verification and often host phishing kits.",
                "evidence": list(ip_hosts)
            })

        if brand_spoof_urls:
            score += 12
            findings.append({
                "id": "URL_BRAND_SPOOF",
                "category": "urls",
                "name": "Targeted Brand Name Spoofed in Link",
                "severity": "critical",
                "points": 12,
                "description": "A well-known brand name appears in an unofficial third-party domain or subdomain.",
                "evidence": list(brand_spoof_urls)
            })

        if credential_trick_urls:
            score += 10
            findings.append({
                "id": "URL_CREDENTIAL_TRICK",
                "category": "urls",
                "name": "Deceptive Embedded @ Symbol in Link",
                "severity": "high",
                "points": 10,
                "description": "The URL uses the '@' character before the host, tricking users into seeing a legitimate domain while routing to an attacker server.",
                "evidence": list(credential_trick_urls)
            })

        if shortened_urls:
            score += 8
            findings.append({
                "id": "URL_SHORTENER",
                "category": "urls",
                "name": "URL Shortener Detected",
                "severity": "medium",
                "points": 8,
                "description": "URL shorteners conceal the true destination server to evade gateway filters and user scrutiny.",
                "evidence": list(shortened_urls)
            })

        if risky_tld_urls:
            score += 8
            findings.append({
                "id": "URL_RISKY_TLD",
                "category": "urls",
                "name": "Suspicious / High-Risk TLD in Link",
                "severity": "medium",
                "points": 8,
                "description": "The destination link uses a top-level domain frequently associated with automated phishing and spam campaigns.",
                "evidence": list(risky_tld_urls)
            })

        if auth_keyword_urls and not (brand_spoof_urls or ip_hosts):
            score += 5
            findings.append({
                "id": "URL_AUTH_KEYWORD",
                "category": "urls",
                "name": "Authentication Keywords in URL Path",
                "severity": "medium",
                "points": 5,
                "description": "The link points directly to an account login or verification page, a typical credential harvesting pattern.",
                "evidence": list(auth_keyword_urls)[:3]
            })

        return findings, score

    def _analyze_urgency(self, text: str) -> tuple[list, int]:
        """Detects urgent deadlines, threatening language, and scare tactics."""
        findings = []
        score = 0
        matched_threats = set()
        matched_deadlines = set()

        for pattern in URGENT_PHRASES:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for m in matches:
                matched_phrase = m.group(0).strip()
                # Categorize into threat vs deadline
                threat_keywords = ["suspend", "terminat", "lock", "legal", "arrest", "breach", "warning", "notice", "law", "close", "disable", "delete", "permanent"]
                if any(w in matched_phrase.lower() for w in threat_keywords):
                    matched_threats.add(matched_phrase)
                else:
                    matched_deadlines.add(matched_phrase)

        if matched_threats:
            score += 10
            findings.append({
                "id": "URG_SUSPENSION_THREAT",
                "category": "urgency",
                "name": "Coercive / Threatening Language",
                "severity": "high",
                "points": 10,
                "description": "Email threatens account termination, suspension, legal consequences, or simulated security breaches to panic the victim.",
                "evidence": sorted(list(matched_threats))
            })

        if matched_deadlines:
            deadline_pts = 8 if not matched_threats else 0  # avoid double counting urgency
            if not matched_threats:
                score += deadline_pts
            findings.append({
                "id": "URG_STRICT_DEADLINE",
                "category": "urgency",
                "name": "Artificial Urgency & Time Pressure",
                "severity": "medium",
                "points": 8,
                "description": "Email creates artificial urgency (e.g. 24-48 hour ultimatum) to compel the recipient into bypassing normal verification procedures.",
                "evidence": sorted(list(matched_deadlines))
            })

        return findings, score

    def _analyze_credentials(self, text: str) -> tuple[list, int]:
        """Detects attempts to harvest passwords, OTPs, 2FA codes, or security PINs."""
        findings = []
        score = 0
        matched_creds = set()
        matched_2fa = set()

        for pattern in CREDENTIAL_PHRASES:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for m in matches:
                matched_phrase = m.group(0).strip()
                if any(w in matched_phrase.lower() for w in ["otp", "one-time", "2fa", "two-factor", "pin", "verification code", "security code"]):
                    matched_2fa.add(matched_phrase)
                else:
                    matched_creds.add(matched_phrase)

        if matched_2fa:
            score += 15
            findings.append({
                "id": "CRED_OTP_REQUEST",
                "category": "credentials",
                "name": "One-Time Password (OTP) / 2FA Interception",
                "severity": "critical",
                "points": 15,
                "description": "Email attempts to solicit a one-time verification code or multi-factor authentication token. Legitimate providers never ask for OTPs via email.",
                "evidence": sorted(list(matched_2fa))
            })

        if matched_creds:
            cred_pts = 12 if not matched_2fa else 0  # avoid double penalty
            if not matched_2fa:
                score += cred_pts
            findings.append({
                "id": "CRED_PASSWORD_REQUEST",
                "category": "credentials",
                "name": "Password / Credential Verification Request",
                "severity": "critical",
                "points": 12,
                "description": "Direct request to enter, verify, or reset account passwords or credentials.",
                "evidence": sorted(list(matched_creds))
            })

        return findings, score

    def _analyze_financial(self, text: str) -> tuple[list, int]:
        """Detects fraudulent payment mechanisms: cryptocurrency, gift cards, wire transfer, invoice fraud."""
        findings = []
        score = 0
        matched_crypto_gift = set()
        matched_wire_invoice = set()

        for pattern in FINANCIAL_PHRASES:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for m in matches:
                matched_phrase = m.group(0).strip()
                if any(w in matched_phrase.lower() for w in ["bitcoin", "btc", "ethereum", "eth", "crypto", "wallet", "gift card", "itunes", "steam", "lottery", "prize"]):
                    matched_crypto_gift.add(matched_phrase)
                else:
                    matched_wire_invoice.add(matched_phrase)

        if matched_crypto_gift:
            score += 10
            findings.append({
                "id": "FIN_CRYPTO_GIFT_CARD",
                "category": "financial",
                "name": "Cryptocurrency or Untraceable Gift Card Demand",
                "severity": "critical",
                "points": 10,
                "description": "Demands payment or prize redemption via cryptocurrency wallets or gift cards, a hallmark of irreversible fraud.",
                "evidence": sorted(list(matched_crypto_gift))
            })

        if matched_wire_invoice:
            wire_pts = 8 if not matched_crypto_gift else 0
            if not matched_crypto_gift:
                score += wire_pts
            findings.append({
                "id": "FIN_WIRE_INVOICE_FRAUD",
                "category": "financial",
                "name": "Urgent Wire Transfer / Unsolicited Invoice",
                "severity": "high",
                "points": 8,
                "description": "Solicits bank wire transfer, modified payroll deposit details, or urgent settlement of an overdue invoice.",
                "evidence": sorted(list(matched_wire_invoice))
            })

        return findings, score

    def _analyze_sender(self, sender: str, body: str) -> tuple[list, int]:
        """Detects sender address anomalies, display name spoofing, and brand typosquatting."""
        findings = []
        score = 0
        if not sender:
            return findings, 0

        display_name, local_part, domain = extract_sender_parts(sender)

        # 1. Missing or invalid domain
        if not domain or "." not in domain:
            score += 10
            findings.append({
                "id": "SND_INVALID_FORMAT",
                "category": "sender",
                "name": "Invalid or Missing Sender Domain",
                "severity": "high",
                "points": 10,
                "description": "The sender header lacks a valid, resolvable domain address.",
                "evidence": [sender]
            })
            return findings, score

        # 2. Display Name Spoofing: Brand in Display Name, but domain is free webmail or unrelated
        for brand in TARGETED_BRANDS:
            if brand in display_name.lower():
                # Legitimate if domain is actually the brand's domain
                if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                    score += 10
                    findings.append({
                        "id": "SND_DISPLAY_NAME_SPOOF",
                        "category": "sender",
                        "name": f"Display Name Impersonation ({brand.capitalize()})",
                        "severity": "critical",
                        "points": 10,
                        "description": f"The sender display name claims to represent '{brand.capitalize()}', but the actual sending domain is '{domain}'.",
                        "evidence": [f"Display: '{display_name}' vs Actual Domain: '{domain}'"]
                    })
                    break

        # 3. Typosquatting / Lookalike Brand Domain
        for regex_pattern, brand_target in TYPOSQUAT_PATTERNS:
            if re.search(regex_pattern, domain) and not (domain == f"{brand_target}.com" or domain.endswith(f".{brand_target}.com")):
                score += 10
                findings.append({
                    "id": "SND_TYPOSQUATTING",
                    "category": "sender",
                    "name": f"Lookalike Domain / Typosquatting ({brand_target.capitalize()})",
                    "severity": "critical",
                    "points": 10,
                    "description": f"The sending domain '{domain}' mimics the legitimate brand '{brand_target.capitalize()}' with deceptive character substitutions.",
                    "evidence": [f"Domain: {domain}"]
                })
                break

        # 4. Risky TLD in Sender Domain
        for tld in RISKY_TLDS:
            if domain.endswith(tld):
                tld_pts = 6 if score == 0 else 0
                if score == 0:
                    score += tld_pts
                findings.append({
                    "id": "SND_RISKY_TLD",
                    "category": "sender",
                    "name": "Suspicious Sender Domain Extension",
                    "severity": "medium",
                    "points": 6,
                    "description": f"The sender domain '{domain}' uses a TLD extension frequently used in low-reputation or disposable email infrastructure.",
                    "evidence": [f"Sender Domain: {domain}"]
                })
                break

        return findings, score

    def _generate_summary(self, category_scores: dict, total_score: int) -> str:
        """Generates a concise human-readable summary of the rule-based findings."""
        if total_score == 0:
            return "No obvious rule-based phishing patterns detected in sender headers, links, or message text."

        flagged_categories = [cat.capitalize() for cat, pts in category_scores.items() if pts > 0]
        return f"Rule engine detected {len(flagged_categories)} threat indicator categories ({', '.join(flagged_categories)}) totaling {total_score}/60 rule risk points."
