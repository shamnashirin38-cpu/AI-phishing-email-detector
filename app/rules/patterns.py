"""
Predefined regex patterns, keywords, and heuristics for Rule-Based Phishing Detection.
Categories:
1. Suspicious URLs (IP host, shorteners, risky TLDs, deceptive subdomains, @ symbols)
2. Urgent or Threatening Language (deadlines, account suspension, legal threats)
3. Password & OTP Requests (credential harvesting, 2FA/PIN demands)
4. Payment & Financial Requests (cryptocurrency, gift cards, wire transfer, invoice fraud)
5. Sender Spoofing & Domain Mismatches (display name tricks, lookalike domains, free mail impersonation)
"""

import re

# ==========================================
# 1. SUSPICIOUS URL PATTERNS & HEURISTICS
# ==========================================

URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'\)]+',
    re.IGNORECASE
)

# Defanged URLs e.g. hxxp:// or [.]
DEFANGED_URL_REGEX = re.compile(
    r'(?:hxxps?://|http\[s\]://)[^\s<>"\'\)]+',
    re.IGNORECASE
)

# IPv4 address as host e.g. http://192.168.1.1/login or http://45.33.32.156
IP_HOST_REGEX = re.compile(
    r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)',
    re.IGNORECASE
)

# Known URL shorteners often abused in phishing
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "rb.gy",
    "cutt.ly", "goo.gl", "shorte.st", "rebrand.ly", "bl.ink",
    "tiny.cc", "t2mio.com", "adf.ly", "bc.vc"
}

# TLDs frequently abused in malicious campaigns
RISKY_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".club", ".work", ".click", ".monster", ".icu",
    ".loan", ".cam", ".live", ".fit", ".rest", ".gdn", ".kim"
}

# Deceptive login/credential keywords in URL paths or subdomains
SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account-update", "secure-update", "confirm-identity", "password-reset",
    "banking", "auth", "credential", "session-expired", "wallet-connect"
]

# Popular targeted brands often spoofed in URLs
TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citi", "irs", "dhl",
    "fedex", "usps", "facebook", "instagram", "dropbox", "outlook"
]

# ==========================================
# 2. URGENT & THREATENING LANGUAGE PATTERNS
# ==========================================

URGENT_PHRASES = [
    r'\bimmediate(?:ly)?\s+action\s+required\b',
    r'\baction\s+required\s+immediately\b',
    r'\b(?:within|after|in|past)\s+(?:24|48|72|12|2|1)\s+hours?\b',
    r'\baccount\s+(?:has\s+been\s+)?suspended\b',
    r'\baccount\s+(?:will\s+be\s+)?terminated\b',
    r'\baccount\s+(?:temporarily\s+)?locked\b',
    r'\bpermanently\s+(?:closed|disabled|deleted)\b',
    r'\bsecurity\s+alert\s*:\s*unauthorized\b',
    r'\bunauthorized\s+access\s+detected\b',
    r'\bsecurity\s+breach\s+detected\b',
    r'\bfinal\s+(?:notice|warning)\b',
    r'\btime\s+is\s+running\s+out\b',
    r'\bact\s+now\s+or\b',
    r'\blegal\s+action\s+will\s+be\s+taken\b',
    r'\barrest\s+warrant\b',
    r'\blaw\s+enforcement\s+(?:contacted|notified)\b',
    r'\bfail(?:ure)?\s+to\s+respond\s+will\s+result\b',
    r'\burgent\s+response\s+needed\b',
    r'\bpenalty\s+will\s+apply\b'
]

# ==========================================
# 3. PASSWORD & OTP / CREDENTIAL HARVESTING
# ==========================================

CREDENTIAL_PHRASES = [
    r'\b(?:enter|confirm|verify|reset|update|provide)\s+(?:your\s+)?(?:current\s+)?password\b',
    r'\bprovide\s+(?:your\s+)?(?:login\s+)?credentials\b',
    r'\bverify\s+(?:your\s+)?(?:one-time\s+password|otp|pin)\b',
    r'\bone-time\s+password\b',
    r'\bone\s+time\s+password\b',
    r'\b2fa\s+(?:code|verification)\b',
    r'\btwo-factor\s+(?:code|authentication)\b',
    r'\bverification\s+code\b',
    r'\bconfirm\s+(?:your\s+)?pin\s+number\b',
    r'\bclick\s+here\s+to\s+reset\s+(?:your\s+)?password\b',
    r'\bupdate\s+(?:your\s+)?password\s+immediately\b',
    r'\bsign\s+in\s+to\s+verify\s+your\s+account\b',
    r'\bre-authenticate\s+your\s+account\b',
    r'\bconfirm\s+your\s+identity\b',
    r'\bvalidate\s+your\s+security\s+questions?\b',
    r'\bsecurity\s+code\s+sent\s+to\b'
]

# ==========================================
# 4. PAYMENT & FINANCIAL FRAUD PATTERNS
# ==========================================

FINANCIAL_PHRASES = [
    r'\bwire\s+transfer\b',
    r'\bsend\s+(?:funds|money)\s+via\s+western\s+union\b',
    r'\bmoneygram\b',
    r'\b(?:bitcoin|btc|ethereum|eth|usdt)\s+wallet\b',
    r'\bcrypto(?:currency)?\s+address\b',
    r'\bbuy\s+(?:itunes|amazon|steam|google\s+play)\s+gift\s+cards?\b',
    r'\bgift\s+card\s+codes?\b',
    r'\binvoice\s+(?:is\s+)?overdue\b',
    r'\boverdue\s+invoice\b',
    r'\bunpaid\s+invoice\b',
    r'\bupdate\s+(?:your\s+)?(?:billing|payment)\s+(?:details|information|method)\b',
    r'\bpayment\s+(?:has\s+been\s+)?declined\b',
    r'\bdirect\s+deposit\s+(?:change|form|information)\b',
    r'\bpayroll\s+(?:update|change|portal)\b',
    r'\brefund\s+of\s+\$[\d,]+(?:\.\d{2})?\b',
    r'\blottery\s+winnings?\b',
    r'\bclaim\s+your\s+prize\b'
]

# ==========================================
# 5. SENDER SPOOFING & DOMAIN MISMATCH
# ==========================================

# Free webmail providers commonly abused to spoof official institutions
FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "zoho.com", "yandex.com", "proton.me", "protonmail.com"
}

# Typosquatting / Lookalike brand keyword mappings
TYPOSQUAT_PATTERNS = [
    (r'paypa[l1i]', "paypal"),
    (r'micr[o0]s[o0]ft', "microsoft"),
    (r'g[o0]{2}g[l1]e', "google"),
    (r'amaz[o0]n', "amazon"),
    (r'netfl[i1]x', "netflix"),
    (r'app[l1]e', "apple"),
    (r'ch[a4]se', "chase"),
    (r'w[e3]llsf[a4]rg[o0]', "wellsfargo")
]
