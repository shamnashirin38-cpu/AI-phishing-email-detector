# College Viva Voce Defense Guide & Theory Reference

This document is prepared to help you defend your college final-year / capstone project during academic viva presentations and external examiner evaluations.

---

## 1. Project Synopsis

- **Project Title:** AI-Powered Phishing Email Detection System
- **Domain:** Cybersecurity, Natural Language Processing (NLP), Machine Learning
- **Tech Stack:** Python 3.11+, Flask, Ollama (Llama 3.2 3B), SQLite, HTML5, CSS3, Vanilla JavaScript, pytest
- **Core Innovation:** A privacy-preserving, dual-tier hybrid architecture combining 5 deterministic rule heuristics (0–60 pts) with local Large Language Model inference (0–40 pts).

---

## 2. Key Academic Concepts to Remember

### A. Why Hybrid Architecture?
| Approach | Strengths | Weaknesses |
|---|---|---|
| **Rule Engine Only** | Deterministic, zero latency, 100% explainable, zero hallucination | Brittle against novel paraphrasing, synonyms, and complex social engineering |
| **LLM Only** | Understands context, nuance, and psychological coercion | Computationally heavy, non-deterministic, prone to hallucination or prompt injection |
| **Hybrid (Our System)** | Combines deterministic evidence for known IoCs with semantic reasoning for novel threats | Best of both worlds; reproducible and robust |

### B. Risk Score vs. AI Confidence (Crucial Viva Question)
- **Risk Score (0 to 100):** Measures the *threat level and malicious potential* of the email.
- **AI Confidence (0% to 100%):** Measures *how sure the model is* about its decision.
  - *Example:* A verified academic email from your professor has a **Risk Score of 0** (Completely Safe), but the AI will have **99% Confidence** in that classification.

### C. Zero Data Leakage (Privacy Compliance)
Standard commercial AI tools send email texts to public cloud APIs (OpenAI, Google, AWS). In corporate or personal contexts, this violates data privacy regulations (**GDPR**, **HIPAA**, **FERPA**). By using **Ollama** locally, no byte of email content ever leaves the host machine.

---

## 3. Top 15 Viva Voce Questions & Model Answers

### Q1: What problem does this system solve?
**Answer:** Over 90% of corporate data breaches originate from phishing emails. Traditional spam filters rely on domain blacklists, which fail against zero-day phishing links, brand typosquatting, and compromised legitimate accounts. Our system provides automated triage by combining heuristic indicator extraction with local AI semantic analysis.

### Q2: What are the 5 core rule indicators implemented in your system?
**Answer:**
1. **Suspicious URLs:** IP-based hosts, URL shorteners (bit.ly), high-risk TLDs (.xyz, .top), and deceptive subdomains.
2. **Urgent or Coercive Language:** Account suspension threats, legal ultimatums, and 24-hour deadlines.
3. **Password or OTP Solicitation:** Credential harvesting, PIN prompts, and two-factor code interception.
4. **Financial and Payment Fraud:** Cryptocurrency wallet addresses, gift card demands, and fraudulent invoices.
5. **Sender Spoofing & Domain Mismatches:** Display name impersonation (e.g. "PayPal Support" from a gmail.com account) and typosquatting (e.g. `paypa1.com`).

### Q3: How is the final risk score calculated?
**Answer:** The system uses a bounded point distribution:
- **Rule Engine:** 0 to 60 points based on detected indicators (capped per category to avoid duplicate inflation).
- **Ollama AI:** 0 to 40 points based on contextual reasoning.
- **Total Score:** $\text{Total} = \min(100, \text{Rule} + \text{AI})$.
- When Ollama is offline, the rule score is normalized: $\text{Total} = \text{round}((\text{Rule Score} / 60) \times 100)$.

### Q4: How do you prevent the same threat signal from being counted multiple times?
**Answer:** The Rule Engine implements deduplication. Extracted URLs and matching phrases are stored in `set()` structures and normalized. For instance, repeating "within 24 hours" multiple times in the body will only trigger the deadline indicator once.

### Q5: How does the application handle Ollama server failure or high latency?
**Answer:** The architecture features graceful fault tolerance. HTTP calls to Ollama are protected by connection exception handling and a strict 30-second timeout. If the service is unreachable, Flask catches the error, sets `ai_available: False`, and normalizes the deterministic rule score without crashing.

### Q6: Why did you choose Llama 3.2 3B over larger models like Llama 70B?
**Answer:** Llama 3.2 3B is lightweight, fast, and optimized for edge devices and consumer laptops. It fits comfortably in 4GB to 8GB of RAM while maintaining excellent instruction-following capabilities for structured JSON output.

### Q7: Why did you choose SQLite for the database?
**Answer:** SQLite is serverless, zero-configuration, and self-contained in a single file (`instance/phishing_detector.db`). It is ideal for local-first desktop security tools, requires no separate database daemon, and supports standard ACID transactions with safe parameterized queries.

### Q8: What security practices did you implement in the backend?
**Answer:**
- Parameterized SQL queries (`?`) to prevent SQL Injection.
- Jinja2 template auto-escaping to prevent Cross-Site Scripting (XSS).
- Automatic URL defanging (`hxxp://` and `[.]`) to prevent accidental clicks on malicious links.
- Maximum payload length limits (512 KB payload, 100 KB body) to prevent Denial of Service (DoS).
- Sensitive environment configurations managed via `.env`.

### Q9: How did you test the system?
**Answer:** We wrote 37 automated tests using `pytest` covering:
- Rule engine indicators (suspicious URLs, urgency, OTP harvesting, payment fraud, sender mismatch).
- Scoring boundaries (0, 24, 25, 49, 50, 74, 75, 100).
- Mocked Ollama AI responses (phishing, safe, ambiguous, markdown stripping, timeout, offline).
- SQLite database CRUD operations and search filtering.
- REST API endpoints and input validation.

### Q10: What are the current limitations of the project?
**Answer:**
1. **Attachments:** The system currently analyzes text content and URLs; it does not parse binary attachments (PDF/EXE/macro-enabled Office docs).
2. **DNS & SPF/DKIM:** It performs lexical analysis on the sender header but does not perform live MX/DNS lookup or DKIM cryptographic signature verification.
3. **Model Resource Requirements:** Ollama requires local CPU/RAM to run the model.

### Q11: What future improvements would you add?
**Answer:**
- Static and sandbox analysis for file attachments (using ClamAV or YARA).
- Active DNS/SPF/DKIM/DMARC record resolution.
- Browser extension or Outlook/Thunderbird add-in for real-time inbox scanning.
- Fine-tuning the local LLM on the PhishTank or Enron email corpus.
