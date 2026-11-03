# System Architecture & Technical Specifications

## 1. Architectural Overview

The **AI-Powered Phishing Email Detection System** utilizes a **two-tier hybrid threat detection model** combining:
1. **Deterministic Rule Engine (Layer 1)**: Heuristic regex and string pattern recognition for instant, zero-latency detection of known indicators of compromise (IoCs).
2. **Local Neural Language Model (Layer 2)**: On-premise Large Language Model (`llama3.2:3b`) running via Ollama for semantic intent analysis and social engineering triage.

```mermaid
flowchart TD
    subgraph Client ["Client Browser (Presentation Layer)"]
        UI["Web Dashboard UI<br/>(HTML5 / CSS3 / Vanilla JS)"]
        Form["Analysis Form & Sample Loader"]
        HealthBadge["Real-Time Ollama Status Badge"]
    end

    subgraph Server ["Flask Application Server (Application Layer)"]
        Routes["Flask Routes & REST API Controller<br/>(app/routes.py)"]
        Validator["Input Sanitizer & Defanger<br/>(app/utils/validators.py)"]
        Scorer["Unified Risk Scoring Engine<br/>(app/utils/scoring.py)"]
        Exporter["Report Exporter (TXT / JSON)<br/>(app/utils/exporters.py)"]
    end

    subgraph DetectionEngines ["Dual Detection Engines"]
        RuleEngine["Deterministic Rule Engine (0–60 pts)<br/>(app/rules/rule_engine.py)<br/>• Suspicious URLs<br/>• Urgency / Coercion<br/>• Credential / OTP Harvesting<br/>• Financial / Wire Fraud<br/>• Domain Impersonation"]
        OllamaClient["Ollama AI Client (0–40 pts)<br/>(app/ai/ollama_client.py)<br/>• Schema Validation<br/>• Markdown Stripper<br/>• Error & Timeout Fallback"]
    end

    subgraph LocalAI ["Local Machine Hardware"]
        OllamaDaemon["Ollama Service (localhost:11434)"]
        LLM["Llama 3.2 3B Model<br/>(Zero Cloud Transmission)"]
    end

    subgraph Storage ["Data Persistence Layer"]
        SQLite["SQLite Database<br/>(instance/phishing_detector.db)<br/>• Parameterized Queries<br/>• Scan History & Full Reports"]
    end

    UI -->|HTTP POST JSON| Routes
    HealthBadge -->|GET /api/status| Routes
    Routes --> Validator
    Validator --> RuleEngine
    Validator --> OllamaClient
    OllamaClient <-->|REST API HTTP| OllamaDaemon
    OllamaDaemon <--> LLM
    RuleEngine --> Scorer
    OllamaClient --> Scorer
    Scorer --> Storage
    Scorer --> Routes
    Routes --> UI
    Routes --> Exporter
```

---

## 2. Component Breakdown

| Module | Primary File | Responsibility |
|---|---|---|
| **Web Presentation** | `templates/*.html`, `static/css/style.css`, `static/js/*.js` | Dark cybersecurity themed dashboard, animated progress states, circular threat gauge, sample loader, and search filters. |
| **Routing & API** | `app/routes.py` | Exposes REST endpoints (`/api/analyze`, `/api/status`, `/api/history`, etc.) and renders server-side Jinja templates. |
| **Rule Engine** | `app/rules/rule_engine.py`, `app/rules/patterns.py` | Evaluates 5 threat categories, disarms malicious URLs (defanging), extracts evidence snippets, and caps score at 60. |
| **AI Integration** | `app/ai/ollama_client.py`, `app/ai/prompts.py` | Communicates with Ollama daemon via local socket/HTTP, validates strict JSON schema, clamps score to 40, and handles offline states. |
| **Scoring Engine** | `app/utils/scoring.py` | Combines rule and AI scores, normalizes rule scores when AI is offline, calculates risk categories, and distinguishes risk from confidence. |
| **Database** | `app/database.py` | SQLite persistence using parameterized queries to prevent SQL injection. Manages history search, filtering, and aggregation. |
| **Exporters** | `app/utils/exporters.py` | Generates structured JSON and professional Plaintext Cybersecurity Incident Triage Reports. |

---

## 3. Privacy & Security Model

1. **Zero External Data Leakage**: Emails submitted to the system are processed entirely on localhost. No data is transmitted to OpenAI, Anthropic, Google, or any cloud LLM provider.
2. **Defensive Link Disarming**: URLs found in suspicious emails are defanged (e.g. `hxxp://` and `[.]`) in UI displays and exported reports to prevent accidental clicks.
3. **Injection Prevention**: Safe parameterized SQL queries (`?` placeholders) and Jinja2 template auto-escaping prevent SQLi and XSS.
4. **Input Boundary Limits**: Strict character length validation (max 100,000 characters for body) protects against denial-of-service via memory exhaustion.
