# Threat Detection Flowcharts & Execution Logic

## 1. End-to-End Analysis Working Flow

```mermaid
flowchart TD
    Start([User submits Email in Web Form]) --> Validate{Input Valid?<br/>Body not empty & < 100K chars}
    Validate -- No --> Return400[Return HTTP 400 with validation error]
    Validate -- Yes --> ParallelStart[Initiate Dual Detection Analysis]

    subgraph Layer1 [Layer 1: Deterministic Heuristic Engine]
        ParallelStart --> CheckURLs[Check URLs: IP Host, Shortener, Risky TLD, Subdomains]
        ParallelStart --> CheckUrgency[Check Language: Suspension Threats, Strict Deadlines]
        ParallelStart --> CheckCreds[Check Credentials: Password & OTP/2FA Requests]
        ParallelStart --> CheckFinance[Check Financial: Crypto Wallets, Gift Cards, Wire Transfer]
        ParallelStart --> CheckSender[Check Sender: Display Name Spoofing, Typosquatting]
        CheckURLs --> SumRules[Aggregate Points & Extract Evidence]
        CheckUrgency --> SumRules
        CheckCreds --> SumRules
        CheckFinance --> SumRules
        CheckSender --> SumRules
        SumRules --> CapRules[Cap Rule Score to Max 60 Points]
    end

    subgraph Layer2 [Layer 2: Ollama Local AI Engine]
        ParallelStart --> PingOllama{Is Ollama Running &<br/>Model Ready?}
        PingOllama -- Yes --> QueryModel[Send Structured Prompt with JSON Schema]
        QueryModel --> ParseResponse{Valid JSON Returned?}
        ParseResponse -- Yes --> ClampAI[Clamp AI Score to 0–40 pts, extract reasoning & confidence]
        ParseResponse -- No --> RegexFallback[Attempt Regex Repair & Fallback Parsing]
        RegexFallback --> ClampAI
        PingOllama -- No --> AIOffline[Mark AI Offline & Return Graceful Advisory]
    end

    CapRules --> Synthesize[Synthesize Risk Score]
    ClampAI --> Synthesize
    AIOffline --> Synthesize

    subgraph RiskSynthesis [Scoring & Categorization]
        Synthesize --> ModeCheck{Was AI Available?}
        ModeCheck -- Yes --> HybridFormula["Total = min(100, Rule Score + AI Score)"]
        ModeCheck -- No --> NormalizedFormula["Total = round((Rule Score / 60) * 100)<br/>(Rule-Only Normalization)"]
        HybridFormula --> Categorize[Categorize Risk & Verdict]
        NormalizedFormula --> Categorize
        Categorize --> SaveDB[(Store Record in SQLite DB)]
    end

    SaveDB --> RenderUI[Render Threat Score Meter, Verdict Badge & Evidence in UI]
    RenderUI --> End([Analysis Complete & Ready for Export])
```

---

## 2. Risk Categorization & Verdict Determination

```mermaid
flowchart LR
    Score[Final Calculated Risk Score: 0 to 100] --> CatDecision{Score Range}
    
    CatDecision -->|0 to 24| Low["Category: LOW (Green)<br/>Verdict: Safe<br/>Minimal threat indicators"]
    CatDecision -->|25 to 49| Med["Category: MEDIUM (Yellow)<br/>Verdict: Suspicious<br/>Mild urgency or tracking anomalies"]
    CatDecision -->|50 to 74| High["Category: HIGH (Orange)<br/>Verdict: Phishing<br/>Significant brand spoofing or threats"]
    CatDecision -->|75 to 100| Crit["Category: CRITICAL (Red)<br/>Verdict: Phishing<br/>Direct credential theft, IP link, or active fraud"]
```

---

## 3. Ollama Fallback & Fault Tolerance Flow

```mermaid
flowchart TD
    Req[Ollama Client Request] --> TryConnect{Try HTTP Connection<br/>to localhost:11434}
    
    TryConnect -- Connection Refused --> ErrConn["Catch ConnectionError<br/>• Return status: 'offline'<br/>• Set ai_score: None<br/>• Never crash Flask"]
    TryConnect -- Timeout > 30s --> ErrTimeout["Catch Timeout<br/>• Return status: 'timeout'<br/>• Suggest model downsizing"]
    TryConnect -- Success 200 OK --> ParseBody{Parse Response Body}
    
    ParseBody -- Markdown Fences Present --> CleanMarkdown[Strip ```json code blocks]
    ParseBody -- Clean JSON --> ValidateTypes[Validate Verdict, Clamp Score 0–40, Conf 0–1]
    CleanMarkdown --> ValidateTypes
    
    ValidateTypes --> Success[Return Validated AI Assessment Object]
```
