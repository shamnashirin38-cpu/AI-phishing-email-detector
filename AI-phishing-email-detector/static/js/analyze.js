/**
 * Email Analysis View Client-Side Logic.
 * Handles interactive sample loading, AJAX analysis submission,
 * multi-stage loading animation, and dynamic results visualization.
 */

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("email-analysis-form");
  const senderInput = document.getElementById("sender-input");
  const subjectInput = document.getElementById("subject-input");
  const bodyInput = document.getElementById("body-input");
  const clearBtn = document.getElementById("clear-form-btn");
  const submitBtn = document.getElementById("analyze-submit-btn");

  const loadingState = document.getElementById("loading-state");
  const resultsCard = document.getElementById("results-card");
  const sampleButtons = document.querySelectorAll(".sample-btn");

  // Cache sample emails from API for quick loading
  let sampleCache = {};
  fetch("/api/sample-emails")
    .then(r => r.json())
    .then(data => {
      if (data.samples) {
        data.samples.forEach(s => {
          sampleCache[s.id] = s;
        });
      }
    })
    .catch(() => {});

  // Handle sample button clicks
  sampleButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const sampleId = btn.getAttribute("data-sample-id");
      const sample = sampleCache[sampleId];
      if (sample) {
        senderInput.value = sample.sender || "";
        subjectInput.value = sample.subject || "";
        bodyInput.value = sample.body || "";
        showToast(`Loaded sample: ${sample.title}`, "info");
      }
    });
  });

  // Handle Clear Form
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      form.reset();
      resultsCard.style.display = "none";
      showToast("Form cleared.", "info");
    });
  }

  // Handle Form Submission
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const sender = senderInput.value.trim();
    const subject = subjectInput.value.trim();
    const body = bodyInput.value.trim();

    if (!body) {
      showToast("Please provide the email body content to analyze.", "warning");
      bodyInput.focus();
      return;
    }

    // UI Loading state transition
    submitBtn.disabled = true;
    submitBtn.innerHTML = "<span>Analyzing...</span>";
    resultsCard.style.display = "none";
    loadingState.style.display = "block";
    loadingState.scrollIntoView({ behavior: "smooth", block: "start" });

    // Multi-stage loading progress indication
    const step1 = document.getElementById("step-1");
    const step2 = document.getElementById("step-2");
    const step3 = document.getElementById("step-3");
    const step4 = document.getElementById("step-4");

    step1.innerHTML = "⏳ 1. Sanitizing and parsing email input...";
    step2.innerHTML = "⏳ 2. Evaluating 5 rule-based threat vectors (0–60 pts)...";
    step3.innerHTML = "⏳ 3. Querying local Ollama AI model (0–40 pts)...";
    step4.innerHTML = "⏳ 4. Synthesizing risk score & defensive actions...";

    setTimeout(() => { if (step1) step1.innerHTML = "✅ 1. Input sanitized and parsed."; }, 300);
    setTimeout(() => { if (step2) step2.innerHTML = "✅ 2. Rule-based threat vectors evaluated."; }, 700);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender, subject, body })
      });

      const json = await response.json();

      if (!response.ok || !json.success) {
        throw new Error(json.error || "Analysis failed on the server.");
      }

      if (step3) step3.innerHTML = "✅ 3. AI model inference complete.";
      if (step4) step4.innerHTML = "✅ 4. Risk synthesized.";

      setTimeout(() => {
        loadingState.style.display = "none";
        renderResults(json.data);
        resultsCard.style.display = "block";
        resultsCard.scrollIntoView({ behavior: "smooth", block: "start" });
        showToast("Analysis complete!", "success");
      }, 500);

    } catch (err) {
      loadingState.style.display = "none";
      showToast(err.message || "An unexpected error occurred during analysis.", "error");
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = "<span>⚡ Analyze Email Threat</span>";
    }
  });

  function renderResults(data) {
    // 1. Verdict Banner
    const banner = document.getElementById("verdict-banner");
    const icon = document.getElementById("verdict-icon");
    const title = document.getElementById("verdict-title");

    if (data.verdict === "Phishing") {
      banner.style.backgroundColor = "var(--color-critical-bg)";
      banner.style.border = "1px solid var(--color-critical)";
      icon.textContent = "🚨";
      title.textContent = "PHISHING DETECTED";
      title.style.color = "var(--color-critical)";
    } else if (data.verdict === "Suspicious") {
      banner.style.backgroundColor = "var(--color-medium-bg)";
      banner.style.border = "1px solid var(--color-medium)";
      icon.textContent = "⚠️";
      title.textContent = "SUSPICIOUS EMAIL";
      title.style.color = "var(--color-medium)";
    } else {
      banner.style.backgroundColor = "var(--color-safe-bg)";
      banner.style.border = "1px solid var(--color-safe)";
      icon.textContent = "✅";
      title.textContent = "VERIFIED SAFE";
      title.style.color = "var(--color-safe)";
    }

    // 2. Score Dial
    const scoreCircle = document.getElementById("score-circle");
    const scoreVal = document.getElementById("risk-score-value");
    const catBadge = document.getElementById("risk-category-badge");
    const catDesc = document.getElementById("risk-category-desc");

    scoreVal.textContent = data.final_risk_score;
    scoreCircle.className = "score-circle " + data.risk_category.toLowerCase();
    
    catBadge.className = "badge " + data.risk_category_badge;
    catBadge.textContent = `${data.risk_category} Risk`;
    catDesc.textContent = data.risk_category_description;

    // 3. Score Breakdown
    document.getElementById("rule-score-breakdown").textContent = `${data.rule_score} / 60 pts`;
    
    const aiScoreElem = document.getElementById("ai-score-breakdown");
    if (data.ai_available && data.ai_score !== null) {
      aiScoreElem.textContent = `${data.ai_score} / 40 pts`;
    } else {
      aiScoreElem.textContent = "Offline (Rule-Only Normalized)";
      aiScoreElem.style.color = "var(--color-medium)";
    }

    const confElem = document.getElementById("ai-confidence-value");
    if (data.ai_confidence !== null && data.ai_confidence !== undefined) {
      confElem.textContent = `${Math.round(data.ai_confidence * 100)}%`;
    } else {
      confElem.textContent = "N/A (AI Offline)";
    }

    document.getElementById("scoring-note-text").textContent = data.scoring_note;

    // 4. Detected Indicators List
    const indContainer = document.getElementById("indicators-container");
    const indBadge = document.getElementById("indicators-count-badge");
    indContainer.innerHTML = "";
    const indicators = data.indicators || [];
    indBadge.textContent = `${indicators.length} Found`;

    if (indicators.length === 0) {
      indContainer.innerHTML = `
        <div style="background-color: var(--bg-secondary); padding: 16px; border-radius: var(--radius-md); color: var(--color-safe); font-size: 13px;">
          ✅ No overt rule-based threat indicators detected in headers, links, or text.
        </div>
      `;
    } else {
      indicators.forEach(ind => {
        const item = document.createElement("div");
        item.className = "indicator-item";
        
        let evidenceHtml = "";
        if (ind.evidence && ind.evidence.length > 0) {
          const pills = ind.evidence.map(e => `<span class="evidence-pill">${escapeHtml(e)}</span>`).join("");
          evidenceHtml = `
            <div style="margin-top: 8px;">
              <span style="font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase;">Matched Evidence:</span>
              <div>${pills}</div>
            </div>
          `;
        }

        const sevClass = ind.severity === "critical" ? "badge-critical" : (ind.severity === "high" ? "badge-high" : "badge-medium");

        item.innerHTML = `
          <div class="indicator-header">
            <div class="indicator-title">
              <span>⚠️ ${escapeHtml(ind.name)}</span>
            </div>
            <span class="badge ${sevClass}">${escapeHtml(ind.severity)} (+${ind.points} pts)</span>
          </div>
          <p style="font-size: 13px; color: var(--text-secondary);">${escapeHtml(ind.description)}</p>
          ${evidenceHtml}
        `;
        indContainer.appendChild(item);
      });
    }

    // 5. AI Reasoning
    document.getElementById("ai-model-tag").textContent = data.ai_model || "local-llm";
    document.getElementById("ai-reasoning-text").textContent = data.ai_reasoning || "No AI explanation available.";
    const aiStatusElem = document.getElementById("ai-status-indicator");
    if (data.ai_available) {
      aiStatusElem.textContent = "Ollama Inference Active";
      aiStatusElem.style.color = "var(--color-safe)";
    } else {
      aiStatusElem.textContent = "Ollama Offline";
      aiStatusElem.style.color = "var(--color-medium)";
    }

    // 6. Recommendations
    const recList = document.getElementById("recommendations-list");
    recList.innerHTML = "";
    (data.recommended_actions || []).forEach(act => {
      const li = document.createElement("li");
      li.style.padding = "10px 14px";
      li.style.backgroundColor = "var(--bg-card)";
      li.style.borderRadius = "var(--radius-sm)";
      li.style.borderLeft = "3px solid var(--accent-cyan)";
      li.textContent = act;
      recList.appendChild(li);
    });

    // 7. Export and View Links
    if (data.scan_id) {
      document.getElementById("export-txt-btn").href = `/export/${data.scan_id}/txt`;
      document.getElementById("export-json-btn").href = `/export/${data.scan_id}/json`;
      document.getElementById("view-scan-link").href = `/scan/${data.scan_id}`;
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
