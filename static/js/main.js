/**
 * Global JavaScript logic for AI Phishing Email Detector.
 * Handles Ollama live connectivity checks and toast notifications.
 */

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.style.padding = "12px 18px";
  toast.style.borderRadius = "8px";
  toast.style.fontSize = "13px";
  toast.style.fontWeight = "500";
  toast.style.color = "#fff";
  toast.style.boxShadow = "0 8px 20px rgba(0,0,0,0.4)";
  toast.style.transition = "all 0.3s ease";
  toast.style.display = "flex";
  toast.style.alignItems = "center";
  toast.style.gap = "10px";

  if (type === "success") {
    toast.style.backgroundColor = "#10b981";
  } else if (type === "error") {
    toast.style.backgroundColor = "#ef4444";
  } else if (type === "warning") {
    toast.style.backgroundColor = "#f59e0b";
  } else {
    toast.style.backgroundColor = "#1e293b";
    toast.style.border = "1px solid #00d2ff";
  }

  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Function to check Ollama status in real time
async function checkOllamaStatus(isManual = false) {
  const badge = document.getElementById("ollama-status-badge");
  const textElem = document.getElementById("ollama-status-text");
  if (!badge || !textElem) return;

  if (isManual) {
    textElem.textContent = "Checking Ollama...";
  }

  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    const dot = badge.querySelector(".status-dot");

    if (dot) {
      dot.className = "status-dot";
      if (data.available && data.model_installed) {
        dot.classList.add("dot-online");
        textElem.textContent = `Ollama: Online (${data.selected_model})`;
        if (isManual) showToast(`Ollama is online and ready with ${data.selected_model}`, "success");
      } else if (data.status === "model_missing") {
        dot.classList.add("dot-model-missing");
        textElem.textContent = "Ollama: Model Missing";
        if (isManual) showToast(`Ollama is running, but ${data.selected_model} is not pulled.`, "warning");
      } else {
        dot.classList.add("dot-offline");
        textElem.textContent = "Ollama: Offline (Rule Fallback)";
        if (isManual) showToast("Ollama is currently offline. Deterministic rule scoring will be used.", "info");
      }
    }
  } catch (err) {
    const dot = badge.querySelector(".status-dot");
    if (dot) {
      dot.className = "status-dot dot-offline";
      textElem.textContent = "Ollama: Offline";
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const statusBadge = document.getElementById("ollama-status-badge");
  if (statusBadge) {
    statusBadge.addEventListener("click", () => checkOllamaStatus(true));
  }
});
