/**
 * Scan History Page Client-Side Logic.
 * Handles dynamic search, category/verdict filters, pagination,
 * single scan deletion, and modal-confirmed clear-all history.
 */

document.addEventListener("DOMContentLoaded", () => {
  const searchInput = document.getElementById("history-search-input");
  const categoryFilter = document.getElementById("filter-category");
  const verdictFilter = document.getElementById("filter-verdict");
  const tableBody = document.getElementById("history-table-body");
  const prevBtn = document.getElementById("prev-page-btn");
  const nextBtn = document.getElementById("next-page-btn");
  const pageIndicator = document.getElementById("page-indicator");
  const countText = document.getElementById("history-count-text");

  const clearAllBtn = document.getElementById("clear-all-history-btn");
  const confirmModal = document.getElementById("clear-confirm-modal");
  const cancelClearBtn = document.getElementById("cancel-clear-btn");
  const confirmClearBtn = document.getElementById("confirm-clear-btn");

  let currentPage = 1;
  const perPage = 10;
  let debounceTimer = null;

  async function loadHistory(page = 1) {
    currentPage = page;
    const query = searchInput.value.trim();
    const category = categoryFilter.value;
    const verdict = verdictFilter.value;

    tableBody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 32px; color: var(--text-muted);">
          Loading scan records...
        </td>
      </tr>
    `;

    try {
      const url = new URL("/api/history", window.location.origin);
      url.searchParams.set("page", page);
      url.searchParams.set("per_page", perPage);
      if (query) url.searchParams.set("q", query);
      if (category && category !== "all") url.searchParams.set("category", category);
      if (verdict && verdict !== "all") url.searchParams.set("verdict", verdict);

      const resp = await fetch(url);
      const data = await resp.json();

      if (!resp.ok || !data.success) {
        throw new Error(data.error || "Failed to load history.");
      }

      renderTable(data.scans, data.total_count, data.page, data.total_pages);
    } catch (err) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; padding: 24px; color: var(--color-critical);">
            ⚠️ Error loading scans: ${err.message}
          </td>
        </tr>
      `;
    }
  }

  function renderTable(scans, totalCount, page, totalPages) {
    countText.textContent = `Showing ${scans.length} of ${totalCount} scans`;
    pageIndicator.textContent = `Page ${page} of ${totalPages}`;

    prevBtn.disabled = page <= 1;
    nextBtn.disabled = page >= totalPages;

    if (!scans || scans.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; padding: 36px 16px;">
            <div style="font-size: 32px; margin-bottom: 8px;">🔍</div>
            <div style="font-size: 14px; font-weight: 600; color: var(--text-secondary);">No scan records found</div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Try modifying your search or filters.</div>
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = "";
    scans.forEach(scan => {
      const tr = document.createElement("tr");

      let scoreBadgeClass = "badge-low";
      if (scan.risk_score >= 75) scoreBadgeClass = "badge-critical";
      else if (scan.risk_score >= 50) scoreBadgeClass = "badge-high";
      else if (scan.risk_score >= 25) scoreBadgeClass = "badge-medium";

      let verdictBadgeClass = "badge-safe";
      if (scan.verdict === "Phishing") verdictBadgeClass = "badge-phishing";
      else if (scan.verdict === "Suspicious") verdictBadgeClass = "badge-suspicious";

      tr.innerHTML = `
        <td style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 600;">#${scan.id}</td>
        <td style="color: var(--text-muted); font-size: 12px;">${escapeHtml(scan.timestamp)}</td>
        <td><strong>${escapeHtml(scan.sender || "(Not provided)")}</strong></td>
        <td>${escapeHtml(scan.subject || "(No subject)")}</td>
        <td>
          <span class="badge ${scoreBadgeClass}">${scan.risk_score}/100</span>
        </td>
        <td>
          <span class="badge ${verdictBadgeClass}">${escapeHtml(scan.verdict)}</span>
        </td>
        <td>
          <div style="display: flex; gap: 6px;">
            <a href="/scan/${scan.id}" class="btn btn-secondary btn-sm" title="View Details">Details</a>
            <a href="/export/${scan.id}/txt" class="btn btn-secondary btn-sm" title="Download TXT">TXT</a>
            <button class="btn btn-outline-danger btn-sm delete-scan-btn" data-id="${scan.id}" title="Delete">🗑️</button>
          </div>
        </td>
      `;

      tableBody.appendChild(tr);
    });

    // Attach individual delete handlers
    document.querySelectorAll(".delete-scan-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        if (!confirm(`Are you sure you want to delete Scan #${id}?`)) return;

        try {
          const resp = await fetch(`/api/scan/${id}`, { method: "DELETE" });
          const res = await resp.json();
          if (res.success) {
            showToast(`Scan #${id} deleted`, "success");
            loadHistory(currentPage);
          } else {
            showToast(res.error || "Failed to delete", "error");
          }
        } catch (e) {
          showToast("Network error deleting scan", "error");
        }
      });
    });
  }

  // Event Listeners for Filters
  searchInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      loadHistory(1);
    }, 350);
  });

  categoryFilter.addEventListener("change", () => loadHistory(1));
  verdictFilter.addEventListener("change", () => loadHistory(1));

  prevBtn.addEventListener("click", () => {
    if (currentPage > 1) loadHistory(currentPage - 1);
  });

  nextBtn.addEventListener("click", () => {
    loadHistory(currentPage + 1);
  });

  // Clear All Modal Logic
  if (clearAllBtn) {
    clearAllBtn.addEventListener("click", () => {
      confirmModal.style.display = "flex";
    });
  }

  if (cancelClearBtn) {
    cancelClearBtn.addEventListener("click", () => {
      confirmModal.style.display = "none";
    });
  }

  if (confirmClearBtn) {
    confirmClearBtn.addEventListener("click", async () => {
      confirmModal.style.display = "none";
      try {
        const resp = await fetch("/api/history/clear", { method: "POST" });
        const res = await resp.json();
        if (res.success) {
          showToast("All scan records cleared successfully.", "success");
          loadHistory(1);
        } else {
          showToast(res.error || "Failed to clear history.", "error");
        }
      } catch (e) {
        showToast("Error clearing history.", "error");
      }
    });
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

  // Initial load
  loadHistory(1);
});
