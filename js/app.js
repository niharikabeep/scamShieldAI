/**
 * ScamShield AI - Application Controller & User Interface Engine
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Engines & State
  const heuristicEngine = new HeuristicEngine();
  const apiService = new ApiService();

  const state = {
    currentTab: "url-scanner",
    settings: { ...CONFIG.DEFAULT_SETTINGS },
    history: [],
    currentResult: null
  };

  // Load saved settings & history
  try {
    const savedSettings = localStorage.getItem(CONFIG.STORAGE_KEYS.SETTINGS);
    if (savedSettings) {
      state.settings = { ...state.settings, ...JSON.parse(savedSettings) };
    }
    const savedHistory = localStorage.getItem(CONFIG.STORAGE_KEYS.HISTORY);
    if (savedHistory) {
      state.history = JSON.parse(savedHistory);
    }
  } catch (e) {
    console.warn("Storage load error:", e);
  }

  // 2. DOM Elements Cache
  const navTabs = document.querySelectorAll(".nav-tab");
  const tabContents = document.querySelectorAll(".tab-content");
  const themeToggle = document.getElementById("theme-toggle");
  const historyCountBadge = document.getElementById("history-count");
  const apiStatusDot = document.getElementById("api-status-dot");

  // URL Tab Elements
  const urlForm = document.getElementById("url-form");
  const urlInput = document.getElementById("url-input");
  const urlPasteBtn = document.getElementById("url-paste-btn");
  const urlClearBtn = document.getElementById("url-clear-btn");
  const urlScanBtn = document.getElementById("url-scan-btn");

  // SMS Tab Elements
  const smsForm = document.getElementById("sms-form");
  const smsInput = document.getElementById("sms-input");
  const smsCharCounter = document.getElementById("sms-char-counter");
  const smsPasteBtn = document.getElementById("sms-paste-btn");
  const smsClearBtn = document.getElementById("sms-clear-btn");
  const smsScanBtn = document.getElementById("sms-scan-btn");

  // Results Section Elements
  const resultSection = document.getElementById("result-section");
  const resTypeBadge = document.getElementById("res-type-badge");
  const resTargetText = document.getElementById("res-target-text");
  const resEngineBadge = document.getElementById("res-engine-badge");
  const resTimeBadge = document.getElementById("res-time-badge");
  const gaugeFillPath = document.getElementById("gauge-fill-path");
  const resScoreValue = document.getElementById("res-score-value");
  const resVerdictBanner = document.getElementById("res-verdict-banner");
  const resCategoryPill = document.getElementById("res-category-pill");
  const resIntelStatus = document.getElementById("res-intel-status");
  const resIntelDetail = document.getElementById("res-intel-detail");
  const resSummaryText = document.getElementById("res-summary-text");
  const resFlagsCount = document.getElementById("res-flags-count");
  const resFlagsList = document.getElementById("res-flags-list");
  const resTrustBox = document.getElementById("res-trust-box");
  const resTrustList = document.getElementById("res-trust-list");
  const resExtractedUrlsBox = document.getElementById("res-extracted-urls-box");
  const resExtractedUrlsList = document.getElementById("res-extracted-urls-list");
  const resActionsList = document.getElementById("res-actions-list");
  const resCopyReportBtn = document.getElementById("res-copy-report-btn");
  const resDismissBtn = document.getElementById("res-dismiss-btn");

  // Gallery & History Elements
  const samplesGrid = document.getElementById("samples-grid");
  const historyTbody = document.getElementById("history-tbody");
  const historyEmpty = document.getElementById("history-empty");
  const clearHistoryBtn = document.getElementById("clear-history-btn");
  const exportHistoryBtn = document.getElementById("export-history-btn");

  // Settings Modal Elements
  const apiSettingsBtn = document.getElementById("api-settings-btn");
  const apiModal = document.getElementById("api-modal");
  const closeModalBtn = document.getElementById("close-modal-btn");
  const geminiApiKeyInput = document.getElementById("gemini-api-key-input");
  const toggleKeyVisibilityBtn = document.getElementById("toggle-key-visibility");
  const testGeminiKeyBtn = document.getElementById("test-gemini-key-btn");
  const geminiTestFeedback = document.getElementById("gemini-test-feedback");
  const geminiModelSelect = document.getElementById("gemini-model-select");
  const toggleUrlhaus = document.getElementById("toggle-urlhaus");
  const saveSettingsBtn = document.getElementById("save-settings-btn");
  const clearApiKeyBtn = document.getElementById("clear-api-key-btn");

  // 3. UI Helpers
  function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    
    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "error") icon = "❌";
    
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(10px)";
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  function updateApiStatusIndicator() {
    const key = apiService.getGeminiApiKey();
    if (key) {
      apiStatusDot.className = "status-dot dot-active";
      apiStatusDot.title = `Gemini AI Active (${state.settings.geminiModel})`;
    } else {
      apiStatusDot.className = "status-dot dot-inactive";
      apiStatusDot.title = "Gemini AI Not Configured (Using Local Heuristic Engine)";
    }
  }

  function updateHistoryBadge() {
    historyCountBadge.textContent = state.history.length;
  }

  function switchTab(tabId) {
    state.currentTab = tabId;
    navTabs.forEach(btn => {
      const isActive = btn.getAttribute("data-tab") === tabId;
      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-selected", isActive);
    });

    tabContents.forEach(content => {
      content.classList.toggle("active", content.id === tabId);
    });

    if (tabId === "history-view") {
      renderHistoryTable();
    }
  }

  // 4. Tab Navigation Events
  navTabs.forEach(tabBtn => {
    tabBtn.addEventListener("click", () => {
      const tabId = tabBtn.getAttribute("data-tab");
      switchTab(tabId);
    });
  });

  // 5. Theme Toggle
  const savedTheme = localStorage.getItem("scam_shield_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  themeToggle.querySelector(".theme-icon").textContent = savedTheme === "dark" ? "🌙" : "☀️";

  themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", nextTheme);
    localStorage.setItem("scam_shield_theme", nextTheme);
    themeToggle.querySelector(".theme-icon").textContent = nextTheme === "dark" ? "🌙" : "☀️";
  });

  // 6. Character Counter & Input Handlers
  smsInput.addEventListener("input", () => {
    smsCharCounter.textContent = `${smsInput.value.length} chars`;
  });

  urlPasteBtn.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        urlInput.value = text.trim();
        showToast("URL pasted from clipboard", "info");
      }
    } catch {
      showToast("Clipboard access denied. Please paste manually.", "error");
    }
  });

  urlClearBtn.addEventListener("click", () => {
    urlInput.value = "";
    urlInput.focus();
  });

  smsPasteBtn.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        smsInput.value = text;
        smsCharCounter.textContent = `${text.length} chars`;
        showToast("Message pasted from clipboard", "info");
      }
    } catch {
      showToast("Clipboard access denied. Please paste manually.", "error");
    }
  });

  smsClearBtn.addEventListener("click", () => {
    smsInput.value = "";
    smsCharCounter.textContent = "0 chars";
    smsInput.focus();
  });

  // Quick URL chip buttons
  document.querySelectorAll(".sample-chip:not(.sms-sample)").forEach(chip => {
    chip.addEventListener("click", () => {
      const sampleUrl = chip.getAttribute("data-sample");
      urlInput.value = sampleUrl;
      handleUrlScan(sampleUrl);
    });
  });

  // Quick SMS chip buttons
  document.querySelectorAll(".sample-chip.sms-sample").forEach(chip => {
    chip.addEventListener("click", () => {
      const idx = parseInt(chip.getAttribute("data-index"), 10);
      const sample = window.TEST_SAMPLES?.sms[idx];
      if (sample) {
        smsInput.value = sample.text;
        smsCharCounter.textContent = `${sample.text.length} chars`;
        handleSmsScan(sample.text);
      }
    });
  });

  // 7. Scanning Logic (URL & SMS)
  async function handleUrlScan(rawUrl) {
    if (!rawUrl || rawUrl.trim().length === 0) {
      showToast("Please enter a website URL or domain", "error");
      return;
    }

    setLoading(urlScanBtn, true, "Scanning...");

    try {
      const geminiKey = apiService.getGeminiApiKey();

      // Priority 1: Query Python Backend API
      try {
        const backendResp = await fetch("/api/scan/url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: rawUrl, apiKey: geminiKey || "" })
        });
        if (backendResp.ok) {
          const backendData = await backendResp.json();
          renderResult(backendData);
          saveToHistory(backendData);
          setLoading(urlScanBtn, false, "Scan Website");
          return;
        }
      } catch (backendErr) {
        // Backend offline or running purely as file://, proceed to client fallback
        console.log("Python backend not responding, using client fallback:", backendErr.message);
      }

      // Priority 2: Client-Side Heuristics Fallback
      const heuristicRes = heuristicEngine.analyzeUrl(rawUrl);
      if (!heuristicRes.success) {
        showToast(heuristicRes.error, "error");
        setLoading(urlScanBtn, false, "Scan Website");
        return;
      }

      let combinedResult = { ...heuristicRes };
      let intelStatus = "Not Checked";
      let intelDetail = "Threat DB lookup disabled in settings.";

      // Step B: Query URLhaus Database if enabled
      if (state.settings.useUrlhaus) {
        intelStatus = "Querying URLhaus...";
        const urlhausRes = await apiService.queryUrlhaus(heuristicRes.target);
        if (urlhausRes.queried) {
          if (urlhausRes.found) {
            intelStatus = "MALICIOUS (Listed in URLhaus)";
            intelDetail = `Flagged in abuse.ch database! Threat: ${urlhausRes.threat}. Date Added: ${urlhausRes.dateAdded || "Recent"}`;
            combinedResult.riskScore = Math.max(combinedResult.riskScore, 95);
            combinedResult.verdict = "HIGH RISK / DANGEROUS";
            combinedResult.riskLevel = "high";
            combinedResult.redFlags.unshift({
              type: "URLHAUS_KNOWN_THREAT",
              title: "Active Threat in URLhaus Malware Registry",
              detail: `This URL is confirmed in the abuse.ch threat database as active malicious infrastructure (${urlhausRes.threat}).`,
              severity: "critical"
            });
          } else {
            intelStatus = "Clean (URLhaus)";
            intelDetail = "No active malware or phishing records found in URLhaus registry.";
          }
        } else {
          intelStatus = "Offline / Skipped";
          intelDetail = "Could not query external URLhaus endpoint (offline or CORS).";
        }
      }

      // Step C: Query Google Gemini AI if enabled & key available
      if (geminiKey && state.settings.useGeminiAI) {
        const aiRes = await apiService.analyzeWithGemini("Website URL", rawUrl, {
          heuristicScore: combinedResult.riskScore,
          flagsFound: combinedResult.redFlags.map(f => f.title)
        });

        if (aiRes.success && aiRes.data) {
          const aiData = aiRes.data;
          // Merge AI insights with heuristic findings
          combinedResult.engine = aiRes.engine;
          combinedResult.summary = aiData.summary;
          combinedResult.category = aiData.threatCategory || "Website Analysis";
          combinedResult.confidence = aiData.confidence || "HIGH";

          // Weighted average if AI score provided
          if (typeof aiData.riskScore === "number") {
            // Give AI 65% weight, heuristics 35% weight
            const blended = Math.round((aiData.riskScore * 0.65) + (combinedResult.riskScore * 0.35));
            combinedResult.riskScore = Math.max(0, Math.min(100, blended));
          }

          if (aiData.verdict) {
            combinedResult.verdict = aiData.verdict;
          }

          if (Array.isArray(aiData.redFlags) && aiData.redFlags.length > 0) {
            // Prepend AI red flags
            combinedResult.redFlags = [...aiData.redFlags, ...combinedResult.redFlags];
          }

          if (Array.isArray(aiData.recommendations) && aiData.recommendations.length > 0) {
            combinedResult.recommendations = aiData.recommendations;
          }
          if (Array.isArray(aiData.trustFactors) && aiData.trustFactors.length > 0) {
            combinedResult.trustFactors = [...combinedResult.trustFactors, ...aiData.trustFactors];
          }
        }
      }

      // Finalize display
      combinedResult.intelStatus = intelStatus;
      combinedResult.intelDetail = intelDetail;
      combinedResult.timestamp = new Date().toISOString();

      renderResult(combinedResult);
      saveToHistory(combinedResult);
    } catch (err) {
      console.error(err);
      showToast(`Scan error: ${err.message}`, "error");
    } finally {
      setLoading(urlScanBtn, false, "Scan Website");
    }
  }

  async function handleSmsScan(messageText) {
    if (!messageText || messageText.trim().length === 0) {
      showToast("Please enter an SMS or message text to analyze", "error");
      return;
    }

    setLoading(smsScanBtn, true, "Analyzing Message...");

    try {
      const geminiKey = apiService.getGeminiApiKey();

      // Priority 1: Query Python Backend API
      try {
        const backendResp = await fetch("/api/scan/sms", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: messageText, apiKey: geminiKey || "" })
        });
        if (backendResp.ok) {
          const backendData = await backendResp.json();
          renderResult(backendData);
          saveToHistory(backendData);
          setLoading(smsScanBtn, false, "Analyze Message");
          return;
        }
      } catch (backendErr) {
        console.log("Python backend not responding, using client fallback:", backendErr.message);
      }

      // Priority 2: Client-Side Heuristic & Smishing analysis fallback
      const heuristicRes = heuristicEngine.analyzeSms(messageText);
      if (!heuristicRes.success) {
        showToast(heuristicRes.error, "error");
        setLoading(smsScanBtn, false, "Analyze Message");
        return;
      }

      let combinedResult = { ...heuristicRes };
      let intelStatus = "Evaluated";
      let intelDetail = `${heuristicRes.extractedUrls.length} embedded link(s) inspected.`;

      // Step B: If SMS contains links, also check them against URLhaus
      if (state.settings.useUrlhaus && heuristicRes.extractedUrls.length > 0) {
        const firstUrl = heuristicRes.extractedUrls[0];
        const urlhausRes = await apiService.queryUrlhaus(firstUrl);
        if (urlhausRes.queried && urlhausRes.found) {
          intelStatus = "MALICIOUS LINK FOUND";
          intelDetail = `Embedded URL (${firstUrl}) is listed in URLhaus malware database!`;
          combinedResult.riskScore = Math.max(combinedResult.riskScore, 95);
          combinedResult.verdict = "HIGH RISK SCAM / SMISHING";
          combinedResult.riskLevel = "high";
          combinedResult.redFlags.unshift({
            type: "URLHAUS_SMS_PAYLOAD",
            title: "Embedded Link Confirmed in URLhaus Threat DB",
            detail: `The link contained in this SMS (${firstUrl}) is indexed in abuse.ch threat intelligence.`,
            severity: "critical"
          });
        }
      }

      // Step C: Query Google Gemini AI for deep semantic reasoning
      if (geminiKey && state.settings.useGeminiAI) {
        const aiRes = await apiService.analyzeWithGemini("SMS / Text Message", messageText, {
          heuristicScore: combinedResult.riskScore,
          extractedLinks: combinedResult.extractedUrls,
          detectedCategories: combinedResult.categories
        });

        if (aiRes.success && aiRes.data) {
          const aiData = aiRes.data;
          combinedResult.engine = aiRes.engine;
          combinedResult.summary = aiData.summary;
          combinedResult.category = aiData.threatCategory || combinedResult.categories[0] || "Smishing";
          combinedResult.confidence = aiData.confidence || "HIGH";

          if (typeof aiData.riskScore === "number") {
            const blended = Math.round((aiData.riskScore * 0.7) + (combinedResult.riskScore * 0.3));
            combinedResult.riskScore = Math.max(0, Math.min(100, blended));
          }

          if (aiData.verdict) {
            combinedResult.verdict = aiData.verdict;
          }

          if (Array.isArray(aiData.redFlags) && aiData.redFlags.length > 0) {
            combinedResult.redFlags = [...aiData.redFlags, ...combinedResult.redFlags];
          }

          if (Array.isArray(aiData.recommendations) && aiData.recommendations.length > 0) {
            combinedResult.recommendations = aiData.recommendations;
          }
          if (Array.isArray(aiData.trustFactors) && aiData.trustFactors.length > 0) {
            combinedResult.trustFactors = [...combinedResult.trustFactors, ...aiData.trustFactors];
          }
        }
      }

      combinedResult.target = messageText;
      combinedResult.intelStatus = intelStatus;
      combinedResult.intelDetail = intelDetail;
      combinedResult.timestamp = new Date().toISOString();

      renderResult(combinedResult);
      saveToHistory(combinedResult);
    } catch (err) {
      console.error(err);
      showToast(`Scan error: ${err.message}`, "error");
    } finally {
      setLoading(smsScanBtn, false, "Analyze Message");
    }
  }

  function setLoading(btn, isLoading, defaultText) {
    const textSpan = btn.querySelector(".btn-text");
    const spinner = btn.querySelector(".btn-spinner");
    if (isLoading) {
      btn.disabled = true;
      if (textSpan) textSpan.textContent = "Scanning...";
      if (spinner) spinner.classList.remove("hidden");
    } else {
      btn.disabled = false;
      if (textSpan) textSpan.textContent = defaultText;
      if (spinner) spinner.classList.add("hidden");
    }
  }

  // 8. Form Submit Listeners
  urlForm.addEventListener("submit", (e) => {
    e.preventDefault();
    handleUrlScan(urlInput.value);
  });

  smsForm.addEventListener("submit", (e) => {
    e.preventDefault();
    handleSmsScan(smsInput.value);
  });

  // 9. Render Assessment Results
  function renderResult(data) {
    state.currentResult = data;
    resultSection.classList.remove("hidden");

    // Header info
    resTypeBadge.textContent = data.targetType;
    resTargetText.textContent = data.target;
    resEngineBadge.textContent = data.engine || "Heuristic Engine";
    resTimeBadge.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    // Animate Gauge
    const score = data.riskScore || 0;
    resScoreValue.textContent = score;

    // SVG semi-circle arc calculation: total length is approx 251.2
    const totalArc = 251.2;
    const offset = totalArc - (totalArc * (score / 100));
    gaugeFillPath.style.strokeDashoffset = offset;

    // Colorize gauge & verdict banner
    resVerdictBanner.className = "verdict-banner";
    if (score >= 65) {
      gaugeFillPath.style.stroke = "var(--color-danger)";
      resVerdictBanner.classList.add("verdict-danger");
      resVerdictBanner.textContent = data.verdict || "HIGH RISK / DANGEROUS";
    } else if (score >= 25) {
      gaugeFillPath.style.stroke = "var(--color-warning)";
      resVerdictBanner.classList.add("verdict-warning");
      resVerdictBanner.textContent = data.verdict || "SUSPICIOUS";
    } else {
      gaugeFillPath.style.stroke = "var(--color-safe)";
      resVerdictBanner.classList.add("verdict-safe");
      resVerdictBanner.textContent = data.verdict || "SAFE";
    }

    resCategoryPill.textContent = data.category || (data.categories ? data.categories.join(", ") : "Cyber Analysis");

    // Threat Intel box
    resIntelStatus.textContent = data.intelStatus || "Checked";
    resIntelDetail.textContent = data.intelDetail || "No threat entries flagged.";

    // Executive Summary
    if (data.summary) {
      resSummaryText.textContent = data.summary;
    } else {
      if (score >= 65) {
        resSummaryText.textContent = `Severe threat detected (${score}% risk). Multiple deceptive indicators confirm high probability of fraudulent intent or malicious phishing.`;
      } else if (score >= 25) {
        resSummaryText.textContent = `Moderate threat indicators detected (${score}% risk). The target exhibits suspicious attributes. Exercise extreme caution.`;
      } else {
        resSummaryText.textContent = `No significant malicious patterns detected (${score}% risk). The target appears normal, but standard cybersecurity diligence is advised.`;
      }
    }

    // Red Flags List
    const flags = data.redFlags || [];
    resFlagsCount.textContent = flags.length;
    resFlagsList.innerHTML = "";

    if (flags.length === 0) {
      resFlagsList.innerHTML = `<div class="flag-item" style="border-color: rgba(16, 185, 129, 0.3);"><div class="flag-title" style="color: var(--color-safe);">✓ No immediate red flags identified.</div></div>`;
    } else {
      flags.forEach(flag => {
        const item = document.createElement("div");
        item.className = "flag-item";
        const sevClass = `sev-${flag.severity || "medium"}`;

        item.innerHTML = `
          <div class="flag-header">
            <span class="flag-title">⚠️ ${flag.title}</span>
            <span class="flag-severity ${sevClass}">${flag.severity || "warning"}</span>
          </div>
          <p class="flag-detail">${flag.detail}</p>
        `;
        resFlagsList.appendChild(item);
      });
    }

    // Trust Factors
    const trust = data.trustFactors || [];
    if (trust.length > 0) {
      resTrustBox.classList.remove("hidden");
      resTrustList.innerHTML = "";
      trust.forEach(tf => {
        const li = document.createElement("li");
        li.className = "trust-item";
        li.innerHTML = `<span class="trust-icon">✓</span><span>${tf}</span>`;
        resTrustList.appendChild(li);
      });
    } else {
      resTrustBox.classList.add("hidden");
    }

    // Extracted URLs (for SMS)
    if (data.extractedUrls && data.extractedUrls.length > 0) {
      resExtractedUrlsBox.classList.remove("hidden");
      resExtractedUrlsList.innerHTML = "";
      data.extractedUrls.forEach(url => {
        const div = document.createElement("div");
        div.className = "extracted-url-pill";
        div.innerHTML = `
          <span class="extracted-url-link">${url}</span>
          <button type="button" class="btn btn-outline btn-sm scan-extracted-btn" data-url="${url}">Inspect URL</button>
        `;
        resExtractedUrlsList.appendChild(div);
      });

      // Bind inspect buttons
      resExtractedUrlsList.querySelectorAll(".scan-extracted-btn").forEach(btn => {
        btn.addEventListener("click", () => {
          const targetUrl = btn.getAttribute("data-url");
          switchTab("url-scanner");
          urlInput.value = targetUrl;
          handleUrlScan(targetUrl);
        });
      });
    } else {
      resExtractedUrlsBox.classList.add("hidden");
    }

    // Recommendations List
    const actions = data.recommendations || [];
    resActionsList.innerHTML = "";
    actions.forEach(act => {
      const li = document.createElement("li");
      li.className = "action-item";
      li.innerHTML = `<span class="action-icon">🛡️</span><span>${act}</span>`;
      resActionsList.appendChild(li);
    });

    // Smooth scroll to result
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // 10. Copy Report & Dismiss
  resCopyReportBtn.addEventListener("click", () => {
    if (!state.currentResult) return;
    const r = state.currentResult;
    const report = `
=============================================
SCAMSHIELD AI - THREAT ASSESSMENT REPORT
=============================================
Target Type : ${r.targetType}
Target      : ${r.target}
Risk Score  : ${r.riskScore} / 100
Verdict     : ${r.verdict}
Engine      : ${r.engine}
Date/Time   : ${r.timestamp}

EXECUTIVE SUMMARY:
${resSummaryText.textContent}

RED FLAGS IDENTIFIED (${(r.redFlags || []).length}):
${(r.redFlags || []).map(f => ` - [${(f.severity || "medium").toUpperCase()}] ${f.title}: ${f.detail}`).join("\n")}

RECOMMENDED ACTIONS:
${(r.recommendations || []).map(a => ` - ${a}`).join("\n")}
=============================================
Generated by ScamShield AI
    `.trim();

    navigator.clipboard.writeText(report).then(() => {
      showToast("Threat report copied to clipboard!", "success");
    }).catch(() => {
      showToast("Failed to copy to clipboard", "error");
    });
  });

  resDismissBtn.addEventListener("click", () => {
    resultSection.classList.add("hidden");
  });

  // 11. Scan History Management
  function saveToHistory(result) {
    const item = {
      id: "scan_" + Date.now(),
      targetType: result.targetType,
      target: result.target,
      riskScore: result.riskScore,
      verdict: result.verdict,
      engine: result.engine,
      timestamp: result.timestamp || new Date().toISOString(),
      fullResult: result
    };

    state.history.unshift(item);
    if (state.history.length > (state.settings.maxHistoryItems || 30)) {
      state.history.pop();
    }

    try {
      localStorage.setItem(CONFIG.STORAGE_KEYS.HISTORY, JSON.stringify(state.history));
    } catch (e) {
      console.warn("Error saving history:", e);
    }

    updateHistoryBadge();
    if (state.currentTab === "history-view") {
      renderHistoryTable();
    }
  }

  function renderHistoryTable() {
    historyTbody.innerHTML = "";
    if (state.history.length === 0) {
      historyEmpty.classList.remove("hidden");
      document.getElementById("history-table").classList.add("hidden");
      return;
    }

    historyEmpty.classList.add("hidden");
    document.getElementById("history-table").classList.remove("hidden");

    state.history.forEach((entry, index) => {
      const tr = document.createElement("tr");

      let verdictColor = "var(--color-safe)";
      if (entry.riskScore >= 65) verdictColor = "var(--color-danger)";
      else if (entry.riskScore >= 25) verdictColor = "var(--color-warning)";

      const formattedDate = new Date(entry.timestamp).toLocaleDateString([], {
        month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
      });

      tr.innerHTML = `
        <td><span class="sample-type-badge ${entry.targetType === 'URL' ? 'sample-type-url' : 'sample-type-sms'}">${entry.targetType}</span></td>
        <td class="hist-target-cell" title="${escapeHtml(entry.target)}">${escapeHtml(entry.target)}</td>
        <td><strong>${entry.riskScore}%</strong></td>
        <td><span style="color: ${verdictColor}; font-weight: 700;">${entry.verdict}</span></td>
        <td><span style="font-size: 0.78rem;">${entry.engine || "Heuristic"}</span></td>
        <td style="font-size: 0.78rem;">${formattedDate}</td>
        <td>
          <button type="button" class="btn btn-outline btn-sm hist-view-btn" data-index="${index}">Inspect</button>
        </td>
      `;
      historyTbody.appendChild(tr);
    });

    // Inspect historical scan
    historyTbody.querySelectorAll(".hist-view-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const idx = parseInt(btn.getAttribute("data-index"), 10);
        const entry = state.history[idx];
        if (entry && entry.fullResult) {
          renderResult(entry.fullResult);
        }
      });
    });
  }

  clearHistoryBtn.addEventListener("click", () => {
    if (confirm("Are you sure you want to clear all scan history?")) {
      state.history = [];
      localStorage.removeItem(CONFIG.STORAGE_KEYS.HISTORY);
      updateHistoryBadge();
      renderHistoryTable();
      showToast("Scan history cleared", "info");
    }
  });

  exportHistoryBtn.addEventListener("click", () => {
    if (state.history.length === 0) {
      showToast("No history items to export", "error");
      return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.history, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `scam_shield_history_${new Date().toISOString().slice(0,10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast("History exported as JSON", "success");
  });

  function escapeHtml(string) {
    if (!string) return "";
    return String(string)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // 12. Render Sample Scams Gallery
  function renderSampleGallery() {
    if (!window.TEST_SAMPLES) return;
    samplesGrid.innerHTML = "";

    // URLs samples
    (window.TEST_SAMPLES.urls || []).forEach(sample => {
      const card = createSampleCard(sample, "URL");
      samplesGrid.appendChild(card);
    });

    // SMS samples
    (window.TEST_SAMPLES.sms || []).forEach(sample => {
      const card = createSampleCard(sample, "SMS");
      samplesGrid.appendChild(card);
    });
  }

  function createSampleCard(sample, type) {
    const card = document.createElement("div");
    card.className = "sample-card";

    let expClass = "exp-safe";
    if (sample.expectedRisk.includes("HIGH")) expClass = "exp-high";
    else if (sample.expectedRisk.includes("SUSP")) expClass = "exp-warn";

    const contentText = type === "URL" ? sample.url : sample.text;

    card.innerHTML = `
      <div>
        <div class="sample-card-header">
          <h4 class="sample-card-title">${sample.name}</h4>
          <span class="sample-type-badge ${type === 'URL' ? 'sample-type-url' : 'sample-type-sms'}">${type}</span>
        </div>
        <p class="sample-card-desc">${sample.description}</p>
      </div>

      <div class="sample-content-preview">${escapeHtml(contentText)}</div>

      <div class="sample-card-footer">
        <span class="sample-expected ${expClass}">Expected: ${sample.expectedRisk}</span>
        <button type="button" class="btn btn-primary btn-sm test-sample-btn">Test Sample</button>
      </div>
    `;

    card.querySelector(".test-sample-btn").addEventListener("click", () => {
      if (type === "URL") {
        switchTab("url-scanner");
        urlInput.value = sample.url;
        handleUrlScan(sample.url);
      } else {
        switchTab("sms-scanner");
        smsInput.value = sample.text;
        smsCharCounter.textContent = `${sample.text.length} chars`;
        handleSmsScan(sample.text);
      }
    });

    return card;
  }

  // 13. API Settings Modal
  apiSettingsBtn.addEventListener("click", () => {
    // Load current values
    const currentKey = apiService.getGeminiApiKey();
    geminiApiKeyInput.value = currentKey || "";
    geminiModelSelect.value = state.settings.geminiModel || "gemini-1.5-flash";
    toggleUrlhaus.checked = state.settings.useUrlhaus !== false;
    geminiTestFeedback.textContent = "";

    apiModal.classList.remove("hidden");
  });

  closeModalBtn.addEventListener("click", () => {
    apiModal.classList.add("hidden");
  });

  apiModal.addEventListener("click", (e) => {
    if (e.target === apiModal) {
      apiModal.classList.add("hidden");
    }
  });

  toggleKeyVisibilityBtn.addEventListener("click", () => {
    const isPass = geminiApiKeyInput.type === "password";
    geminiApiKeyInput.type = isPass ? "text" : "password";
    toggleKeyVisibilityBtn.textContent = isPass ? "🔒" : "👁️";
  });

  testGeminiKeyBtn.addEventListener("click", async () => {
    const key = geminiApiKeyInput.value.trim();
    if (!key) {
      geminiTestFeedback.className = "test-feedback feedback-error";
      geminiTestFeedback.textContent = "Please enter a key to test";
      return;
    }

    geminiTestFeedback.className = "test-feedback";
    geminiTestFeedback.textContent = "Testing connection...";
    testGeminiKeyBtn.disabled = true;

    const res = await apiService.testGeminiKey(key);
    testGeminiKeyBtn.disabled = false;

    if (res.success) {
      geminiTestFeedback.className = "test-feedback feedback-success";
      geminiTestFeedback.textContent = "✓ Connected successfully!";
    } else {
      geminiTestFeedback.className = "test-feedback feedback-error";
      geminiTestFeedback.textContent = res.message;
    }
  });

  saveSettingsBtn.addEventListener("click", () => {
    const newKey = geminiApiKeyInput.value.trim();
    apiService.setGeminiApiKey(newKey);

    state.settings.geminiModel = geminiModelSelect.value;
    state.settings.useUrlhaus = toggleUrlhaus.checked;
    state.settings.useGeminiAI = Boolean(newKey);

    localStorage.setItem(CONFIG.STORAGE_KEYS.SETTINGS, JSON.stringify(state.settings));
    updateApiStatusIndicator();
    apiModal.classList.add("hidden");

    showToast("Settings saved successfully", "success");
  });

  clearApiKeyBtn.addEventListener("click", () => {
    if (confirm("Remove saved Gemini API Key? The app will continue using the offline heuristic engine.")) {
      apiService.setGeminiApiKey(null);
      geminiApiKeyInput.value = "";
      state.settings.useGeminiAI = false;
      localStorage.setItem(CONFIG.STORAGE_KEYS.SETTINGS, JSON.stringify(state.settings));
      updateApiStatusIndicator();
      geminiTestFeedback.textContent = "";
      showToast("API Key removed. Local heuristic engine active.", "info");
    }
  });

  // Initial Boot
  updateApiStatusIndicator();
  updateHistoryBadge();
  renderSampleGallery();
});
