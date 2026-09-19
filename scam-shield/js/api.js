/**
 * ScamShield AI - External Threat Intelligence & AI API Integration Service
 * Integrates Google Gemini Generative AI and URLhaus (abuse.ch) Threat DB.
 */

class ApiService {
  constructor() {
    this.config = window.CONFIG || {};
  }

  /**
   * Retrieves saved Gemini API key from localStorage
   */
  getGeminiApiKey() {
    const key = localStorage.getItem(this.config.STORAGE_KEYS?.GEMINI_API_KEY || "scam_shield_gemini_key");
    return key ? key.trim() : null;
  }

  /**
   * Saves Gemini API key
   */
  setGeminiApiKey(key) {
    if (!key) {
      localStorage.removeItem(this.config.STORAGE_KEYS?.GEMINI_API_KEY || "scam_shield_gemini_key");
    } else {
      localStorage.setItem(this.config.STORAGE_KEYS?.GEMINI_API_KEY || "scam_shield_gemini_key", key.trim());
    }
  }

  /**
   * Tests if a Gemini API Key is valid
   */
  async testGeminiKey(apiKey) {
    if (!apiKey || apiKey.trim().length === 0) {
      return { success: false, message: "Please provide an API key to test." };
    }

    const testUrl = `${this.config.API_ENDPOINTS.GEMINI_BASE}/gemini-1.5-flash:generateContent?key=${encodeURIComponent(apiKey.trim())}`;
    try {
      const response = await fetch(testUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: "Respond with the single word: OK" }]
          }]
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errMsg = errorData.error?.message || `HTTP ${response.status}: ${response.statusText}`;
        return { success: false, message: `API Key test failed: ${errMsg}` };
      }

      return { success: true, message: "Connection successful! Gemini API is active." };
    } catch (err) {
      return { success: false, message: `Network error: ${err.message}` };
    }
  }

  /**
   * Queries URLhaus (abuse.ch) Threat Database for known malicious URLs
   */
  async queryUrlhaus(urlToCheck) {
    try {
      const endpoint = this.config.API_ENDPOINTS.URLHAUS_API;
      const formData = new URLSearchParams();
      formData.append("url", urlToCheck);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: formData.toString(),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return { queried: true, found: false, note: "URLhaus returned non-200 status." };
      }

      const data = await response.json();
      if (data.query_status === "ok") {
        return {
          queried: true,
          found: true,
          status: data.url_status,
          threat: data.threat || "Malware / Phishing Distribution",
          tags: data.tags || [],
          reporter: data.reporter,
          dateAdded: data.date_added
        };
      }

      return { queried: true, found: false, queryStatus: data.query_status };
    } catch (err) {
      // URLhaus might be blocked by client ad-blocker or CORS; fail gracefully
      console.warn("URLhaus query skipped or failed:", err.message);
      return { queried: false, error: err.message };
    }
  }

  /**
   * Deep AI Threat Analysis using Google Gemini Generative AI
   */
  async analyzeWithGemini(targetType, content, heuristicContext = null) {
    const apiKey = this.getGeminiApiKey();
    if (!apiKey) {
      return {
        available: false,
        message: "No Gemini API Key configured. Analysis performed using Heuristic Rule Engine."
      };
    }

    const modelName = this.config.DEFAULT_SETTINGS?.geminiModel || "gemini-1.5-flash";
    const endpoint = `${this.config.API_ENDPOINTS.GEMINI_BASE}/${modelName}:generateContent?key=${encodeURIComponent(apiKey)}`;

    const promptText = `
You are ScamShield AI, an elite cybersecurity, anti-phishing, and social engineering threat intelligence system.
Analyze the following ${targetType} item for potential fraud, phishing, smishing, scam lure, brand impersonation, or malicious intent.

TARGET TYPE: ${targetType}
TARGET CONTENT:
"""
${content}
"""

HEURISTIC CONTEXT (Pre-screen indicators):
${heuristicContext ? JSON.stringify(heuristicContext) : "None"}

TASK:
Provide a rigorous cybersecurity evaluation.
Respond ONLY with a valid JSON object (no surrounding conversational text, no preamble) adhering strictly to this schema:
{
  "riskScore": <number between 0 and 100>,
  "verdict": "<SAFE | SUSPICIOUS | DANGEROUS>",
  "threatCategory": "<string: e.g. Smishing, Bank Impersonation, Credential Harvest, Fake Delivery, Lottery Fraud, Legitimate>",
  "confidence": "<HIGH | MEDIUM | LOW>",
  "summary": "<Concise 1-2 sentence executive threat summary>",
  "redFlags": [
    {
      "title": "<Specific indicator title>",
      "detail": "<Clear explanation of why this indicates deception>",
      "severity": "<critical | high | medium | low>"
    }
  ],
  "trustFactors": [
    "<Legitimate aspect or reassuring security indicator>"
  ],
  "recommendations": [
    "<Concrete protective action user should take>"
  ]
}
`;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);

      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: promptText }]
          }],
          generationConfig: {
            temperature: 0.1,
            topK: 1
          }
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.error?.message || `API error ${response.status}`);
      }

      const data = await response.json();
      const rawResponse = data.candidates?.[0]?.content?.parts?.[0]?.text || "";

      // Extract JSON from markdown or raw string
      let jsonString = rawResponse.trim();
      if (jsonString.includes("```json")) {
        jsonString = jsonString.split("```json")[1].split("```")[0].trim();
      } else if (jsonString.includes("```")) {
        jsonString = jsonString.split("```")[1].split("```")[0].trim();
      }

      const aiResult = JSON.parse(jsonString);

      return {
        available: true,
        success: true,
        engine: `Gemini AI (${modelName})`,
        data: aiResult
      };
    } catch (err) {
      console.error("Gemini API scan failed:", err);
      return {
        available: true,
        success: false,
        error: err.message,
        message: `Gemini API query failed: ${err.message}. Showing local heuristic result instead.`
      };
    }
  }
}

// Expose globally
if (typeof window !== "undefined") {
  window.ApiService = ApiService;
}
