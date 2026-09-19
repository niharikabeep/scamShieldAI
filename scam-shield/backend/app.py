"""
ScamShield AI - Flask REST API Backend & Threat Intelligence Server
"""

import os
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from .config import Config, BASE_DIR
from .detector import ScamDetector
from .api_service import ApiService
from .storage import Storage

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
CORS(app)

# Initialize Database on startup
Storage.init_db()

@app.route("/")
def index():
    """Serves the frontend single page app"""
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/<path:path>")
def static_files(path):
    """Serves static CSS, JS, and asset files"""
    return send_from_directory(BASE_DIR, path)

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint and engine status"""
    return jsonify({
        "status": "healthy",
        "service": "ScamShield AI Python Backend",
        "gemini_configured": bool(Config.GEMINI_API_KEY),
        "urlhaus_enabled": True
    })

@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    """
    Main URL threat assessment endpoint.
    Performs multi-layer inspection:
    1. Python Heuristics (Typosquatting, TLDs, IP, Obfuscation)
    2. URLhaus Threat Database Query (abuse.ch API)
    3. DNS Resolution check
    4. Google Gemini Generative AI (if key configured or supplied)
    """
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    client_key = data.get("apiKey", "").strip()

    if not url:
        return jsonify({"success": False, "error": "No URL provided."}), 400

    # Step 1: Server-side Heuristic Analysis
    res = ScamDetector.analyze_url(url)
    if not res.get("success"):
        return jsonify(res), 400

    intel_status = "Checked (Clean)"
    intel_detail = "No active malware or phishing entries found in URLhaus registry."

    # Step 2: Query URLhaus API
    urlhaus_data = ApiService.query_urlhaus(res["target"])
    if urlhaus_data.get("queried"):
        if urlhaus_data.get("found"):
            intel_status = "MALICIOUS (Listed in URLhaus)"
            intel_detail = f"Confirmed active threat in abuse.ch database! Threat: {urlhaus_data.get('threat')}."
            res["riskScore"] = max(res["riskScore"], 95)
            res["verdict"] = "HIGH RISK / DANGEROUS"
            res["redFlags"].insert(0, {
                "title": "Confirmed in URLhaus Threat Database",
                "detail": f"Active threat listed by abuse.ch: {urlhaus_data.get('threat')}.",
                "severity": "critical"
            })

    # Step 3: DNS Resolution Check
    hostname = res.get("hostname", "")
    if hostname and not ScamDetector.is_ip_address(hostname):
        dns_res = ApiService.check_dns_resolution(hostname)
        if not dns_res.get("resolves"):
            res["riskScore"] = min(100, res["riskScore"] + 15)
            res["redFlags"].append({
                "title": "DNS Lookup Failed (Non-Existent Domain)",
                "detail": f"Host '{hostname}' could not be resolved. Scammers frequently register throwaway domains that disappear quickly.",
                "severity": "medium"
            })

    # Step 4: Google Gemini AI Deep Semantic Analysis (if key available)
    gemini_res = ApiService.analyze_with_gemini(
        target_type="Website URL",
        content=url,
        heuristic_context={"riskScore": res["riskScore"], "redFlags": [f["title"] for f in res["redFlags"]]},
        api_key=client_key or Config.GEMINI_API_KEY
    )

    if gemini_res.get("success") and gemini_res.get("data"):
        ai = gemini_res["data"]
        res["engine"] = f"Python Backend + {gemini_res['engine']}"
        res["summary"] = ai.get("summary")
        res["category"] = ai.get("threatCategory", res["category"])
        if isinstance(ai.get("riskScore"), int):
            # Blend AI score with heuristics
            blended = round((ai["riskScore"] * 0.65) + (res["riskScore"] * 0.35))
            res["riskScore"] = max(0, min(100, blended))
        if ai.get("verdict"):
            res["verdict"] = ai["verdict"]
        if ai.get("redFlags"):
            res["redFlags"] = ai["redFlags"] + res["redFlags"]
        if ai.get("recommendations"):
            res["recommendations"] = ai["recommendations"]
        if ai.get("trustFactors"):
            res["trustFactors"] = ai["trustFactors"] + res["trustFactors"]
    else:
        res["engine"] = "Python Backend + URLhaus API"

    res["intelStatus"] = intel_status
    res["intelDetail"] = intel_detail

    # Step 5: Save to SQLite Database
    scan_id = Storage.save_scan(res)
    res["id"] = scan_id

    return jsonify(res)

@app.route("/api/scan/sms", methods=["POST"])
def scan_sms():
    """
    Main SMS/Message threat assessment endpoint.
    Performs multi-layer inspection:
    1. Python Smishing Heuristics (Urgency, OTP lures, Financial bait)
    2. Embedded link extraction & URLhaus lookup
    3. Google Gemini Generative AI for social engineering detection
    """
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    client_key = data.get("apiKey", "").strip()

    if not message:
        return jsonify({"success": False, "error": "No message text provided."}), 400

    # Step 1: Server-side SMS Analysis
    res = ScamDetector.analyze_sms(message)
    if not res.get("success"):
        return jsonify(res), 400

    intel_status = "Evaluated"
    intel_detail = f"{len(res.get('extractedUrls', []))} embedded link(s) inspected."

    # Step 2: Check any extracted URLs against URLhaus
    if res.get("extractedUrls"):
        first_link = res["extractedUrls"][0]
        urlhaus_data = ApiService.query_urlhaus(first_link)
        if urlhaus_data.get("queried") and urlhaus_data.get("found"):
            intel_status = "MALICIOUS LINK FOUND"
            intel_detail = f"Embedded link ({first_link}) is listed in abuse.ch malware database!"
            res["riskScore"] = max(res["riskScore"], 95)
            res["verdict"] = "HIGH RISK SCAM / SMISHING"
            res["redFlags"].insert(0, {
                "title": "Embedded Link Confirmed in URLhaus Threat DB",
                "detail": f"The link contained in this SMS is indexed as malicious: {first_link}.",
                "severity": "critical"
            })

    # Step 3: Google Gemini AI Analysis
    gemini_res = ApiService.analyze_with_gemini(
        target_type="SMS / Text Message",
        content=message,
        heuristic_context={"riskScore": res["riskScore"], "extractedUrls": res.get("extractedUrls", [])},
        api_key=client_key or Config.GEMINI_API_KEY
    )

    if gemini_res.get("success") and gemini_res.get("data"):
        ai = gemini_res["data"]
        res["engine"] = f"Python Backend + {gemini_res['engine']}"
        res["summary"] = ai.get("summary")
        res["category"] = ai.get("threatCategory", res["category"])
        if isinstance(ai.get("riskScore"), int):
            blended = round((ai["riskScore"] * 0.70) + (res["riskScore"] * 0.30))
            res["riskScore"] = max(0, min(100, blended))
        if ai.get("verdict"):
            res["verdict"] = ai["verdict"]
        if ai.get("redFlags"):
            res["redFlags"] = ai["redFlags"] + res["redFlags"]
        if ai.get("recommendations"):
            res["recommendations"] = ai["recommendations"]
        if ai.get("trustFactors"):
            res["trustFactors"] = ai["trustFactors"] + res["trustFactors"]
    else:
        res["engine"] = "Python Backend + URLhaus API"

    res["intelStatus"] = intel_status
    res["intelDetail"] = intel_detail

    # Step 4: Save to SQLite Database
    scan_id = Storage.save_scan(res)
    res["id"] = scan_id

    return jsonify(res)

@app.route("/api/history", methods=["GET"])
def get_history():
    """Fetches persistent scan history from SQLite"""
    limit = request.args.get("limit", 50, type=int)
    history = Storage.get_history(limit)
    return jsonify({"success": True, "history": history})

@app.route("/api/history", methods=["DELETE"])
def clear_history():
    """Clears scan history from SQLite"""
    Storage.clear_history()
    return jsonify({"success": True, "message": "Scan history cleared."})

@app.route("/api/settings/test-key", methods=["POST"])
def test_key():
    """Tests Gemini API key validity"""
    data = request.get_json() or {}
    key = data.get("apiKey", "").strip()
    result = ApiService.test_gemini_key(key)
    return jsonify(result)
