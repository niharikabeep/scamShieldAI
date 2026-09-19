"""
ScamShield AI - Backend External API Integration Service
Calls external threat intelligence APIs (URLhaus abuse.ch & Google Gemini AI).
"""

import json
import socket
import logging
import requests
from urllib.parse import urlparse
from .config import Config

logger = logging.getLogger(__name__)

class ApiService:
    @staticmethod
    def query_urlhaus(url: str) -> dict:
        """
        Queries URLhaus (abuse.ch) Threat Database for known malicious malware/phishing URLs.
        This is a real live threat intelligence API check.
        """
        try:
            payload = {"url": url}
            response = requests.post(
                Config.URLHAUS_API_URL,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=6
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {
                        "queried": True,
                        "found": True,
                        "threat": data.get("threat", "Malware / Phishing Distribution"),
                        "status": data.get("url_status"),
                        "tags": data.get("tags", []),
                        "reporter": data.get("reporter"),
                        "date_added": data.get("date_added")
                    }
                return {"queried": True, "found": False, "status": data.get("query_status")}
            return {"queried": True, "found": False, "note": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.warning(f"URLhaus query error: {e}")
            return {"queried": False, "found": False, "error": str(e)}

    @staticmethod
    def check_dns_resolution(hostname: str) -> dict:
        """
        Checks if the domain resolves to an IP address using socket.
        """
        try:
            ip = socket.gethostbyname(hostname)
            return {"resolves": True, "ip": ip}
        except socket.gaierror:
            return {"resolves": False, "error": "Domain does not resolve via DNS"}
        except Exception as e:
            return {"resolves": False, "error": str(e)}

    @staticmethod
    def analyze_with_gemini(target_type: str, content: str, heuristic_context: dict = None, api_key: str = None) -> dict:
        """
        Deep AI Threat Analysis using Google Gemini Generative AI API.
        """
        key = api_key or Config.GEMINI_API_KEY
        if not key:
            return {
                "available": False,
                "message": "No Gemini API Key configured on server or in request."
            }

        endpoint = f"{Config.GEMINI_BASE_URL}/{Config.DEFAULT_GEMINI_MODEL}:generateContent?key={key}"
        prompt = f"""
You are ScamShield AI, an elite cybersecurity and anti-phishing threat intelligence system.
Analyze the following {target_type} for fraud, scam, smishing, typosquatting, credential harvesting, social engineering, or malicious intent.

TARGET TYPE: {target_type}
TARGET CONTENT:
\"\"\"
{content}
\"\"\"

HEURISTIC PRE-SCREEN CONTEXT:
{json.dumps(heuristic_context or {})}

TASK:
Provide a rigorous cybersecurity threat evaluation.
Respond ONLY with a valid JSON object (no markdown wrapping, no introductory commentary) conforming strictly to this format:
{{
  "riskScore": <integer between 0 and 100>,
  "verdict": "<SAFE | SUSPICIOUS | DANGEROUS>",
  "threatCategory": "<e.g. Smishing, Bank Impersonation, Credential Harvest, Delivery Scam, Lottery Fraud, Legitimate>",
  "confidence": "<HIGH | MEDIUM | LOW>",
  "summary": "<1-2 concise sentence executive threat summary>",
  "redFlags": [
    {{
      "title": "<Indicator Title>",
      "detail": "<Clear explanation of why this is suspicious>",
      "severity": "<critical | high | medium | low>"
    }}
  ],
  "trustFactors": [
    "<Positive reassuring indicator, if any>"
  ],
  "recommendations": [
    "<Specific concrete action user should take>"
  ]
}}
"""
        try:
            response = requests.post(
                endpoint,
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.1, "topK": 1}
                },
                timeout=15
            )
            if response.status_code != 200:
                err_data = response.json() if response.content else {}
                err_msg = err_data.get("error", {}).get("message", f"HTTP {response.status_code}")
                return {"available": True, "success": False, "error": err_msg}

            data = response.json()
            raw_text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")

            # Strip markdown if present
            clean_json = raw_text.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].split("```")[0].strip()

            parsed = json.loads(clean_json)
            return {
                "available": True,
                "success": True,
                "engine": f"Gemini AI ({Config.DEFAULT_GEMINI_MODEL})",
                "data": parsed
            }
        except Exception as e:
            logger.error(f"Gemini API analysis failed: {e}")
            return {"available": True, "success": False, "error": str(e)}

    @staticmethod
    def test_gemini_key(api_key: str) -> dict:
        """
        Tests whether a provided Google Gemini API Key is valid and active.
        """
        if not api_key:
            return {"success": False, "message": "API key is required."}

        endpoint = f"{Config.GEMINI_BASE_URL}/{Config.DEFAULT_GEMINI_MODEL}:generateContent?key={api_key.strip()}"
        try:
            resp = requests.post(
                endpoint,
                headers={"Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": "Say OK"}]}]},
                timeout=8
            )
            if resp.status_code == 200:
                return {"success": True, "message": "Connection verified! Gemini API is active."}
            err = resp.json().get("error", {}).get("message", f"HTTP {resp.status_code}")
            return {"success": False, "message": f"API Key verification failed: {err}"}
        except Exception as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}
