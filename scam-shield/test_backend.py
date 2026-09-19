"""
Integration verification test for ScamShield Python backend
"""
import sys
from pathlib import Path

# Ensure root directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.app import app
from backend.detector import ScamDetector
from backend.storage import Storage

def run_tests():
    print("--- 1. Testing SQLite Storage ---")
    Storage.init_db()
    scan_id = Storage.save_scan({
        "id": "test_scan_init",
        "targetType": "URL",
        "target": "http://paypa1-security-verification.xyz/login",
        "riskScore": 90,
        "verdict": "HIGH RISK / DANGEROUS",
        "engine": "Test Engine"
    })
    history = Storage.get_history(limit=5)
    assert len(history) >= 1, "Storage failed to persist item"
    print(f"  [PASS] Storage initialized and verified. Scan ID: {scan_id}")

    print("--- 2. Testing URL Heuristic Engine ---")
    res_url_phish = ScamDetector.analyze_url("http://paypa1-security-verification.xyz/login")
    assert res_url_phish["riskScore"] >= 65, f"Expected high risk, got {res_url_phish['riskScore']}"
    print(f"  [PASS] URL Phishing detection: {res_url_phish['verdict']} (Score: {res_url_phish['riskScore']}%)")

    res_url_safe = ScamDetector.analyze_url("https://www.google.com")
    assert res_url_safe["riskScore"] <= 25, f"Expected safe, got {res_url_safe['riskScore']}"
    print(f"  [PASS] Safe URL detection: {res_url_safe['verdict']} (Score: {res_url_safe['riskScore']}%)")

    print("--- 3. Testing SMS Smishing Engine ---")
    res_sms_phish = ScamDetector.analyze_sms("USPS: Your package could not be delivered. Update address here: http://usps-post-redelivery.xyz/track")
    assert res_sms_phish["riskScore"] >= 65, f"Expected smishing high risk, got {res_sms_phish['riskScore']}"
    print(f"  [PASS] SMS Smishing detection: {res_sms_phish['verdict']} (Score: {res_sms_phish['riskScore']}%)")

    print("--- 4. Testing Flask REST API Client ---")
    client = app.test_client()

    # Health endpoint
    h = client.get("/api/health")
    assert h.status_code == 200, f"Health check failed: {h.status_code}"
    print(f"  [PASS] GET /api/health -> {h.get_json()}")

    # URL Scan endpoint
    scan_resp = client.post("/api/scan/url", json={"url": "http://paypa1-security-verification.xyz/login"})
    assert scan_resp.status_code == 200, f"Scan URL failed: {scan_resp.status_code}"
    url_data = scan_resp.get_json()
    print(f"  [PASS] POST /api/scan/url -> Verdict: {url_data['verdict']}, Score: {url_data['riskScore']}%, Engine: {url_data['engine']}")

    # SMS Scan endpoint
    sms_resp = client.post("/api/scan/sms", json={"message": "Wells Fargo Alert: A suspicious charge of $1,420 was attempted. Verify immediately: http://wf-sec-auth.top/login"})
    assert sms_resp.status_code == 200, f"Scan SMS failed: {sms_resp.status_code}"
    sms_data = sms_resp.get_json()
    print(f"  [PASS] POST /api/scan/sms -> Verdict: {sms_data['verdict']}, Score: {sms_data['riskScore']}%, Engine: {sms_data['engine']}")

    # History endpoint
    hist_resp = client.get("/api/history")
    assert hist_resp.status_code == 200, "History GET failed"
    total_items = len(hist_resp.get_json().get("history", []))
    print(f"  [PASS] GET /api/history -> Stored items count: {total_items}")

    # Static HTML serving
    idx_resp = client.get("/")
    assert idx_resp.status_code == 200, "Frontend index failed"
    assert b"ScamShield" in idx_resp.data, "ScamShield missing from frontend HTML"
    print(f"  [PASS] GET / -> Successfully serving frontend HTML ({len(idx_resp.data)} bytes)")

    print("\n=======================================================")
    print("ALL PYTHON BACKEND TESTS PASSED WITH 100% SUCCESS!")
    print("=======================================================")

if __name__ == "__main__":
    run_tests()
