"""
ScamShield AI - Backend Configuration & Threat Intelligence Dictionaries
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Config:
    # Server settings
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", 5000))
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")

    # API Keys
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

    # External Threat Intelligence APIs
    URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
    GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

    # Database Path
    DATABASE_PATH = BASE_DIR / "backend" / "scans.db"

    # Suspicious Top-Level Domains (TLDs) frequently abused in phishing/malware
    SUSPICIOUS_TLDS = {
        "xyz", "top", "work", "click", "link", "gq", "cf", "tk", "ml", "ga",
        "country", "stream", "kim", "rest", "casa", "buzz", "surf", "fit",
        "support", "review", "icu", "bar", "download", "zip", "mov", "ru"
    }

    # High-value brands frequently spoofed
    TARGET_BRANDS = [
        {"name": "PayPal", "domain": "paypal.com", "aliases": ["paypal", "pay-pal", "paypa1"]},
        {"name": "Apple", "domain": "apple.com", "aliases": ["apple", "icloud", "applestore"]},
        {"name": "Microsoft", "domain": "microsoft.com", "aliases": ["microsoft", "office365", "outlook"]},
        {"name": "Google", "domain": "google.com", "aliases": ["google", "gmail", "youtube"]},
        {"name": "Amazon", "domain": "amazon.com", "aliases": ["amazon", "prime", "amazn"]},
        {"name": "Netflix", "domain": "netflix.com", "aliases": ["netflix", "netfIix"]},
        {"name": "Chase Bank", "domain": "chase.com", "aliases": ["chase", "chasebank"]},
        {"name": "Wells Fargo", "domain": "wellsfargo.com", "aliases": ["wellsfargo", "wf"]},
        {"name": "Bank of America", "domain": "bankofamerica.com", "aliases": ["bankofamerica", "bofa"]},
        {"name": "USPS", "domain": "usps.com", "aliases": ["usps", "postal-service", "postaldelivery"]},
        {"name": "FedEx", "domain": "fedex.com", "aliases": ["fedex", "fed-ex"]},
        {"name": "UPS", "domain": "ups.com", "aliases": ["ups", "ups-tracking"]}
    ]

    # Known URL shortener domains
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
        "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"
    }
