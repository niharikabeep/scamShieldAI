"""
ScamShield AI - Python Server-Side Heuristic & Scoring Engine
Evaluates websites, domains, and SMS text messages for fraud indicators.
"""

import re
from urllib.parse import urlparse
from .config import Config

class ScamDetector:
    @staticmethod
    def is_ip_address(hostname: str) -> bool:
        ipv4_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return bool(re.match(ipv4_regex, hostname))

    @staticmethod
    def normalize_substitutions(text: str) -> str:
        """Normalizes common leet-speak character substitutions (paypa1 -> paypal)"""
        norm = text.lower()
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a',
            '5': 's', '@': 'a', 'vv': 'w'
        }
        for k, v in substitutions.items():
            norm = norm.replace(k, v)
        return norm

    @staticmethod
    def check_brand_spoofing(hostname: str, path: str) -> dict:
        clean_host = hostname.lower()
        clean_path = path.lower()
        full_target = f"{clean_host}{clean_path}"
        normalized = ScamDetector.normalize_substitutions(full_target)

        for brand in Config.TARGET_BRANDS:
            # Genuine official domain check
            if clean_host == brand["domain"] or clean_host.endswith(f".{brand['domain']}"):
                return {"is_legit": True, "brand": brand["name"]}

            # Check for spoofing aliases
            for alias in brand["aliases"]:
                alias_norm = ScamDetector.normalize_substitutions(alias)
                if alias in clean_host or (alias_norm in normalized and alias_norm != full_target):
                    return {
                        "is_legit": False,
                        "spoofed": True,
                        "brand": brand["name"],
                        "official_domain": brand["domain"]
                    }

        return {"is_legit": False, "spoofed": False}

    @staticmethod
    def analyze_url(raw_url: str) -> dict:
        """
        Deep technical inspection of URL structure, protocol, domain, and patterns.
        """
        if not raw_url or not isinstance(raw_url, str):
            return {"success": False, "error": "Invalid URL provided"}

        url_str = raw_url.strip()
        if not re.match(r"^https?://", url_str, re.IGNORECASE):
            url_str = "https://" + url_str

        try:
            parsed = urlparse(url_str)
        except Exception as e:
            return {"success": False, "error": f"URL parsing error: {e}"}

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return {"success": False, "error": "Invalid or missing domain name"}

        risk_score = 0
        red_flags = []
        trust_factors = []
        recommendations = []

        # 1. Protocol check
        if parsed.scheme.lower() == "http":
            risk_score += 20
            red_flags.append({
                "title": "Unencrypted Connection (HTTP)",
                "detail": "Website does not use SSL/TLS encryption. Legitimate payment, banking, and login portals require HTTPS.",
                "severity": "medium"
            })
        else:
            trust_factors.append("Uses SSL/HTTPS encrypted transport layer.")

        # 2. IP as hostname
        if ScamDetector.is_ip_address(hostname):
            risk_score += 45
            red_flags.append({
                "title": "Raw IP Address Used as Hostname",
                "detail": f"The target uses a raw IP ({hostname}) instead of a registered domain name. Common for phishing kits.",
                "severity": "critical"
            })

        # 3. Domain extension / TLD
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in Config.SUSPICIOUS_TLDS:
            risk_score += 25
            red_flags.append({
                "title": f"High-Risk Domain Extension (.{tld})",
                "detail": f"The .{tld} top-level domain is heavily correlated with disposable scam and phishing infrastructure.",
                "severity": "high"
            })
        elif tld in ("gov", "mil", "edu"):
            risk_score -= 30
            trust_factors.append(f"Regulated institutional top-level domain (.{tld}).")

        # 4. Brand spoofing & typosquatting
        brand_res = ScamDetector.check_brand_spoofing(hostname, parsed.path)
        if brand_res.get("is_legit"):
            risk_score -= 35
            trust_factors.append(f"Matches genuine verified domain for {brand_res['brand']}.")
        elif brand_res.get("spoofed"):
            risk_score += 50
            red_flags.append({
                "title": f"Brand Impersonation of {brand_res['brand']}",
                "detail": f"This site mimics {brand_res['brand']}, but genuine domain is {brand_res['official_domain']}.",
                "severity": "critical"
            })

        # 5. Punycode obfuscation
        if "xn--" in hostname:
            risk_score += 35
            red_flags.append({
                "title": "Punycode (IDN) Character Obfuscation",
                "detail": "Domain utilizes Punycode to masquerade Cyrillic or Greek lookalike glyphs as Latin letters.",
                "severity": "critical"
            })

        # 6. URL shorteners
        if hostname in Config.URL_SHORTENERS:
            risk_score += 20
            red_flags.append({
                "title": "URL Shortener Masking Destination",
                "detail": f"Uses a redirection service ({hostname}) that conceals the true landing page.",
                "severity": "medium"
            })

        # 7. Credential '@' trick
        if "@" in raw_url:
            risk_score += 40
            red_flags.append({
                "title": "Deceptive '@' Credential Character in URL",
                "detail": "Browsers route requests to whatever domain follows '@', hiding malicious destinations.",
                "severity": "critical"
            })

        # Clamp score between 0 and 100
        risk_score = max(0, min(100, risk_score))

        if risk_score >= 65:
            verdict = "HIGH RISK / DANGEROUS"
            category = "Phishing / Malicious Site"
            recommendations.append("Do NOT enter credentials, passwords, or payment cards on this website.")
            recommendations.append("Close the browser tab immediately.")
        elif risk_score >= 25:
            verdict = "SUSPICIOUS / PROCEED WITH CAUTION"
            category = "Unverified / Suspicious Site"
            recommendations.append("Verify the website directly via an official search or bookmark before interacting.")
        else:
            verdict = "LIKELY SAFE"
            category = "Verified / Normal Website"
            recommendations.append("Standard browsing vigilance applies; verify the padlock in your browser.")

        return {
            "success": True,
            "targetType": "URL",
            "target": url_str,
            "hostname": hostname,
            "riskScore": risk_score,
            "verdict": verdict,
            "category": category,
            "redFlags": red_flags,
            "trustFactors": trust_factors,
            "recommendations": recommendations,
            "engine": "Backend Heuristic Engine"
        }

    @staticmethod
    def extract_urls(text: str) -> list:
        url_pattern = r"(https?://[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.(?:com|org|net|xyz|top|ru|co|info|biz|club|link|io|me|app)[^\s]*)"
        matches = re.findall(url_pattern, text, re.IGNORECASE)
        clean_urls = []
        for m in matches:
            cleaned = re.sub(r"[.,;!?)]+$", "", m)
            if cleaned not in clean_urls:
                clean_urls.append(cleaned)
        return clean_urls

    @staticmethod
    def analyze_sms(message_text: str) -> dict:
        """
        Analyzes SMS and text messages for smishing, social engineering, and fraud lures.
        """
        if not message_text or not isinstance(message_text, str) or not message_text.strip():
            return {"success": False, "error": "Please provide message text to analyze."}

        text = message_text.strip()
        risk_score = 0
        red_flags = []
        trust_factors = []
        recommendations = []
        categories = []

        # 1. Embedded Links
        extracted_urls = ScamDetector.extract_urls(text)
        highest_url_score = 0
        analyzed_urls = []

        for u in extracted_urls:
            u_res = ScamDetector.analyze_url(u)
            if u_res.get("success"):
                analyzed_urls.append(u_res)
                if u_res.get("riskScore", 0) > highest_url_score:
                    highest_url_score = u_res.get("riskScore", 0)

        if extracted_urls:
            risk_score += 20
            red_flags.append({
                "title": f"Contains {len(extracted_urls)} Embedded Link(s)",
                "detail": f"Smishing attacks rely on links ({', '.join(extracted_urls)}) to lure users into harvesting portals.",
                "severity": "medium"
            })
            if highest_url_score >= 65:
                risk_score += 35
                red_flags.append({
                    "title": "Embedded Link Flagged as High Risk / Phishing",
                    "detail": "At least one embedded web address contains high-risk indicators of brand spoofing or suspicious hosting.",
                    "severity": "critical"
                })

        # 2. Urgency & Coercive Pressure
        urgency_regex = r"\b(urgent|immediately|action required|within 24 hours|account suspended|locked|unauthorized|final warning|legal action)\b"
        if re.search(urgency_regex, text, re.IGNORECASE):
            risk_score += 25
            categories.append("Urgent Account Threat")
            red_flags.append({
                "title": "Coercive Psychological Urgency",
                "detail": "Uses false urgency to induce panic and prevent calm verification.",
                "severity": "high"
            })

        # 3. Financial / Prize Lures
        financial_regex = r"\b(won|winner|lottery|cash prize|crypto bonus|refund waiting|tax refund|irs stimulus|\$\d{2,5})\b"
        if re.search(financial_regex, text, re.IGNORECASE):
            risk_score += 30
            categories.append("Lottery / Prize Bait")
            red_flags.append({
                "title": "Unsolicited Financial Reward / Prize Lure",
                "detail": "Claims an unexpected financial payout. Legitimate agencies never send unsolicited cash prizes via SMS.",
                "severity": "high"
            })

        # 4. Credential / OTP Harvesting
        cred_regex = r"\b(otp|one time password|pin|security code|password|passcode|social security|ssn|credit card|cvv)\b"
        if re.search(cred_regex, text, re.IGNORECASE):
            risk_score += 40
            categories.append("Credential Harvesting")
            red_flags.append({
                "title": "Demands Sensitive Credentials or OTP",
                "detail": "Solicits one-time authentication codes or financial PINs. Banks never ask for your OTP over SMS.",
                "severity": "critical"
            })

        # 5. Package delivery patterns
        delivery_regex = r"\b(package|parcel|shipment|delivery) (cannot be delivered|is on hold|failed)\b|\bupdate (your )?(address|delivery)\b"
        if re.search(delivery_regex, text, re.IGNORECASE):
            risk_score += 25
            categories.append("Package Smishing")
            red_flags.append({
                "title": "Fake Parcel Redirection Smishing",
                "detail": "Impersonates postal couriers asking to update delivery details or pay an unpaid fee.",
                "severity": "high"
            })

        # If URL risk is higher, adapt score
        if highest_url_score > risk_score:
            risk_score = round((risk_score + highest_url_score) / 2) + 10

        risk_score = max(0, min(100, risk_score))

        if not extracted_urls and not red_flags:
            trust_factors.append("No links or known smishing lure patterns identified.")
            trust_factors.append("No sensitive personal or OTP credentials requested.")

        if risk_score >= 65:
            verdict = "HIGH RISK SCAM / SMISHING"
            category = categories[0] if categories else "Smishing Message"
            recommendations.append("Do NOT tap on any links in this message.")
            recommendations.append("Do NOT reply with personal info or verification codes.")
            recommendations.append("Block the sender number and report as spam.")
        elif risk_score >= 25:
            verdict = "SUSPICIOUS MESSAGE"
            category = categories[0] if categories else "Unverified Message"
            recommendations.append("Contact the alleged sender directly via their official application or website.")
        else:
            verdict = "LIKELY SAFE / NORMAL MESSAGE"
            category = "Normal Communication"
            recommendations.append("Standard caution: Never share one-time security codes with anyone.")

        return {
            "success": True,
            "targetType": "SMS",
            "target": text,
            "extractedUrls": extracted_urls,
            "analyzedUrls": analyzed_urls,
            "riskScore": risk_score,
            "verdict": verdict,
            "category": category,
            "redFlags": red_flags,
            "trustFactors": trust_factors,
            "recommendations": recommendations,
            "engine": "Backend Smishing Detector"
        }
