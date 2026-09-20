/**
 * ScamShield AI - Configuration & Threat Intelligence Dictionaries
 */

const CONFIG = {
  APP_NAME: "ScamShield AI",
  VERSION: "1.0.0",

  STORAGE_KEYS: {
    GEMINI_API_KEY: "scam_shield_gemini_key",
    SETTINGS: "scam_shield_settings",
    HISTORY: "scam_shield_history"
  },

  DEFAULT_SETTINGS: {
    useGeminiAI: true,
    useUrlhaus: true,
    useHeuristics: true,
    geminiModel: "gemini-1.5-flash",
    autoExtractSmsUrls: true,
    maxHistoryItems: 30
  },

  API_ENDPOINTS: {
    GEMINI_BASE: "https://generativelanguage.googleapis.com/v1beta/models",
    URLHAUS_API: "https://urlhaus-api.abuse.ch/v1/url/"
  },

  // High-risk top-level domains frequently abused for phishing and malware campaigns
  SUSPICIOUS_TLDS: new Set([
    "xyz", "top", "work", "click", "link", "gq", "cf", "tk", "ml", "ga",
    "country", "stream", "kim", "rest", "casa", "buzz", "surf", "fit",
    "support", "review", "icu", "bar", "download", "zip", "mov", "ru"
  ]),

  // Well-known trusted top-level domains / extensions
  TRUSTED_TLDS: new Set(["gov", "mil", "edu"]),

  // Popular high-value brands frequently targeted by smishing and phishing spoofing
  TARGET_BRANDS: [
    { name: "PayPal", domain: "paypal.com", aliases: ["paypal", "pay-pal", "paypa1"] },
    { name: "Apple", domain: "apple.com", aliases: ["apple", "icloud", "applestore"] },
    { name: "Microsoft", domain: "microsoft.com", aliases: ["microsoft", "office365", "outlook", "live", "onedrive"] },
    { name: "Google", domain: "google.com", aliases: ["google", "gmail", "youtube", "drive.google"] },
    { name: "Amazon", domain: "amazon.com", aliases: ["amazon", "prime", "amazn"] },
    { name: "Netflix", domain: "netflix.com", aliases: ["netflix", "netfIix"] },
    { name: "Meta / Facebook", domain: "facebook.com", aliases: ["facebook", "meta", "instagram", "whatsapp"] },
    { name: "Chase Bank", domain: "chase.com", aliases: ["chase", "chasebank"] },
    { name: "Wells Fargo", domain: "wellsfargo.com", aliases: ["wellsfargo", "wf"] },
    { name: "Bank of America", domain: "bankofamerica.com", aliases: ["bankofamerica", "bofa"] },
    { name: "USPS", domain: "usps.com", aliases: ["usps", "postal-service", "postaldelivery"] },
    { name: "UPS", domain: "ups.com", aliases: ["ups", "ups-tracking"] },
    { name: "FedEx", domain: "fedex.com", aliases: ["fedex", "fed-ex"] },
    { name: "DHL", domain: "dhl.com", aliases: ["dhl", "dhl-express"] },
    { name: "Coinbase", domain: "coinbase.com", aliases: ["coinbase"] },
    { name: "Binance", domain: "binance.com", aliases: ["binance"] },
    { name: "MetaMask", domain: "metamask.io", aliases: ["metamask"] }
  ],

  // Common URL shortener services that disguise target links
  URL_SHORTENERS: new Set([
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "goo.gl"
  ]),

  // Common phishing lure path terms
  SUSPICIOUS_PATH_KEYWORDS: [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "billing", "confirm", "wallet",
    "recovery", "unlock", "authenticate", "credential", "password", "reset"
  ],

  // SMS urgency & fear triggers
  URGENCY_PATTERNS: [
    /\b(urgent|immediately|action required|within 24 hours|within 1 hour|immediate attention)\b/i,
    /\b(account (suspended|locked|restricted|blocked|disabled|frozen))\b/i,
    /\b(unauthorized (charge|transaction|access|activity|sign-in))\b/i,
    /\b(final notice|last warning|legal action|warrant|arrest|irs penalty)\b/i,
    /\b(terminated?|cancelled?|deactivated?) immediately\b/i
  ],

  // SMS financial reward / lottery / gift lures
  FINANCIAL_LURE_PATTERNS: [
    /\b(won|winner|winning|lottery|lucky winner|jackpot)\b/i,
    /\b(free gift|gift card|\$\d{2,5}|claim your prize|cash reward)\b/i,
    /\b(crypto bonus|bitcoin bonus|usdt airdrop|guaranteed return)\b/i,
    /\b(tax refund|irs stimulus|relief payment|pending payout)\b/i,
    /\b(approved loan|pre-approved|instant cash transfer)\b/i
  ],

  // SMS credential / sensitive data request triggers
  CREDENTIAL_HARVEST_PATTERNS: [
    /\b(otp|one time password|pin|security code|verification code)\b/i,
    /\b(password|passcode|secret phrase|recovery seed)\b/i,
    /\b(social security|ssn|credit card number|cvv|expiry date)\b/i,
    /\b(mother's maiden name|date of birth|driver'?s license)\b/i,
    /\b(reply with your (pin|password|code|credentials))\b/i
  ],

  // Package delivery smishing patterns
  DELIVERY_LURE_PATTERNS: [
    /\b(package|parcel|shipment|delivery) (cannot be delivered|is on hold|failed|pending delivery)\b/i,
    /\b(update (your )?(address|postal address|delivery preference))\b/i,
    /\b(pay (redelivery|customs|postage) fee)\b/i,
    /\b(tracking number:? [a-z0-9]+)\b/i
  ]
};

// Expose globally
if (typeof window !== "undefined") {
  window.CONFIG = CONFIG;
}
