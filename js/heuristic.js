/**
 * ScamShield AI - Heuristic & Rule-Based Threat Analysis Engine
 * Evaluates URLs and SMS/Text messages against 25+ indicators of deception.
 */

class HeuristicEngine {
  constructor() {
    this.config = window.CONFIG || {};
  }

  /**
   * Normalizes and parses a URL safely
   */
  parseUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string") {
      throw new Error("Invalid URL provided");
    }

    let urlString = rawUrl.trim();
    if (!/^https?:\/\//i.test(urlString)) {
      urlString = "https://" + urlString;
    }

    try {
      return new URL(urlString);
    } catch (e) {
      throw new Error("Unable to parse URL structure. Please enter a valid URL.");
    }
  }

  /**
   * Evaluates if a hostname is an IPv4 or IPv6 address
   */
  isIpAddress(hostname) {
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const ipv6Regex = /^\[?[a-fA-F0-9:]+\]?$/;
    return ipv4Regex.test(hostname) || ipv6Regex.test(hostname);
  }

  /**
   * Extracts the Top-Level Domain (TLD) and Root Domain
   */
  extractDomainInfo(hostname) {
    const cleanHost = hostname.toLowerCase().replace(/:\d+$/, "");
    const parts = cleanHost.split(".");

    if (parts.length <= 1) {
      return { tld: "", rootDomain: cleanHost, subdomains: [] };
    }

    const tld = parts[parts.length - 1];
    let rootDomain = parts.slice(-2).join(".");
    let subdomains = parts.slice(0, -2);

    // Common two-part TLDs (e.g. .co.uk, .com.au, .gov.uk)
    if (parts.length > 2) {
      const secondLevel = parts[parts.length - 2];
      if (["co", "com", "org", "gov", "edu", "net"].includes(secondLevel)) {
        rootDomain = parts.slice(-3).join(".");
        subdomains = parts.slice(0, -3);
      }
    }

    return { tld, rootDomain, subdomains };
  }

  /**
   * Detects character substitution (leet speak) like paypa1, micros0ft, arnazon
   */
  detectSubstitutions(word) {
    let normalized = word.toLowerCase();
    normalized = normalized.replace(/0/g, "o");
    normalized = normalized.replace(/1/g, "l");
    normalized = normalized.replace(/3/g, "e");
    normalized = normalized.replace(/4/g, "a");
    normalized = normalized.replace(/5/g, "s");
    normalized = normalized.replace(/@/g, "a");
    normalized = normalized.replace(/vv/g, "w");
    return normalized;
  }

  /**
   * Checks for brand impersonation or typosquatting
   */
  checkBrandImpersonation(hostname, pathname) {
    const cleanHost = hostname.toLowerCase();
    const cleanPath = pathname.toLowerCase();
    const fullTarget = `${cleanHost}${cleanPath}`;
    const normalizedTarget = this.detectSubstitutions(fullTarget);

    const brands = this.config.TARGET_BRANDS || [];
    const results = [];

    for (const brand of brands) {
      const isOfficialDomain = cleanHost === brand.domain || cleanHost.endsWith(`.${brand.domain}`);

      // If user is actually on the genuine domain, it's not impersonation
      if (isOfficialDomain) {
        return { isLegitBrand: true, brand: brand.name };
      }

      // Check if brand aliases or leet versions are present in unauthorized domain/path
      for (const alias of brand.aliases) {
        const aliasLower = alias.toLowerCase();
        const leetAlias = this.detectSubstitutions(aliasLower);

        const containsExact = cleanHost.includes(aliasLower);
        const containsLeet = normalizedTarget.includes(leetAlias) && (normalizedTarget !== fullTarget);
        const containsInSubdomain = cleanHost.split(".").some(part => part.includes(aliasLower) && cleanHost !== brand.domain);

        if (containsExact || containsLeet || containsInSubdomain) {
          results.push({
            impersonatedBrand: brand.name,
            officialDomain: brand.domain,
            detectedAlias: alias,
            isLeet: containsLeet
          });
          break;
        }
      }
    }

    return { isLegitBrand: false, matches: results };
  }

  /**
   * Main URL Threat Evaluation
   */
  analyzeUrl(rawUrl) {
    let parsedUrl;
    try {
      parsedUrl = this.parseUrl(rawUrl);
    } catch (err) {
      return {
        success: false,
        error: err.message
      };
    }

    let riskScore = 0;
    const redFlags = [];
    const trustFactors = [];
    const recommendations = [];

    const hostname = parsedUrl.hostname.toLowerCase();
    const protocol = parsedUrl.protocol.toLowerCase();
    const pathname = parsedUrl.pathname;
    const search = parsedUrl.search;
    const { tld, rootDomain, subdomains } = this.extractDomainInfo(hostname);

    // 1. Protocol check
    if (protocol === "http:") {
      riskScore += 20;
      redFlags.push({
        type: "INSECURE_PROTOCOL",
        title: "Unencrypted Connection (HTTP)",
        detail: "This website does not use SSL/HTTPS encryption. Legitimate banking, shopping, and login portals require HTTPS.",
        severity: "medium"
      });
    } else if (protocol === "https:") {
      trustFactors.push("Uses SSL/HTTPS encryption (Note: modern phishing sites can also obtain free certificates).");
    }

    // 2. IP Address as Hostname
    if (this.isIpAddress(hostname)) {
      riskScore += 45;
      redFlags.push({
        type: "IP_AS_HOST",
        title: "IP Address Used as Hostname",
        detail: `The URL uses a raw IP address (${hostname}) instead of a verified registered domain. This is a common tactic for malicious servers and phishing kits.`,
        severity: "critical"
      });
    }

    // 3. Suspicious Top-Level Domain (TLD)
    if (this.config.SUSPICIOUS_TLDS && this.config.SUSPICIOUS_TLDS.has(tld)) {
      riskScore += 25;
      redFlags.push({
        type: "SUSPICIOUS_TLD",
        title: `High-Risk Domain Extension (.${tld})`,
        detail: `The .${tld} top-level domain has a disproportionately high correlation with spam, phishing, and scam operations due to low registration cost.`,
        severity: "high"
      });
    }

    // 4. Trusted TLD
    if (this.config.TRUSTED_TLDS && this.config.TRUSTED_TLDS.has(tld)) {
      riskScore -= 30;
      trustFactors.push(`Regulated institutional domain extension (.${tld}), requiring strict official accreditation.`);
    }

    // 5. Brand Impersonation / Typosquatting
    const brandCheck = this.checkBrandImpersonation(hostname, pathname);
    if (brandCheck.isLegitBrand) {
      riskScore -= 35;
      trustFactors.push(`Matches genuine verified domain for ${brandCheck.brand}.`);
    } else if (brandCheck.matches && brandCheck.matches.length > 0) {
      const match = brandCheck.matches[0];
      riskScore += 50;
      redFlags.push({
        type: "BRAND_SPOOFING",
        title: `Impersonation of ${match.impersonatedBrand}`,
        detail: `This website appears to mimic ${match.impersonatedBrand} using an unofficial domain (${rootDomain}). Genuine domain is: ${match.officialDomain}.`,
        severity: "critical"
      });
    }

    // 6. Punycode / Internationalized Domain Name (IDN) Spoofing
    if (hostname.includes("xn--")) {
      riskScore += 35;
      redFlags.push({
        type: "PUNYCODE_OBFUSCATION",
        title: "Punycode Character Obfuscation Detected",
        detail: "The URL uses Punycode (starts with 'xn--') to disguise lookalike Cyrillic or Greek characters as Latin letters.",
        severity: "critical"
      });
    }

    // 7. Excessive Subdomains (Domain Crowding)
    if (subdomains.length >= 3) {
      riskScore += 20;
      redFlags.push({
        type: "EXCESSIVE_SUBDOMAINS",
        title: "Excessive Subdomains (Domain Crowding)",
        detail: `Contains ${subdomains.length} subdomains (${subdomains.join(".")}). Scammers often stack subdomains to hide the true destination domain on mobile screens.`,
        severity: "medium"
      });
    }

    // 8. URL Shortener Service
    if (this.config.URL_SHORTENERS && this.config.URL_SHORTENERS.has(hostname)) {
      riskScore += 20;
      redFlags.push({
        type: "URL_SHORTENER",
        title: "Shortened URL Cloaking Destination",
        detail: `Uses a URL shortening service (${hostname}) that obscures the actual end destination until clicked.`,
        severity: "medium"
      });
    }

    // 9. Sensitive Path Keywords on Unofficial Domains
    const suspiciousKeywords = (this.config.SUSPICIOUS_PATH_KEYWORDS || []).filter(kw =>
      pathname.includes(kw) || search.includes(kw)
    );
    if (suspiciousKeywords.length > 0 && !brandCheck.isLegitBrand) {
      riskScore += 15;
      redFlags.push({
        type: "CREDENTIAL_PATH_LURE",
        title: "Sensitive Action Path on Unverified Domain",
        detail: `URL path requests sensitive action keywords: [${suspiciousKeywords.join(", ")}]. Avoid providing credentials or personal data here.`,
        severity: "medium"
      });
    }

    // 10. Embedded Credentials or '@' Symbol
    if (rawUrl.includes("@")) {
      riskScore += 40;
      redFlags.push({
        type: "URL_AT_TRICK",
        title: "Deceptive '@' Character in URL",
        detail: "Browsers treat text before '@' as user credentials, redirecting you to whatever server follows it. Classic phishing tactic.",
        severity: "critical"
      });
    }

    // 11. Port Anomaly
    if (parsedUrl.port && !["80", "443", ""].includes(parsedUrl.port)) {
      riskScore += 15;
      redFlags.push({
        type: "UNUSUAL_PORT",
        title: `Non-Standard Network Port (:${parsedUrl.port})`,
        detail: `The connection specifies an unusual web port (${parsedUrl.port}), which is rarely used for public consumer services.`,
        severity: "low"
      });
    }

    // Clamp score
    riskScore = Math.max(0, Math.min(100, Math.round(riskScore)));

    // Categorization
    let verdict = "SAFE";
    let riskLevel = "low";

    if (riskScore >= 65) {
      verdict = "HIGH RISK / DANGEROUS";
      riskLevel = "high";
      recommendations.push("Do NOT click links, enter passwords, or provide payment details on this site.");
      recommendations.push("If you reached this via an SMS or email, report the sender as spam/phishing immediately.");
      recommendations.push("If you already entered information, change your passwords immediately and notify your bank.");
    } else if (riskScore >= 25) {
      verdict = "SUSPICIOUS / PROCEED WITH CAUTION";
      riskLevel = "medium";
      recommendations.push("Verify the sender through an official phone number or separate app before interacting.");
      recommendations.push("Double-check the exact domain spelling in your browser address bar.");
      recommendations.push("Avoid downloading any files or inputting sensitive authentication credentials.");
    } else {
      verdict = "LIKELY SAFE";
      riskLevel = "low";
      recommendations.push("Standard web precautions still apply; verify HTTPS lock in your browser address bar.");
      recommendations.push("Ensure you navigated here from an intended, reputable source.");
    }

    return {
      success: true,
      targetType: "URL",
      target: parsedUrl.href,
      hostname: hostname,
      rootDomain: rootDomain,
      riskScore: riskScore,
      verdict: verdict,
      riskLevel: riskLevel,
      redFlags: redFlags,
      trustFactors: trustFactors,
      recommendations: recommendations,
      engine: "Heuristic Pattern Engine"
    };
  }

  /**
   * Extracts URLs from message text
   */
  extractUrls(text) {
    const urlPattern = /(https?:\/\/[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.(?:com|org|net|xyz|top|ru|co|info|biz|club|link|io|me|app)[^\s]*)/gi;
    const matches = text.match(urlPattern) || [];
    return Array.from(new Set(matches.map(u => u.replace(/[.,;!?)]+$/, ""))));
  }

  /**
   * Main SMS / Message Fraud Evaluation
   */
  analyzeSms(messageText) {
    if (!messageText || typeof messageText !== "string" || messageText.trim().length === 0) {
      return {
        success: false,
        error: "Please enter an SMS or message text to analyze."
      };
    }

    const cleanText = messageText.trim();
    let riskScore = 0;
    const redFlags = [];
    const trustFactors = [];
    const recommendations = [];
    const categoryTriggers = [];

    // 1. Extract embedded links and analyze them
    const extractedUrls = this.extractUrls(cleanText);
    const analyzedUrls = [];
    let highestUrlRisk = 0;

    for (const urlStr of extractedUrls) {
      const urlAnalysis = this.analyzeUrl(urlStr);
      if (urlAnalysis.success) {
        analyzedUrls.push(urlAnalysis);
        if (urlAnalysis.riskScore > highestUrlRisk) {
          highestUrlRisk = urlAnalysis.riskScore;
        }
      }
    }

    if (extractedUrls.length > 0) {
      riskScore += 20; // Smishing messages almost always rely on external links
      redFlags.push({
        type: "EMBEDDED_LINKS",
        title: `Contains ${extractedUrls.length} External Link(s)`,
        detail: `The message contains links: ${extractedUrls.join(", ")}. Smishing attacks rely on links to lure victims to spoofed credential-harvesting pages.`,
        severity: "medium"
      });

      if (highestUrlRisk >= 65) {
        riskScore += 35;
        redFlags.push({
          type: "MALICIOUS_LINK_PAYLOAD",
          title: "Extracted URL Flagged as Malicious/Phishing",
          detail: "At least one embedded web address contains high-risk indicators of brand spoofing or malicious hosting.",
          severity: "critical"
        });
      }
    }

    // 2. Urgency and Fear Pressure
    const urgencyMatches = (this.config.URGENCY_PATTERNS || []).filter(pattern => pattern.test(cleanText));
    if (urgencyMatches.length > 0) {
      riskScore += 25;
      categoryTriggers.push("Urgent Action / Account Threat");
      redFlags.push({
        type: "URGENCY_PRESSURE",
        title: "Artificial Urgency & Fear Induction",
        detail: "The message uses coercive psychological urgency ('immediate action required', 'account suspended', 'legal notice') to prevent careful thinking.",
        severity: "high"
      });
    }

    // 3. Financial / Lottery / Crypto Lures
    const financialMatches = (this.config.FINANCIAL_LURE_PATTERNS || []).filter(pattern => pattern.test(cleanText));
    if (financialMatches.length > 0) {
      riskScore += 30;
      categoryTriggers.push("Lottery / Financial Lure");
      redFlags.push({
        type: "FINANCIAL_LURE",
        title: "Unsolicited Financial Prize or Payout Bait",
        detail: "Claims you won a lottery, prize, crypto bonus, or unexpected refund. Legitimate organizations never distribute random financial rewards via unsolicited SMS.",
        severity: "high"
      });
    }

    // 4. Credential & Identity Harvesting
    const credentialMatches = (this.config.CREDENTIAL_HARVEST_PATTERNS || []).filter(pattern => pattern.test(cleanText));
    if (credentialMatches.length > 0) {
      riskScore += 40;
      categoryTriggers.push("Credential Harvesting");
      redFlags.push({
        type: "CREDENTIAL_HARVESTING",
        title: "Request for Sensitive Credentials or OTP",
        detail: "The message solicits one-time passwords (OTP), PINs, security numbers, or banking credentials. Banks and legitimate services will NEVER ask you to reveal your OTP.",
        severity: "critical"
      });
    }

    // 5. Package Delivery Scams
    const deliveryMatches = (this.config.DELIVERY_LURE_PATTERNS || []).filter(pattern => pattern.test(cleanText));
    if (deliveryMatches.length > 0) {
      riskScore += 25;
      categoryTriggers.push("Package Delivery Smishing");
      redFlags.push({
        type: "DELIVERY_SMISHING",
        title: "Fake Parcel / Delivery Redirection Scam",
        detail: "Impersonates postal services (USPS, UPS, FedEx, DHL) asking to update an address or pay an overdue customs redelivery fee.",
        severity: "high"
      });
    }

    // 6. Bank / Brand Impersonation in text
    const mentionedBrands = (this.config.TARGET_BRANDS || []).filter(b => {
      const regex = new RegExp(`\\b${b.name.split(" ")[0]}\\b`, "i");
      return regex.test(cleanText);
    });

    if (mentionedBrands.length > 0) {
      const brandNames = mentionedBrands.map(b => b.name).join(", ");
      categoryTriggers.push("Brand Impersonation");

      if (extractedUrls.length > 0) {
        // Brand mentioned with an unverified link
        riskScore += 20;
        redFlags.push({
          type: "BRAND_NAME_MISMATCH",
          title: `Mentions ${brandNames} with Suspicious Call-to-Action`,
          detail: `The SMS refers to ${brandNames}, but directs you to an external or shortened link. Genuine institutions instruct you to log in via their official mobile app.`,
          severity: "high"
        });
      }
    }

    // 7. Conversational / Safe Trust Indicators
    if (extractedUrls.length === 0 && redFlags.length === 0) {
      trustFactors.push("No external links or malicious URLs detected in message.");
      trustFactors.push("No typical phishing urgency keywords or high-pressure threats found.");
      trustFactors.push("No requests for sensitive personal identifiers, passwords, or one-time codes.");
    }

    // Combine score with highest URL risk if URL is higher
    if (highestUrlRisk > riskScore) {
      riskScore = Math.round((riskScore + highestUrlRisk) / 2) + 10;
    }

    // Clamp score
    riskScore = Math.max(0, Math.min(100, Math.round(riskScore)));

    // Categorization
    let verdict = "LIKELY SAFE";
    let riskLevel = "low";

    if (riskScore >= 65) {
      verdict = "HIGH RISK SCAM / SMISHING";
      riskLevel = "high";
      recommendations.push("DO NOT tap or open any links included in this message.");
      recommendations.push("DO NOT reply with 'STOP', 'YES', or any personal information (this confirms your number is active).");
      recommendations.push("Block the sender's phone number or contact immediately.");
      recommendations.push("Forward the text to your telecom spam reporting shortcode (e.g., 7726 / SPAM in US/UK/Canada).");
    } else if (riskScore >= 25) {
      verdict = "SUSPICIOUS MESSAGE";
      riskLevel = "medium";
      recommendations.push("Verify the communication by contacting the company directly through their official app or website.");
      recommendations.push("Do not enter login credentials or payment details on any link provided.");
    } else {
      verdict = "LIKELY SAFE / NORMAL MESSAGE";
      riskLevel = "low";
      recommendations.push("Message appears standard, but never share one-time passwords (OTPs) with anyone over text or phone.");
    }

    return {
      success: true,
      targetType: "SMS",
      messageLength: cleanText.length,
      extractedUrls: extractedUrls,
      analyzedUrls: analyzedUrls,
      categories: categoryTriggers.length > 0 ? categoryTriggers : ["Normal Communication"],
      riskScore: riskScore,
      verdict: verdict,
      riskLevel: riskLevel,
      redFlags: redFlags,
      trustFactors: trustFactors,
      recommendations: recommendations,
      engine: "Heuristic Smishing Detection Engine"
    };
  }
}

// Expose globally
if (typeof window !== "undefined") {
  window.HeuristicEngine = HeuristicEngine;
}
