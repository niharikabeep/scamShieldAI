/**
 * ScamShield AI - Curated Real-World Test Sample Database
 */

const TEST_SAMPLES = {
  urls: [
    {
      id: "url-paypal-phish",
      name: "Fake PayPal Phishing",
      category: "Typosquatting & Unsecure TLD",
      expectedRisk: "HIGH RISK",
      url: "http://paypa1-security-verification.xyz/login?account=review",
      description: "Uses 'paypa1' with digit 1, HTTP protocol, and high-risk .xyz TLD."
    },
    {
      id: "url-ip-bank",
      name: "IP-Based Chase Bank Phish",
      category: "Raw IP & Credential Lure",
      expectedRisk: "HIGH RISK",
      url: "http://192.168.1.105/chase-online-banking/verify-identity.html",
      description: "Uses raw IP address and banking keywords to steal bank credentials."
    },
    {
      id: "url-netflix-fake",
      name: "Fake Netflix Billing",
      category: "Lookalike Domain (.top)",
      expectedRisk: "HIGH RISK",
      url: "https://netfIix-billing-update.top/account/security",
      description: "Disguised with capital 'I' instead of 'l' and high-risk .top extension."
    },
    {
      id: "url-apple-subdomain",
      name: "Apple ID Multi-Subdomain",
      category: "Subdomain Crowding",
      expectedRisk: "HIGH RISK",
      url: "https://appleid.apple.com.verify-device-portal.club/signin",
      description: "Stacks fake subdomains to mask the true destination (.club)."
    },
    {
      id: "url-shortener-lure",
      name: "IRS Refund URL Shortener",
      category: "Shortener Cloaking",
      expectedRisk: "SUSPICIOUS",
      url: "https://bit.ly/irs-tax-refund-claim-2026",
      description: "Hides malicious destination behind a shortened URL."
    },
    {
      id: "url-legit-paypal",
      name: "Genuine PayPal Official",
      category: "Legitimate Verified",
      expectedRisk: "SAFE",
      url: "https://www.paypal.com/signin",
      description: "Official PayPal authentication portal with genuine domain & HTTPS."
    },
    {
      id: "url-legit-google",
      name: "Genuine Google Search",
      category: "Legitimate Verified",
      expectedRisk: "SAFE",
      url: "https://www.google.com",
      description: "Official Google search engine homepage."
    },
    {
      id: "url-legit-github",
      name: "Genuine GitHub Portal",
      category: "Legitimate Verified",
      expectedRisk: "SAFE",
      url: "https://github.com/security",
      description: "Official GitHub developer and security portal."
    }
  ],

  sms: [
    {
      id: "sms-usps-delivery",
      name: "USPS Fake Delivery Smishing",
      category: "Package Delivery Smishing",
      expectedRisk: "HIGH RISK",
      text: "USPS: Your package could not be delivered due to an incomplete street address. Please confirm your delivery details within 12 hours here: http://usps-post-redelivery.xyz/track or your parcel will be returned to sender.",
      description: "Classic package redirection smishing with false urgency and .xyz link."
    },
    {
      id: "sms-wells-fargo-alert",
      name: "Wells Fargo Urgent Fraud Alert",
      category: "Bank Impersonation",
      expectedRisk: "HIGH RISK",
      text: "Wells Fargo Alert: A suspicious charge of $1,420.50 was attempted on your debit card. If this was NOT you, immediately verify your identity: http://wf-sec-auth.top/login to prevent permanent account suspension.",
      description: "Bank spoofing invoking financial panic and credential phishing link."
    },
    {
      id: "sms-netflix-suspension",
      name: "Netflix Payment Failure",
      category: "Subscription Threat",
      expectedRisk: "HIGH RISK",
      text: "URGENT: Your Netflix membership payment has failed. Your subscription will be cancelled within 24 hours. Update your credit card details now: http://netfIix-billing-service.com/update",
      description: "Subscription cancellation threat baiting for credit card numbers."
    },
    {
      id: "sms-lottery-prize",
      name: "International Cash Lottery",
      category: "Advance-Fee Fraud",
      expectedRisk: "HIGH RISK",
      text: "CONGRATULATIONS! Your mobile number won the 2026 International Cash Grant of $50,000. Reply with your Full Name, Bank Account Number, and PIN code immediately to claim your payout!",
      description: "Unsolicited cash reward harvesting bank account number and PIN."
    },
    {
      id: "sms-legit-amazon",
      name: "Legitimate Amazon Shipment",
      category: "Normal E-Commerce Notification",
      expectedRisk: "SAFE",
      text: "Your Amazon order #402-9821 has shipped and will arrive tomorrow by 8 PM. Track progress directly in your Amazon app. Reply STOP to opt out.",
      description: "Legitimate tracking reminder without phishing links or OTP demands."
    },
    {
      id: "sms-legit-2fa",
      name: "Standard Google 2FA Code",
      category: "Legitimate Authentication",
      expectedRisk: "SAFE",
      text: "Your Google verification code is 849201. Never share this code with anyone. Google will never call or text you asking for this code.",
      description: "Official 2FA security code with explicit reminder not to share."
    },
    {
      id: "sms-legit-personal",
      name: "Casual Friendly Text",
      category: "Normal Personal Chat",
      expectedRisk: "SAFE",
      text: "Hey Alex, are we still meeting for lunch at 1 PM at the downtown cafe? Let me know when you're on the way!",
      description: "Standard personal text message with zero threat indicators."
    }
  ]
};

// Expose globally
if (typeof window !== "undefined") {
  window.TEST_SAMPLES = TEST_SAMPLES;
}
