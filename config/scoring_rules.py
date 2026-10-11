"""Configurable weights, thresholds, and word lists.

Detection code asks whether a condition is present. This file says how
that condition affects the score. It does not inspect URLs.
"""

# Starting score before any indicator is applied.
BASE_SCORE = 10

# Classification uses the final 0–100 score.
# 0–30 Low Risk, 31–60 Suspicious, 61–100 High Risk.
LOW_RISK_MAX = 30
SUSPICIOUS_MAX = 60

# A URL longer than this many characters is unusually long.
LONG_URL_THRESHOLD = 120

# Subdomain labels before the final two hostname labels. More than this
# is a simple heuristic, not a public-suffix lookup.
EXCESSIVE_SUBDOMAIN_LEVELS = 3

# Ordinary ports for HTTP and HTTPS. An explicit different port is flagged.
STANDARD_PORTS = {
    "http": 80,
    "https": 443,
}

SUSPICIOUS_URL_KEYWORDS = (
    "login",
    "verify",
    "account",
    "update",
    "password",
    "banking",
    "secure",
    "confirm",
)

# How similar a domain label must be to a reference label before the
# impersonation heuristic reports a warning. This is not proof of intent.
DOMAIN_SIMILARITY_THRESHOLD = 0.80

# Expected domains for a small MVP set. Genuine hosts of these domains
# are not treated as impersonation.
REFERENCE_DOMAINS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
}

# Compared with the URL hostname only (exact host match, not a substring).
URL_SHORTENERS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "linkr.it",
    "cutt.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "tiny.one",
)

URL_RULES = {
    "https_present": {
        "weight": -5,
        "description": (
            "The URL uses HTTPS, which encrypts data transmitted between "
            "the browser and the website. However, HTTPS alone does not "
            "guarantee that a website is trustworthy."
        ),
    },
    "http_only": {
        "weight": 10,
        "description": (
            "The URL uses HTTP instead of HTTPS. Information transmitted "
            "over HTTP is not protected by TLS encryption."
        ),
    },
    "ip_hostname": {
        "weight": 20,
        "description": (
            "The URL uses an IP address as its hostname instead of a normal "
            "domain name. This can occur legitimately, but it is also a "
            "pattern sometimes seen in suspicious or phishing URLs."
        ),
    },
    "long_url": {
        "weight": 10,
        "description": (
            "Unusually long URLs can sometimes be used to hide or obscure "
            "suspicious destinations or parameters, but URL length alone "
            "does not prove malicious intent."
        ),
    },
    "excessive_subdomains": {
        "weight": 10,
        "description": (
            "The hostname contains an unusually large number of subdomain "
            "levels. Attackers can sometimes use deeply nested subdomains "
            "to make a URL appear associated with a trusted service."
        ),
    },
    "at_symbol": {
        "weight": 20,
        "description": (
            "The @ symbol has a special meaning in a URL: it separates "
            "optional user information from the hostname. That can make "
            "the real destination confusing. Its presence is a suspicious "
            "indicator, not proof that the URL is malicious."
        ),
    },
    "punycode": {
        "weight": 15,
        "description": (
            "The hostname contains Punycode, which is used to represent "
            "internationalized domain names. Punycode is legitimate, but "
            "visually similar characters can sometimes be abused in domain "
            "impersonation attacks."
        ),
    },
    "suspicious_keywords": {
        "weight_per_keyword": 5,
        "max_contribution": 15,
        "description": (
            "The URL contains words commonly associated with authentication, "
            "account verification, or credential-related pages. These words "
            "can be completely legitimate, but they are also frequently used "
            "in phishing URLs."
        ),
    },
    "suspicious_port": {
        "weight": 10,
        "description": (
            "The URL uses a non-standard port for its protocol. Alternative "
            "ports can be legitimate for development or specialized services, "
            "but they may warrant additional verification."
        ),
    },
    "url_shortener": {
        "weight": 20,
        "description": (
            "URL shortening services hide the final destination. Shortened "
            "URLs can be used legitimately, but they reduce visibility into "
            "where the link leads."
        ),
    },
    "possible_typosquatting": {
        "weight": 20,
        "severity": "warning",
        "description": (
            "The hostname appears similar to a configured well-known domain "
            "but is not the expected domain. This may indicate domain "
            "impersonation or typosquatting, although similarity alone does "
            "not prove malicious intent."
        ),
    },
}

# Extra points when existing indicators appear together. Each rule is
# applied at most once, based on which indicator IDs are present.
CORRELATION_RULES = (
    {
        "rule": "impersonation_with_credentials",
        "requires": ("possible_typosquatting", "suspicious_keywords"),
        "weight": 15,
        "title": "Domain impersonation combined with credential-related language",
        "explanation": (
            "The URL resembles a configured well-known domain and also "
            "contains authentication or account-related language. This "
            "combination is more concerning than either indicator alone."
        ),
    },
    {
        "rule": "shortener_with_credentials",
        "requires": ("url_shortener", "suspicious_keywords"),
        "weight": 10,
        "title": "URL shortener combined with credential-related language",
        "explanation": (
            "The URL uses a shortening service while also containing account "
            "or authentication-related language. The shortened destination is "
            "hidden, increasing uncertainty."
        ),
    },
    {
        "rule": "at_symbol_with_credentials",
        "requires": ("at_symbol", "suspicious_keywords"),
        "weight": 10,
        "title": "@ symbol combined with credential-related language",
        "explanation": (
            "The URL contains an @ symbol together with authentication or "
            "account-related language. This combination may make the actual "
            "destination harder for a user to interpret."
        ),
    },
    {
        "rule": "ip_with_credentials",
        "requires": ("ip_hostname", "suspicious_keywords"),
        "weight": 10,
        "title": "IP address combined with credential-related language",
        "explanation": (
            "The URL uses an IP address instead of a domain while also "
            "containing authentication or account-related language."
        ),
    },
)
