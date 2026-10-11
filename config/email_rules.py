"""Configurable email indicator terms.

Detection code asks whether a phrase or extension is present. This file
stores those lists. It does not score emails or inspect message content.
"""

URGENCY_TERMS = (
    "urgent",
    "immediately",
    "act now",
    "verify now",
    "action required",
    "account suspended",
    "account locked",
    "final warning",
    "security alert",
    "unusual activity",
    "payment failed",
)

CREDENTIAL_TERMS = (
    "login",
    "log in",
    "sign in",
    "password",
    "verify your account",
    "verify account",
    "confirm account",
    "reset password",
    "confirm identity",
    "update payment",
    "update billing",
)

FINANCIAL_TERMS = (
    "invoice",
    "payment",
    "bank transfer",
    "wire transfer",
    "refund",
    "billing",
    "credit card",
    "payment method",
)

GENERIC_GREETINGS = (
    "dear customer",
    "dear user",
    "dear account holder",
    "valued customer",
    "hello customer",
)

RISKY_ATTACHMENT_EXTENSIONS = (
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".msi",
    ".com",
)

# Heuristic email score. These numbers are not a probability of phishing.
EMAIL_BASE_SCORE = 10
EMAIL_LOW_RISK_MAX = 30
EMAIL_SUSPICIOUS_MAX = 60

# Keys are the rule_name values produced by email security detection.
EMAIL_INDICATOR_WEIGHTS = {
    "reply_to_mismatch": 10,
    "return_path_mismatch": 5,
    "display_name_deception": 15,
    "urgency_language": 5,
    "credential_language": 10,
    "financial_language": 3,
    "generic_greeting": 3,
    "suspicious_embedded_link": 20,
    "link_text_mismatch": 20,
    "risky_attachment_extension": 20,
    "misleading_double_extension": 15,
    "spf_fail": 15,
    "spf_softfail": 8,
    "dkim_fail": 15,
    "dmarc_fail": 20,
}

# requires_all must all be present. requires_any, when set, needs one of them.
EMAIL_CORRELATION_RULES = (
    {
        "rule": "sender_mismatch_with_credentials",
        "requires_all": ("reply_to_mismatch", "credential_language"),
        "requires_any": (),
        "weight": 10,
        "title": "Sender mismatch combined with credential-related language",
        "explanation": (
            "The email directs replies to a different domain while also "
            "requesting login, verification, password, or account-related "
            "action. This combination is more concerning than either signal "
            "alone. It does not prove phishing."
        ),
    },
    {
        "rule": "suspicious_link_with_credentials",
        "requires_all": ("suspicious_embedded_link", "credential_language"),
        "requires_any": (),
        "weight": 15,
        "title": "Suspicious link combined with credential-related language",
        "explanation": (
            "The message contains a locally suspicious link and also asks "
            "for a login, password, or account action. The link was not opened."
        ),
    },
    {
        "rule": "urgency_with_credentials",
        "requires_all": ("urgency_language", "credential_language"),
        "requires_any": (),
        "weight": 5,
        "title": "Urgency combined with credential-related language",
        "explanation": (
            "The subject uses pressure language and the message also asks "
            "for an account or sign-in action."
        ),
    },
    {
        "rule": "deceptive_link_with_credentials",
        "requires_all": ("link_text_mismatch", "credential_language"),
        "requires_any": (),
        "weight": 15,
        "title": "Deceptive link presentation combined with credential-related language",
        "explanation": (
            "Visible link text points at a different hostname from the real "
            "target, and the message also asks for a sign-in or account action."
        ),
    },
    {
        "rule": "risky_attachment_with_financial_context",
        "requires_all": ("risky_attachment_extension", "financial_language"),
        "requires_any": (),
        "weight": 10,
        "title": "Risky attachment type combined with financial context",
        "explanation": (
            "The message talks about payment or an invoice and also includes "
            "an attachment type that can run code. The file was not opened."
        ),
    },
    {
        "rule": "reported_auth_failure_with_sender_mismatch",
        "requires_all": ("dmarc_fail",),
        "requires_any": ("reply_to_mismatch", "return_path_mismatch"),
        "weight": 10,
        "title": "Reported authentication failure combined with sender-domain mismatch",
        "explanation": (
            "The supplied email headers report a DMARC failure, and a sender "
            "domain also differs. PhishLens did not independently validate "
            "DMARC. It only read the pasted header text."
        ),
    },
)

