"""Configurable thresholds for the combined PhishLens assessment."""

from config.scoring_rules import LOW_RISK_MAX, SUSPICIOUS_MAX

# Combined score classification uses the same URL thresholds.
COMBINED_LOW_RISK_MAX = LOW_RISK_MAX
COMBINED_SUSPICIOUS_MAX = SUSPICIOUS_MAX

# Cross-layer reinforcement (applied at most once each).
CROSS_LAYER_ADJUSTMENTS = {
    "suspicious_final_with_credentials": {
        "weight": 10,
        "title": "Suspicious destination with credential collection",
        "explanation": (
            "The final destination shows suspicious URL characteristics and the "
            "page contains credential-collection signals."
        ),
    },
    "suspicious_final_with_payment": {
        "weight": 10,
        "title": "Suspicious destination with payment collection",
        "explanation": (
            "The final destination shows suspicious URL characteristics and the "
            "page requests payment or card details."
        ),
    },
    "shortener_with_risky_final": {
        "weight": 10,
        "title": "Shortener hiding a risky destination",
        "explanation": (
            "The submitted URL hides its destination with a shortening service, "
            "and the resolved destination is Suspicious or High Risk."
        ),
    },
}

# VirusTotal supporting evidence — never reduces local risk.
VT_MALICIOUS_BANDS = (
    (6, 30, "vt_malicious_high"),
    (3, 20, "vt_malicious_medium"),
    (1, 10, "vt_malicious_low"),
)
VT_SUSPICIOUS_ONLY_WEIGHT = 5

MAX_ASSESSMENT_REASONS = 6

RECOMMENDATIONS = {
    "low_risk": (
        "No major warning signals were identified in the completed checks. "
        "Continue to verify unexpected requests before entering sensitive "
        "information."
    ),
    "suspicious": (
        "Use caution. Verify the website through an independent trusted source "
        "before entering passwords, payment details, or personal information."
    ),
    "high_risk": (
        "Avoid entering credentials, payment details, or personal information "
        "on this page. Verify the request using an official website or trusted "
        "contact method."
    ),
}

ASSESSMENT_DISCLAIMER = (
    "This assessment is based on the evidence available to PhishLens and is "
    "not a guarantee that a website is safe or malicious."
)

NO_WARNING_GUARANTEE = (
    "No detected warning signals guarantee that a website is safe."
)

CREDENTIAL_PAGE_RULES = frozenset(
    {
        "password_login_form",
        "credential_input_fields",
        "credential_verification_language",
    }
)
PAYMENT_PAGE_RULES = frozenset(
    {
        "payment_information_requested",
        "sensitive_information_requested",
    }
)
