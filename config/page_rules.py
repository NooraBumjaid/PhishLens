"""Centralized phrases and weights for static page-content analysis."""

from config.scoring_rules import REFERENCE_DOMAINS

MAX_TITLE_LENGTH = 200
MAX_VISIBLE_TEXT_CHARS = 20000
MAX_EVIDENCE_LENGTH = 120

BASE_PAGE_SCORE = 0

PAGE_BRAND_DOMAINS = dict(REFERENCE_DOMAINS)

URGENCY_PHRASES = (
    "urgent",
    "immediately",
    "act now",
    "final warning",
    "account suspended",
    "account will be suspended",
    "within 24 hours",
    "pay now",
    "penalty",
    "fine",
    "overdue",
    "avoid legal action",
)

FINE_PENALTY_PHRASES = (
    "traffic fine",
    "traffic penalty",
    "unpaid fine",
    "parking fine",
    "violation",
    "penalty notice",
    "pay your fine",
    "unpaid traffic",
    "traffic penalty",
)

CREDENTIAL_LANGUAGE_PHRASES = (
    "verify your account",
    "confirm your identity",
    "login to continue",
    "sign in to verify",
    "update your password",
    "security verification",
    "verify your information",
    "account verification",
)

CREDENTIAL_FIELD_TOKENS = (
    "username",
    "user_name",
    "userid",
    "user_id",
    "email",
    "e-mail",
    "account",
    "password",
    "passwd",
    "passcode",
    "pin",
    "otp",
    "one-time",
    "verification code",
    "verify",
)

PAYMENT_FIELD_TOKENS = (
    "card number",
    "card_number",
    "cardnumber",
    "credit card",
    "creditcard",
    "debit card",
    "cvv",
    "cvc",
    "expiry",
    "expiration",
    "exp_date",
    "billing",
    "payment",
    "cardholder",
)

SENSITIVE_FIELD_TOKENS = (
    "national id",
    "national_id",
    "passport",
    "date of birth",
    "date_of_birth",
    "dob",
    "ssn",
    "social security",
)

PAGE_RULES = {
    "password_login_form": {
        "weight": 15,
        "severity": "medium",
        "title": "Password / Login Form Detected",
        "description": (
            "The page contains a password input field, indicating that it "
            "requests authentication information."
        ),
    },
    "credential_input_fields": {
        "weight": 10,
        "severity": "medium",
        "title": "Credential Input Fields Detected",
        "description": (
            "The page includes input fields commonly associated with "
            "usernames, emails, passwords, or verification codes."
        ),
    },
    "payment_information_requested": {
        "weight": 20,
        "severity": "high",
        "title": "Payment Information Requested",
        "description": (
            "The page appears to request payment or card details. Legitimate "
            "sites also use payment forms, so this is a risk-relevant "
            "characteristic rather than proof of phishing."
        ),
    },
    "sensitive_information_requested": {
        "weight": 10,
        "severity": "medium",
        "title": "Sensitive Information Requested",
        "description": (
            "The page appears to request sensitive personal identifiers such "
            "as a national ID, passport, or date of birth."
        ),
    },
    "urgency_pressure_language": {
        "weight": 10,
        "severity": "medium",
        "title": "Urgency / Pressure Language",
        "description": (
            "Visible page text includes urgency or pressure wording often "
            "used in social-engineering messages."
        ),
    },
    "fine_penalty_language": {
        "weight": 10,
        "severity": "medium",
        "title": "Fine or Penalty Payment Language",
        "description": (
            "Visible page text refers to fines, penalties, or similar payment "
            "notices. This is a contextual signal, not proof of malice."
        ),
    },
    "credential_verification_language": {
        "weight": 10,
        "severity": "medium",
        "title": "Credential / Account Verification Language",
        "description": (
            "Visible page text asks the visitor to verify an account, "
            "identity, or password."
        ),
    },
    "external_form_submission": {
        "weight": 25,
        "severity": "high",
        "title": "External Form Submission",
        "description": (
            "The page contains a form configured to submit information to a "
            "different domain."
        ),
    },
    "javascript_form_action": {
        "weight": 5,
        "severity": "low",
        "title": "Unusual JavaScript Form Action",
        "description": (
            "A form uses a javascript: action. PhishLens does not execute it; "
            "the unusual destination is noted for review."
        ),
    },
    "brand_domain_mismatch": {
        "weight": 25,
        "severity": "high",
        "title": "Possible Brand / Domain Mismatch",
        "description": (
            "Prominent page content appears to reference a known brand, but "
            "the destination hostname is outside that brand’s expected domain."
        ),
    },
}

PAGE_CORRELATION_RULES = (
    {
        "rule": "urgent_payment_request",
        "requires": ("payment_information_requested", "urgency_pressure_language"),
        "weight": 15,
        "title": "Urgent Payment Request",
        "explanation": (
            "Payment-related fields appear together with urgency or pressure language."
        ),
    },
    {
        "rule": "penalty_with_payment_request",
        "requires": ("fine_penalty_language", "payment_information_requested"),
        "weight": 15,
        "title": "Penalty + Payment Request",
        "explanation": (
            "Fine or penalty wording appears together with payment-related fields."
        ),
    },
    {
        "rule": "credential_request_with_login_form",
        "requires": ("credential_verification_language", "password_login_form"),
        "weight": 10,
        "title": "Credential Request with Login Form",
        "explanation": (
            "Account-verification language appears together with a password login form."
        ),
    },
    {
        "rule": "brand_mismatch_with_login",
        "requires": ("brand_domain_mismatch", "password_login_form"),
        "weight": 15,
        "title": "Brand Mismatch with Login Form",
        "explanation": (
            "A possible brand/domain mismatch appears together with a login form."
        ),
    },
    {
        "rule": "external_submission_with_credentials",
        "requires": ("external_form_submission", "credential_input_fields"),
        "weight": 15,
        "title": "External Submission with Credentials",
        "explanation": (
            "Credential-related fields appear in a form that submits to another domain."
        ),
    },
)
