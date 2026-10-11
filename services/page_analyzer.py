"""Static HTML inspection for phishing-related page characteristics.

This module never executes JavaScript, never submits forms, and never loads
images, iframes, CSS, or other remote resources.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from config.page_rules import (
    CREDENTIAL_FIELD_TOKENS,
    CREDENTIAL_LANGUAGE_PHRASES,
    FINE_PENALTY_PHRASES,
    MAX_EVIDENCE_LENGTH,
    MAX_TITLE_LENGTH,
    MAX_VISIBLE_TEXT_CHARS,
    PAGE_BRAND_DOMAINS,
    PAGE_RULES,
    PAYMENT_FIELD_TOKENS,
    SENSITIVE_FIELD_TOKENS,
    URGENCY_PHRASES,
)


def _clip(text, limit=MAX_EVIDENCE_LENGTH):
    value = re.sub(r"\s+", " ", (text or "")).strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def _normalize_text(text):
    return re.sub(r"\s+", " ", (text or "")).strip()


def _field_blob(element):
    parts = [
        element.get("type"),
        element.get("name"),
        element.get("id"),
        element.get("placeholder"),
        element.get("autocomplete"),
        element.get("aria-label"),
    ]
    input_id = element.get("id")
    if input_id:
        form = element.find_parent("form")
        root = form or element
        label = None
        if hasattr(root, "find"):
            label = root.find("label", attrs={"for": input_id})
        if label:
            parts.append(label.get_text(" ", strip=True))
    return " ".join(str(part or "") for part in parts).lower()


def _contains_token(blob, tokens):
    for token in tokens:
        if token in blob:
            return token
    return None


def _find_phrase(text, phrases):
    lowered = (text or "").lower()
    for phrase in phrases:
        if phrase in lowered:
            return phrase
    return None


def _hostname(url):
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.lower().rstrip(".")


def _same_site(page_host, action_host):
    if not page_host or not action_host:
        return True
    if page_host == action_host:
        return True
    return page_host.endswith("." + action_host) or action_host.endswith("." + page_host)


def _brand_host_matches(page_host, brand_domain):
    if not page_host or not brand_domain:
        return False
    return page_host == brand_domain or page_host.endswith("." + brand_domain)


def _make_indicator(rule_name, evidence):
    rule = PAGE_RULES[rule_name]
    return {
        "rule": rule_name,
        "title": rule["title"],
        "severity": rule["severity"],
        "score_change": rule["weight"],
        "explanation": rule["description"],
        "evidence": _clip(evidence),
    }


def extract_page_document(html_text, page_url):
    """Parse HTML and return title, visible text, and structural notes."""
    soup = BeautifulSoup(html_text or "", "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    title = ""
    if soup.title and soup.title.string:
        title = _normalize_text(soup.title.get_text(" ", strip=True))
    title = title[:MAX_TITLE_LENGTH]

    visible = _normalize_text(soup.get_text(" ", strip=True))
    limited_js = False
    # Re-parse original to detect script-heavy pages without executing them.
    raw_soup = BeautifulSoup(html_text or "", "html.parser")
    script_count = len(raw_soup.find_all("script"))
    if script_count >= 3 and len(visible) < 80:
        limited_js = True

    iframe_count = len(raw_soup.find_all("iframe"))
    forms = raw_soup.find_all("form")
    inputs = raw_soup.find_all("input")

    headings = []
    for heading in raw_soup.find_all(["h1", "h2"]):
        text = _normalize_text(heading.get_text(" ", strip=True))
        if text:
            headings.append(text[:MAX_TITLE_LENGTH])

    return {
        "page_url": page_url,
        "title": title,
        "visible_text": visible[:MAX_VISIBLE_TEXT_CHARS],
        "forms": forms,
        "inputs": inputs,
        "headings": headings,
        "iframe_count": iframe_count,
        "script_count": script_count,
        "limited_static_content": limited_js,
        "soup": raw_soup,
    }


def analyze_page_html(html_text, page_url):
    """Return page indicators for a single HTML document."""
    document = extract_page_document(html_text, page_url)
    indicators = []
    triggered = set()
    page_host = _hostname(page_url)
    visible = document["visible_text"]
    title = document["title"]

    def add(rule_name, evidence):
        if rule_name in triggered:
            return
        triggered.add(rule_name)
        indicators.append(_make_indicator(rule_name, evidence))

    password_found = False
    credential_token = None
    payment_token = None
    sensitive_hits = set()

    for element in document["inputs"]:
        input_type = (element.get("type") or "text").lower()
        blob = _field_blob(element)
        if input_type == "password":
            password_found = True
        token = _contains_token(blob, CREDENTIAL_FIELD_TOKENS)
        if token or input_type in {"email", "password"}:
            credential_token = token or input_type
        pay = _contains_token(blob, PAYMENT_FIELD_TOKENS)
        if pay:
            payment_token = pay
        sensitive = _contains_token(blob, SENSITIVE_FIELD_TOKENS)
        if sensitive:
            sensitive_hits.add(sensitive)

    if password_found:
        add("password_login_form", "input type=password")
    if credential_token:
        add("credential_input_fields", f"Matched field token: {credential_token}")
    if payment_token:
        add("payment_information_requested", f"Matched field token: {payment_token}")
    if len(sensitive_hits) >= 2 or (
        sensitive_hits and {"passport", "national id", "national_id", "ssn"} & sensitive_hits
    ):
        add(
            "sensitive_information_requested",
            "Matched sensitive fields: " + ", ".join(sorted(sensitive_hits)),
        )

    urgency = _find_phrase(visible, URGENCY_PHRASES) or _find_phrase(title, URGENCY_PHRASES)
    if urgency:
        add("urgency_pressure_language", f'Matched phrase: "{urgency}"')

    fine = _find_phrase(visible, FINE_PENALTY_PHRASES) or _find_phrase(title, FINE_PENALTY_PHRASES)
    if fine:
        add("fine_penalty_language", f'Matched phrase: "{fine}"')

    credential_language = _find_phrase(visible, CREDENTIAL_LANGUAGE_PHRASES) or _find_phrase(
        title, CREDENTIAL_LANGUAGE_PHRASES
    )
    if credential_language:
        add(
            "credential_verification_language",
            f'Matched phrase: "{credential_language}"',
        )

    for form in document["forms"]:
        action = (form.get("action") or "").strip()
        if action.lower().startswith("javascript:"):
            add("javascript_form_action", f"Form action: {action[:80]}")
            continue
        if action in {"", "#"}:
            continue
        absolute = urljoin(page_url, action)
        action_host = _hostname(absolute)
        if action_host and not _same_site(page_host, action_host):
            add(
                "external_form_submission",
                f"Form action host: {action_host}",
            )

    # Conservative brand mismatch: brand in title or heading + auth/payment context.
    auth_context = bool(
        password_found
        or credential_token
        or payment_token
        or credential_language
        or "payment_information_requested" in triggered
    )
    prominent = " ".join([title] + document["headings"]).lower()
    for brand, expected_domain in PAGE_BRAND_DOMAINS.items():
        brand_pattern = re.compile(rf"\b{re.escape(brand)}\b", re.IGNORECASE)
        in_title = bool(brand_pattern.search(title or ""))
        in_heading = any(brand_pattern.search(item) for item in document["headings"])
        if not (in_title or in_heading):
            continue
        if not auth_context:
            continue
        if _brand_host_matches(page_host, expected_domain):
            continue
        evidence_source = "title" if in_title else "heading"
        add(
            "brand_domain_mismatch",
            f'Brand "{brand}" in {evidence_source}; host is {page_host or "unknown"}',
        )
        break

    return {
        "page_url": page_url,
        "page_title": title,
        "indicators": indicators,
        "limited_static_content": document["limited_static_content"],
        "iframe_count": document["iframe_count"],
        "script_count": document["script_count"],
    }
