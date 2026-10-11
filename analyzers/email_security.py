"""Local, explainable checks for a parsed email.

These checks describe individual signals. They do not produce an email risk
score, open links, open attachments, or contact another computer.
"""

import re
from email.utils import parseaddr
from urllib.parse import urlsplit

from analyzers.url_analyzer import URLValidationError, analyze_url
from config.email_rules import (
    CREDENTIAL_TERMS,
    FINANCIAL_TERMS,
    GENERIC_GREETINGS,
    RISKY_ATTACHMENT_EXTENSIONS,
    URGENCY_TERMS,
)
from services.risk_engine import HIGH_RISK, SUSPICIOUS, calculate_risk

_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)
_VISIBLE_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_TAG_RE = re.compile(r"(?is)<(script|style)\b.*?>.*?</\1>|<[^>]+>")


def analyze_email_security(parsed_email):
    """Return local indicators and in-memory URL results for a parsed email."""
    indicators = []
    indicators.extend(_address_indicators(parsed_email.get("headers") or {}))
    indicators.extend(_language_indicators(parsed_email))
    embedded_urls = _analyze_embedded_urls(parsed_email.get("urls") or [])
    suspicious_links = _suspicious_link_indicator(embedded_urls)
    if suspicious_links:
        indicators.append(suspicious_links)
    mismatch = _link_mismatch_indicator(parsed_email.get("links") or [])
    if mismatch:
        indicators.append(mismatch)
    indicators.extend(_attachment_indicators(parsed_email.get("attachments") or []))
    indicators.extend(_authentication_indicators(parsed_email.get("authentication") or {}))
    return {
        "indicators": indicators,
        "embedded_urls": embedded_urls,
    }


def _indicator(rule_name, title, severity, explanation, evidence):
    return {
        "rule_name": rule_name,
        "title": title,
        "severity": severity,
        "score_change": 0,
        "explanation": explanation,
        "evidence": evidence,
    }


def _domain_from_header(value):
    if not value:
        return None
    _name, address = parseaddr(str(value))
    address = address.strip().lower().strip("<>")
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().strip(">")
    domain = domain.rstrip(".")
    if not domain or any(character.isspace() for character in domain):
        return None
    return domain


def _display_name(value):
    if not value:
        return ""
    name, _address = parseaddr(str(value))
    return name.strip().strip('"')


def _address_indicators(headers):
    indicators = []
    from_header = headers.get("from")
    from_domain = _domain_from_header(from_header)
    reply_domain = _domain_from_header(headers.get("reply_to"))
    return_domain = _domain_from_header(headers.get("return_path"))

    if from_domain and reply_domain and from_domain != reply_domain:
        indicators.append(
            _indicator(
                "reply_to_mismatch",
                "From and Reply-To domains differ",
                "medium",
                (
                    "The Reply-To address uses a different domain from the From "
                    "address. That can be worth reviewing, although legitimate "
                    "email may also use a different reply address."
                ),
                f"From domain: {from_domain}\nReply-To domain: {reply_domain}",
            )
        )

    if from_domain and return_domain and from_domain != return_domain:
        indicators.append(
            _indicator(
                "return_path_mismatch",
                "From and Return-Path domains differ",
                "low",
                (
                    "The Return-Path domain differs from the From domain. "
                    "Legitimate mailing services frequently use a different "
                    "Return-Path domain, so this is supporting evidence only."
                ),
                f"From domain: {from_domain}\nReturn-Path domain: {return_domain}",
            )
        )

    display_name = _display_name(from_header)
    referenced = _domains_in_text(display_name)
    conflicting = sorted(
        domain for domain in referenced if from_domain and domain != from_domain
    )
    if conflicting:
        actual = parseaddr(str(from_header or ""))[1] or "Not present"
        indicators.append(
            _indicator(
                "display_name_deception",
                "Sender display name may conflict with actual address",
                "medium",
                (
                    "The visible sender name refers to a domain that is not the "
                    "domain of the actual sending address. This can make the "
                    "sender look like a different organization. It is a signal "
                    "to review, not proof of phishing."
                ),
                (
                    f"Display name: {display_name}\n"
                    f"Actual sender address: {actual}\n"
                    f"Actual sender domain: {from_domain}"
                ),
            )
        )
    return indicators


def _domains_in_text(text):
    if not text:
        return set()
    found = set()
    for match in _DOMAIN_RE.findall(text):
        domain = match.lower().rstrip(".")
        if domain:
            found.add(domain)
    return found


def _readable_text(parsed_email):
    body = parsed_email.get("body") or {}
    plain = body.get("plain_text") or ""
    html = body.get("html_text") or ""
    if html:
        html = _TAG_RE.sub(" ", html)
    return f"{plain}\n{html}".strip()


def _matched_terms(text, terms):
    haystack = (text or "").casefold()
    matched = []
    seen = set()
    for term in terms:
        folded = term.casefold()
        if folded in haystack and folded not in seen:
            seen.add(folded)
            matched.append(term)
    return matched


def _language_indicators(parsed_email):
    indicators = []
    headers = parsed_email.get("headers") or {}
    subject = headers.get("subject") or ""
    readable = _readable_text(parsed_email)
    urgency = _matched_terms(subject, URGENCY_TERMS)
    if urgency:
        indicators.append(
            _indicator(
                "urgency_language",
                "Urgent or pressure-related subject language",
                "low",
                (
                    "The subject contains language that asks the reader to act "
                    "quickly. Urgency alone does not mean the email is phishing."
                ),
                "Matched terms: " + ", ".join(urgency),
            )
        )

    credential = _matched_terms(f"{subject}\n{readable}", CREDENTIAL_TERMS)
    if credential:
        indicators.append(
            _indicator(
                "credential_language",
                "Credential or account-action language detected",
                "medium",
                (
                    "The subject or message mentions signing in, a password, or "
                    "an account action. Those words are common in real account "
                    "email and also in phishing email, so they are context only."
                ),
                "Matched terms: " + ", ".join(credential),
            )
        )

    financial = _matched_terms(f"{subject}\n{readable}", FINANCIAL_TERMS)
    if financial:
        indicators.append(
            _indicator(
                "financial_language",
                "Financial or payment-related language detected",
                "informational",
                (
                    "The message mentions money, billing, or payment. Financial "
                    "language is context only and is not inherently malicious."
                ),
                "Matched terms: " + ", ".join(financial),
            )
        )

    greeting = _generic_greeting(readable)
    if greeting:
        indicators.append(
            _indicator(
                "generic_greeting",
                "Generic recipient greeting",
                "low",
                (
                    "The message opens with a generic greeting instead of a "
                    "person's name. That can appear in bulk mail. It does not "
                    "by itself mean the email is phishing."
                ),
                f"Detected greeting: {greeting}",
            )
        )
    return indicators


def _generic_greeting(readable):
    opening = " ".join((readable or "")[:400].split()).casefold()
    for greeting in GENERIC_GREETINGS:
        if greeting.casefold() in opening:
            return greeting
    return None


def _analyze_embedded_urls(urls):
    results = []
    for url in urls:
        try:
            analyzed = analyze_url(url)
        except URLValidationError:
            continue
        risk = calculate_risk(analyzed["indicators"])
        results.append(
            {
                "url": url,
                "score": risk["final_score"],
                "classification": risk["classification"],
                "indicators": [
                    {
                        "title": indicator["title"],
                        "evidence": indicator.get("evidence") or "",
                        "explanation": indicator.get("explanation") or "",
                    }
                    for indicator in risk["indicators"]
                ],
            }
        )
    return results


def _suspicious_link_indicator(embedded_urls):
    concerning = [
        item
        for item in embedded_urls
        if item["classification"] in (SUSPICIOUS, HIGH_RISK)
    ]
    if not concerning:
        return None
    lines = [
        f"{item['url']} — {item['score']}/100, {item['classification']}"
        for item in concerning
    ]
    return _indicator(
        "suspicious_embedded_link",
        "Suspicious link detected in email",
        "high",
        (
            "One or more links in the message received Suspicious or High Risk "
            "from the local URL rules. The link text was not opened."
        ),
        "\n".join(lines),
    )


def _host_of(url):
    host = urlsplit(url).hostname
    if not host:
        return None
    return host.lower().rstrip(".")


def _visible_host(text):
    if not text:
        return None
    compact = " ".join(text.split())
    match = _VISIBLE_URL_RE.search(compact)
    if match:
        return _host_of(match.group(0))
    stripped = compact.strip("<>").rstrip(".")
    if _DOMAIN_RE.fullmatch(stripped):
        return stripped.lower()
    return None


def _hosts_differ(left, right):
    if not left or not right:
        return False
    left = left.lower().rstrip(".")
    right = right.lower().rstrip(".")
    if left == right or left.endswith("." + right) or right.endswith("." + left):
        return False
    return True


def _link_mismatch_indicator(links):
    mismatches = []
    for link in links:
        href = (link.get("href") or "").strip()
        visible = link.get("text") or ""
        visible_host = _visible_host(visible)
        actual_host = _host_of(href) if href.lower().startswith(("http://", "https://")) else None
        if _hosts_differ(visible_host, actual_host):
            mismatches.append((visible.strip(), href))
    if not mismatches:
        return None
    evidence = "\n\n".join(
        f"Displayed:\n{visible}\n\nActual destination:\n{href}"
        for visible, href in mismatches
    )
    return _indicator(
        "link_text_mismatch",
        "Displayed link destination differs from actual link",
        "high",
        (
            "The visible text looks like one web address, while the link "
            "target is a different hostname. The addresses were compared as "
            "text. The destination was not visited."
        ),
        evidence,
    )


def _attachment_indicators(attachments):
    indicators = []
    risky = []
    doubled = []
    risky_set = {extension.lower() for extension in RISKY_ATTACHMENT_EXTENSIONS}
    for attachment in attachments:
        filename = attachment.get("filename") or ""
        lowered = filename.strip().lower()
        if "." not in lowered:
            continue
        parts = lowered.split(".")
        extension = "." + parts[-1]
        if extension in risky_set:
            risky.append((filename, extension))
        if len(parts) >= 3 and extension in risky_set:
            doubled.append(filename)
    if risky:
        evidence = "\n".join(
            f"Filename: {filename}\nExtension: {extension}"
            for filename, extension in risky
        )
        indicators.append(
            _indicator(
                "risky_attachment_extension",
                "Potentially risky attachment type",
                "high",
                (
                    "An attachment filename ends with a file type that can run "
                    "code when opened. Only the filename was checked. The file "
                    "was not opened, saved, or examined, and this does not mean "
                    "it contains malware."
                ),
                evidence,
            )
        )
    if doubled:
        indicators.append(
            _indicator(
                "misleading_double_extension",
                "Attachment uses a potentially misleading double extension",
                "high",
                (
                    "The filename has an extra extension after another name, and "
                    "the final extension is a type that can run code. A reader "
                    "might notice only the earlier name. The file was not opened."
                ),
                "Filename: " + "\nFilename: ".join(doubled),
            )
        )
    return indicators


def _authentication_indicators(authentication):
    text = "\n".join(
        authentication.get("authentication_results") or []
    )
    text = text + "\n" + "\n".join(authentication.get("received_spf") or [])
    folded = text.casefold()
    indicators = []
    checks = (
        (
            "spf=fail",
            "spf_fail",
            "Email header reports SPF failure",
            "an SPF failure",
        ),
        (
            "spf=softfail",
            "spf_softfail",
            "Email header reports SPF soft failure",
            "an SPF soft failure",
        ),
        (
            "dkim=fail",
            "dkim_fail",
            "Email header reports DKIM failure",
            "a DKIM failure",
        ),
        (
            "dmarc=fail",
            "dmarc_fail",
            "Email header reports DMARC failure",
            "a DMARC failure",
        ),
    )
    for token, rule_name, title, phrase in checks:
        if token in folded:
            indicators.append(
                _indicator(
                    rule_name,
                    title,
                    "medium" if token != "spf=softfail" else "low",
                    (
                        f"The supplied email authentication header reports {phrase}. "
                        "PhishLens is reading the pasted header text. It does not "
                        "independently verify SPF, DKIM, or DMARC."
                    ),
                    f"Reported value: {token}",
                )
            )
    return indicators
