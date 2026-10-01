"""Parse a URL and run security checks on the text.

This module only inspects the URL text. It does not visit the website.
"""

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit

from config.scoring_rules import (
    DOMAIN_SIMILARITY_THRESHOLD,
    EXCESSIVE_SUBDOMAIN_LEVELS,
    LONG_URL_THRESHOLD,
    REFERENCE_DOMAINS,
    STANDARD_PORTS,
    SUSPICIOUS_URL_KEYWORDS,
    URL_RULES,
    URL_SHORTENERS,
)


class URLValidationError(Exception):
    """Raised when the submitted text is not a usable URL."""


def parse_url(url):
    """Break a URL string into its main parts."""
    submitted_url = url.strip()
    parts = urlsplit(submitted_url)

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as error:
        raise URLValidationError(
            "Please enter a valid URL, such as https://example.com."
        ) from error

    if not parts.scheme or not hostname:
        raise URLValidationError(
            "Please enter a full URL that includes http:// or https:// and a hostname."
        )

    scheme = parts.scheme.lower()
    hostname = hostname.lower()
    path = parts.path
    query = parts.query

    if ":" in hostname:
        host_for_url = f"[{hostname}]"
    else:
        host_for_url = hostname

    if port is not None:
        netloc = f"{host_for_url}:{port}"
    else:
        netloc = host_for_url

    normalized_url = urlunsplit((scheme, netloc, path, query, ""))

    return {
        "submitted_url": submitted_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
        "query": query,
    }


def check_protocol(parsed_url):
    """Check whether the URL uses HTTPS or plain HTTP."""
    scheme = (parsed_url.get("scheme") or "").lower()

    if scheme == "https":
        return {
            "rule": "https_present",
            "detected": True,
            "severity": "positive",
            "score_change": URL_RULES["https_present"]["weight"],
            "title": "HTTPS detected",
            "explanation": URL_RULES["https_present"]["description"],
        }

    if scheme == "http":
        return {
            "rule": "http_only",
            "detected": True,
            "severity": "warning",
            "score_change": URL_RULES["http_only"]["weight"],
            "title": "HTTP connection",
            "explanation": URL_RULES["http_only"]["description"],
        }

    return None


def check_ip_hostname(hostname):
    """Check whether the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return None

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return None

    return {
        "rule": "ip_hostname",
        "detected": True,
        "severity": "warning",
        "score_change": URL_RULES["ip_hostname"]["weight"],
        "title": "IP address used instead of domain",
        "explanation": URL_RULES["ip_hostname"]["description"],
    }


def check_url_length(url):
    """Flag a URL whose text is longer than LONG_URL_THRESHOLD."""
    if not url:
        return None

    url_length = len(url)
    if url_length <= LONG_URL_THRESHOLD:
        return None

    return {
        "rule": "long_url",
        "detected": True,
        "severity": "warning",
        "score_change": URL_RULES["long_url"]["weight"],
        "title": "Unusually long URL",
        "explanation": URL_RULES["long_url"]["description"],
        "evidence": f"URL length: {url_length} characters",
    }


def check_subdomains(hostname):
    """Flag a hostname with many nested subdomain labels.

    Heuristic only: the last two dot-separated labels are treated as the
    domain, and every label before them is counted as a subdomain. This
    does not determine the real public suffix. IP addresses are skipped
    because they are not domain names.
    """
    if not hostname:
        return None

    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    labels = [label for label in hostname.split(".") if label]
    subdomain_count = max(len(labels) - 2, 0)
    if subdomain_count <= EXCESSIVE_SUBDOMAIN_LEVELS:
        return None

    return {
        "rule": "excessive_subdomains",
        "detected": True,
        "severity": "warning",
        "score_change": URL_RULES["excessive_subdomains"]["weight"],
        "title": "Excessive subdomains",
        "explanation": URL_RULES["excessive_subdomains"]["description"],
        "evidence": f"Detected subdomain levels: {subdomain_count}",
    }


def check_at_symbol(url):
    """Flag a URL that contains an @ character."""
    if not url or "@" not in url:
        return None

    return {
        "rule": "at_symbol",
        "detected": True,
        "severity": "warning",
        "score_change": URL_RULES["at_symbol"]["weight"],
        "title": "@ symbol detected",
        "explanation": URL_RULES["at_symbol"]["description"],
    }


def check_punycode(hostname):
    """Flag a hostname that contains a Punycode label (xn--)."""
    if not hostname:
        return None

    labels = [label for label in hostname.split(".") if label]
    has_punycode = any(label.lower().startswith("xn--") for label in labels)
    if not has_punycode:
        return None

    return {
        "rule": "punycode",
        "detected": True,
        "severity": "warning",
        "score_change": URL_RULES["punycode"]["weight"],
        "title": "Punycode domain detected",
        "explanation": URL_RULES["punycode"]["description"],
    }


def check_suspicious_keywords(parsed_url):
    """Flag login-style words in the hostname, path, or query.

    Matching is case-insensitive and uses whole words, so a repeated word
    such as /login/login/login counts once. Points per word and the cap
    come from the suspicious_keywords rule in the scoring configuration.
    """
    text = " ".join(
        [
            parsed_url.get("hostname") or "",
            parsed_url.get("path") or "",
            parsed_url.get("query") or "",
        ]
    )
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    keyword_rule = URL_RULES["suspicious_keywords"]
    keyword_set = set(SUSPICIOUS_URL_KEYWORDS)

    found = []
    seen = set()
    for token in tokens:
        if token in keyword_set and token not in seen:
            seen.add(token)
            found.append(token)

    if not found:
        return None

    score_change = min(
        len(found) * keyword_rule["weight_per_keyword"],
        keyword_rule["max_contribution"],
    )
    return {
        "rule": "suspicious_keywords",
        "detected": True,
        "severity": "warning",
        "score_change": score_change,
        "title": "Suspicious keywords detected",
        "evidence": "Detected keywords: " + ", ".join(found),
        "explanation": keyword_rule["description"],
    }


def check_suspicious_port(parsed_url):
    """Flag an explicit HTTP or HTTPS port other than 80 or 443."""
    scheme = (parsed_url.get("scheme") or "").lower()
    port = parsed_url.get("port")
    standard_port = STANDARD_PORTS.get(scheme)

    if standard_port is None or port is None or port == standard_port:
        return None

    scheme_label = scheme.upper()
    return {
        "rule": "suspicious_port",
        "detected": True,
        "severity": "warning",
        "score_change": URL_RULES["suspicious_port"]["weight"],
        "title": "Non-standard port detected",
        "evidence": f"{scheme_label} URL explicitly uses port {port}",
        "explanation": URL_RULES["suspicious_port"]["description"],
    }


def check_url_shortener(hostname):
    """Flag a hostname that is a known URL-shortening service."""
    if not hostname:
        return None

    normalized = hostname.lower().rstrip(".")
    shorteners = {name.lower() for name in URL_SHORTENERS}
    if normalized not in shorteners:
        return None

    return {
        "rule": "url_shortener",
        "detected": True,
        "severity": "warning",
        "score_change": URL_RULES["url_shortener"]["weight"],
        "title": "URL shortening service detected",
        "evidence": f"Shortening service: {normalized}",
        "explanation": URL_RULES["url_shortener"]["description"],
    }


def _is_ip_address(hostname):
    """Return True when the hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _is_reference_hostname(hostname, reference_domain):
    """Return True for a reference domain or one of its real subdomains."""
    return hostname == reference_domain or hostname.endswith("." + reference_domain)


def _heuristic_domain_label(hostname):
    """Return the label just before the final hostname suffix.

    The last two dot-separated labels are treated as the domain. This is
    a heuristic, not a public-suffix lookup, so names such as example.co.uk
    are not handled perfectly.
    """
    labels = [label for label in hostname.split(".") if label]
    if len(labels) < 2:
        return None
    return labels[-2]


def _confusable_label(label):
    """Fold lookalike characters that this MVP compares as the same letter."""
    return label.replace("0", "o").replace("1", "l")


def _lookalike_examples(candidate_label, reference_label):
    """Describe substitutions that were folded before matching."""
    examples = []
    if "0" in candidate_label and "0" not in reference_label:
        examples.append('"0" resembles "o"')
    if "1" in candidate_label and "1" not in reference_label:
        examples.append('"1" resembles "l"')
    return examples


def _impersonation_evidence(reference_domain, text_ratio, lookalike_examples):
    """Build heuristic evidence without treating folded text as the similarity."""
    sentences = [f"Hostname resembles {reference_domain}."]
    if lookalike_examples:
        example_text = "; ".join(lookalike_examples)
        sentences.append(
            "Lookalike character substitution detected "
            f"(for example, {example_text})."
        )
    similarity_percent = round(text_ratio * 100)
    sentences.append(
        f"Text similarity: {similarity_percent}%. "
        "This percentage is only a heuristic."
    )
    return " ".join(sentences)


def check_domain_impersonation(hostname):
    """Flag a hostname that resembles a configured reference domain.

    Only the hostname is checked. Words in the path or query are ignored.
    The exact reference domain and its genuine subdomains are not flagged.
    IP addresses are not compared. Lookalike characters such as 0 and 1 can
    help decide that a match exists, but the displayed text similarity uses
    the original lowercase labels. A match is a heuristic, not proof that
    the domain is impersonating anyone.
    """
    if not hostname or _is_ip_address(hostname):
        return None

    normalized_host = hostname.lower().rstrip(".")
    candidate_label = _heuristic_domain_label(normalized_host)
    if not candidate_label:
        return None

    folded_candidate = _confusable_label(candidate_label)
    best_domain = None
    best_reference_label = None
    best_folded_ratio = 0
    best_text_ratio = 0

    for reference_domain in REFERENCE_DOMAINS.values():
        reference_domain = reference_domain.lower()
        if _is_reference_hostname(normalized_host, reference_domain):
            continue

        reference_label = reference_domain.split(".")[0]
        folded_ratio = SequenceMatcher(
            None,
            folded_candidate,
            _confusable_label(reference_label),
        ).ratio()
        if folded_ratio > best_folded_ratio:
            best_folded_ratio = folded_ratio
            best_text_ratio = SequenceMatcher(
                None,
                candidate_label,
                reference_label,
            ).ratio()
            best_domain = reference_domain
            best_reference_label = reference_label

    if best_domain is None or best_folded_ratio < DOMAIN_SIMILARITY_THRESHOLD:
        return None

    substitution_caused_match = best_text_ratio < DOMAIN_SIMILARITY_THRESHOLD
    lookalike_examples = []
    if substitution_caused_match:
        lookalike_examples = _lookalike_examples(
            candidate_label,
            best_reference_label,
        )

    rule = URL_RULES["possible_typosquatting"]
    return {
        "rule": "possible_typosquatting",
        "detected": True,
        "severity": rule["severity"],
        "score_change": rule["weight"],
        "title": "Possible domain impersonation",
        "evidence": _impersonation_evidence(
            best_domain,
            best_text_ratio,
            lookalike_examples,
        ),
        "explanation": rule["description"],
    }


def analyze_url(url):
    """Parse a URL and collect every indicator the current rules find."""
    parsed = parse_url(url)
    indicators = []

    for indicator in (
        check_protocol(parsed),
        check_ip_hostname(parsed["hostname"]),
        check_url_length(parsed["submitted_url"]),
        check_subdomains(parsed["hostname"]),
        check_at_symbol(parsed["submitted_url"]),
        check_punycode(parsed["hostname"]),
        check_suspicious_keywords(parsed),
        check_suspicious_port(parsed),
        check_url_shortener(parsed["hostname"]),
        check_domain_impersonation(parsed["hostname"]),
    ):
        if indicator:
            indicators.append(indicator)

    return {
        "parsed": parsed,
        "indicators": indicators,
    }
