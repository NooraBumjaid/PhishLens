"""Parse pasted email text locally.

This module does not score email, contact mail servers, resolve domains,
or open URLs and attachments.
"""

import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

from config.security import MAX_EMAIL_BYTES, MAX_EMAIL_CHARS

# Compatibility alias used by tests and callers that prefer a single name.
MAX_EMAIL_INPUT_LENGTH = MAX_EMAIL_CHARS

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class EmailValidationError(ValueError):
    """The pasted email cannot be analyzed."""


class _HrefCollector(HTMLParser):
    """Collect href values and anchor text without loading the document."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        href = None
        for name, value in attrs:
            if name == "href" and value:
                href = value.strip()
                self.hrefs.append(href)
        self._href = href
        self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag != "a" or self._href is None:
            return
        self.links.append(
            {
                "text": "".join(self._text).strip(),
                "href": self._href,
            }
        )
        self._href = None
        self._text = []


def validate_email_input(raw_email):
    """Reject empty or oversized email text before parsing.

    Both character and UTF-8 byte limits apply. Dense Unicode can exceed the
    byte limit even when the character count is still under the character cap.
    """
    if raw_email is None:
        raw_email = ""
    if len(raw_email) > MAX_EMAIL_CHARS:
        raise EmailValidationError(
            "This email is too large to analyze. The maximum length is 100,000 characters."
        )
    encoded_size = len(raw_email.encode("utf-8", errors="surrogateescape"))
    if encoded_size > MAX_EMAIL_BYTES:
        raise EmailValidationError(
            "This email is too large to analyze. The maximum size is 100 KB."
        )
    if not raw_email.strip():
        raise EmailValidationError("Please paste an email before analyzing.")
    return raw_email


def parse_email(raw_email):
    """Return headers, body text, URL strings, and attachment metadata."""
    raw_email = validate_email_input(raw_email)
    # BytesParser preserves UTF-8 bodies. Parser.parsestr() can corrupt
    # non-ASCII content even when charset=utf-8 is declared.
    message = BytesParser(policy=policy.default).parsebytes(
        raw_email.encode("utf-8", errors="surrogateescape")
    )
    plain_parts, html_parts, attachments = _collect_parts(message)
    plain_text = "\n".join(plain_parts) if plain_parts else None
    html_text = "\n".join(html_parts) if html_parts else None
    urls, links = _extract_urls(plain_text, html_text)
    return {
        "headers": {
            "from": _header_value(message, "from"),
            "to": _header_value(message, "to"),
            "reply_to": _header_value(message, "reply-to"),
            "subject": _header_value(message, "subject"),
            "date": _header_value(message, "date"),
            "message_id": _header_value(message, "message-id"),
            "return_path": _header_value(message, "return-path"),
        },
        "received_headers": _header_values(message, "received"),
        "authentication": {
            "authentication_results": _header_values(message, "authentication-results"),
            "received_spf": _header_values(message, "received-spf"),
            "dkim_signatures": _header_values(message, "dkim-signature"),
        },
        "body": {
            "plain_text": plain_text,
            "html_text": html_text,
        },
        "urls": urls,
        "links": links,
        "attachments": attachments,
    }


def _header_value(message, name):
    value = message.get(name)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _header_values(message, name):
    values = message.get_all(name) or []
    collected = []
    for value in values:
        text = str(value).strip()
        if text:
            collected.append(text)
    return collected


def _part_text(part):
    try:
        content = part.get_content()
    except (LookupError, UnicodeError, ValueError, TypeError):
        payload = part.get_payload(decode=True) or b""
        if isinstance(payload, str):
            return payload
        return payload.decode("utf-8", errors="replace")
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return str(content)


def _collect_parts(message):
    plain_parts = []
    html_parts = []
    attachments = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disposition == "attachment" or (
            filename and content_type not in ("text/plain", "text/html")
        ):
            payload = part.get_payload(decode=True)
            attachments.append(
                {
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(payload) if isinstance(payload, (bytes, bytearray)) else 0,
                }
            )
            continue
        if content_type == "text/html":
            html_parts.append(_part_text(part))
        elif content_type == "text/plain":
            plain_parts.append(_part_text(part))
    return plain_parts, html_parts, attachments


def _clean_url(value):
    return value.rstrip(".,;:)>]\"'")


def _add_url(found, seen, value):
    if not value:
        return
    url = _clean_url(value.strip())
    lowered = url.lower()
    if not lowered.startswith(("http://", "https://")):
        return
    if url in seen:
        return
    seen.add(url)
    found.append(url)


def _extract_urls(plain_text, html_text):
    found = []
    seen = set()
    links = []
    for text in (plain_text, html_text):
        if not text:
            continue
        for match in _URL_RE.findall(text):
            _add_url(found, seen, match)
    if html_text:
        collector = _HrefCollector()
        try:
            collector.feed(html_text)
            collector.close()
        except Exception:
            return found, links
        for href in collector.hrefs:
            _add_url(found, seen, href)
        links = collector.links
    return found, links
