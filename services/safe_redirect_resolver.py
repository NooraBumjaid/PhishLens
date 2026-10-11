"""Safely resolve redirect chains without rendering pages.

Network destinations are validated before every connection. DNS answers are
checked in full, and HTTP(S) connections are pinned to a previously validated
public IP while preserving Host / TLS server_hostname for the original host.
This avoids a silent DNS-rebinding switch to a private address between check
and connect.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import socket
import ssl
from urllib.parse import urljoin, urlsplit, urlunsplit

from config.resolver_settings import (
    ACCEPTED_HTML_CONTENT_TYPES,
    ALLOWED_SCHEMES,
    BLOCKED_HOSTNAME_SUFFIXES,
    BLOCKED_HOSTNAMES,
    CONNECT_TIMEOUT_SECONDS,
    MAX_PAGE_BYTES,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    READ_TIMEOUT_SECONDS,
    REDIRECT_STATUS_CODES,
    USER_AGENT,
)

logger = logging.getLogger(__name__)


class SafeResolveError(Exception):
    """Controlled resolver failure with a public status and reason."""

    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def is_blocked_ip(address):
    """Return True when an IP must not be contacted by the resolver."""
    try:
        ip_obj = ipaddress.ip_address(address)
    except ValueError:
        return True

    # Prefer global routability rather than a short prefix deny-list.
    if not ip_obj.is_global:
        return True

    # Defense in depth for categories that should never be contacted.
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return True

    return False


def _hostname_is_blocked(hostname):
    value = (hostname or "").strip().lower().rstrip(".")
    if not value:
        return True
    if value in BLOCKED_HOSTNAMES:
        return True
    return any(value.endswith(suffix) for suffix in BLOCKED_HOSTNAME_SUFFIXES)


def _format_host_header(hostname, port, scheme):
    default_port = 443 if scheme == "https" else 80
    if ":" in hostname and not hostname.startswith("["):
        host = f"[{hostname}]"
    else:
        host = hostname
    if port is None or port == default_port:
        return host
    return f"{host}:{port}"


def normalize_destination_url(url):
    """Return a stable URL string for loop detection and hop storage."""
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "").lower()
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as error:
        raise SafeResolveError("failed", "The destination URL could not be parsed.") from error

    if not hostname:
        raise SafeResolveError("failed", "The destination URL is missing a hostname.")

    hostname = hostname.lower().rstrip(".")
    if ":" in hostname:
        host_for_url = f"[{hostname}]"
    else:
        host_for_url = hostname

    if port is not None:
        netloc = f"{host_for_url}:{port}"
    else:
        netloc = host_for_url

    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def validate_destination_url(url):
    """Parse and validate a candidate destination before any network use."""
    if url is None or not str(url).strip():
        raise SafeResolveError("failed", "The destination URL is empty or invalid.")

    text = str(url).strip()
    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()

    if scheme not in ALLOWED_SCHEMES:
        raise SafeResolveError(
            "blocked",
            "Only http and https destinations are allowed for inspection.",
        )

    if "@" in (parts.netloc or "") or parts.username is not None or parts.password is not None:
        raise SafeResolveError(
            "blocked",
            "URLs that include embedded user credentials are not allowed.",
        )

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as error:
        raise SafeResolveError(
            "failed",
            "The destination URL has an invalid hostname or port.",
        ) from error

    if not hostname:
        raise SafeResolveError("failed", "The destination URL is missing a hostname.")

    hostname = hostname.lower().rstrip(".")
    if _hostname_is_blocked(hostname):
        raise SafeResolveError(
            "blocked",
            "Localhost and local-only destinations are not allowed.",
        )

    # Literal IP hostnames are validated immediately.
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None and is_blocked_ip(literal_ip):
        raise SafeResolveError(
            "blocked",
            "The destination resolves to a non-public network address.",
        )

    normalized = normalize_destination_url(text)
    return {
        "url": normalized,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "literal_ip": literal_ip,
    }


def dns_lookup(hostname):
    """Resolve a hostname to IP addresses. Patchable in tests."""
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise SafeResolveError(
            "failed",
            "The destination hostname could not be resolved.",
        ) from error

    addresses = []
    for entry in results:
        address = entry[4][0]
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip_obj not in addresses:
            addresses.append(ip_obj)

    if not addresses:
        raise SafeResolveError(
            "failed",
            "The destination hostname could not be resolved.",
        )
    return addresses


def validate_resolved_addresses(addresses):
    """Block when any resolved address is non-public."""
    if not addresses:
        raise SafeResolveError(
            "failed",
            "The destination hostname could not be resolved.",
        )
    for address in addresses:
        if is_blocked_ip(address):
            raise SafeResolveError(
                "blocked",
                "The destination resolves to a non-public network address.",
            )
    return [str(address) for address in addresses]


def select_pinned_ip(addresses):
    """Choose one previously validated public IP for the connection."""
    validated = validate_resolved_addresses(addresses)
    return validated[0]


def prepare_destination(url):
    """Validate URL text, resolve DNS when needed, and return a pinned target."""
    parsed = validate_destination_url(url)
    if parsed["literal_ip"] is not None:
        pinned_ip = str(parsed["literal_ip"])
        validate_resolved_addresses([parsed["literal_ip"]])
    else:
        addresses = dns_lookup(parsed["hostname"])
        pinned_ip = select_pinned_ip(addresses)

    return {
        **parsed,
        "pinned_ip": pinned_ip,
    }


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that dials a validated IP while keeping the Host name."""

    def __init__(self, host, pinned_ip, port=None, timeout=None):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            CONNECT_TIMEOUT_SECONDS,
        )
        self.sock.settimeout(READ_TIMEOUT_SECONDS)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection with IP pinning and hostname TLS verification."""

    def __init__(self, host, pinned_ip, port=None, timeout=None, context=None):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        # TCP dials the validated public IP (DNS-rebinding resistance).
        # TLS SNI + certificate hostname checks still use self.host (original hostname).
        sock = socket.create_connection(
            (self._pinned_ip, self.port),
            CONNECT_TIMEOUT_SECONDS,
        )
        sock.settimeout(READ_TIMEOUT_SECONDS)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def build_tls_context():
    """Build a TLS context with trusted CAs and hostname verification enabled.

    Uses the certifi CA bundle when available so verification does not depend on
    an incomplete platform trust store. Never disables certificate checks.
    """
    cafile = None
    try:
        import certifi

        cafile = certifi.where()
    except ImportError:
        cafile = None

    if cafile:
        context = ssl.create_default_context(cafile=cafile)
    else:
        context = ssl.create_default_context()

    # Defense in depth — create_default_context already enables these.
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


def _read_limited_body(response, max_bytes):
    """Read at most max_bytes from an HTTP response body."""
    chunks = []
    total = 0
    while total < max_bytes:
        chunk = response.read(min(8192, max_bytes - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    truncated = bool(response.read(1))
    return b"".join(chunks), truncated


def _decode_body(raw_body, content_encoding, max_bytes):
    """Decode identity or compressed bodies with a hard decompressed cap."""
    encoding = (content_encoding or "identity").lower()
    if not encoding or encoding == "identity":
        return raw_body[:max_bytes], len(raw_body) > max_bytes

    try:
        import gzip
        import io
        import zlib

        if "gzip" in encoding:
            with gzip.GzipFile(fileobj=io.BytesIO(raw_body)) as handle:
                decoded = handle.read(max_bytes + 1)
        elif "deflate" in encoding:
            decoded = zlib.decompress(raw_body)
            if len(decoded) > max_bytes + 1:
                decoded = decoded[: max_bytes + 1]
        else:
            raise SafeResolveError(
                "failed",
                "Unsupported content encoding for page inspection.",
            )
    except SafeResolveError:
        raise
    except Exception as error:
        raise SafeResolveError(
            "failed",
            "The page response could not be decoded safely.",
        ) from error

    truncated = len(decoded) > max_bytes
    return decoded[:max_bytes], truncated


def http_exchange(url, pinned_ip, max_body_bytes=MAX_RESPONSE_BYTES, include_body=False):
    """Perform one non-redirecting request pinned to a validated IP.

    Patchable in tests. TLS certificate verification remains enabled.
    """
    parsed = validate_destination_url(url)
    scheme = parsed["scheme"]
    hostname = parsed["hostname"]
    port = parsed["port"]
    if port is None:
        port = 443 if scheme == "https" else 80

    path = urlsplit(parsed["url"]).path or "/"
    query = urlsplit(parsed["url"]).query
    request_target = path
    if query:
        request_target = f"{path}?{query}"

    connection = None
    try:
        if scheme == "https":
            context = build_tls_context()
            connection = _PinnedHTTPSConnection(
                hostname,
                pinned_ip,
                port=port,
                timeout=READ_TIMEOUT_SECONDS,
                context=context,
            )
        else:
            connection = _PinnedHTTPConnection(
                hostname,
                pinned_ip,
                port=port,
                timeout=READ_TIMEOUT_SECONDS,
            )

        connection.putrequest("GET", request_target, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", _format_host_header(hostname, parsed["port"], scheme))
        connection.putheader("User-Agent", USER_AGENT)
        connection.putheader("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
        connection.putheader("Accept-Encoding", "identity")
        connection.putheader("Connection", "close")
        connection.endheaders()

        response = connection.getresponse()
        status_code = response.status
        headers = {key.lower(): value for key, value in response.getheaders()}
        raw_body, raw_truncated = _read_limited_body(response, max_body_bytes)
        body = b""
        truncated = raw_truncated
        if include_body:
            body, decoded_truncated = _decode_body(
                raw_body,
                headers.get("content-encoding"),
                max_body_bytes,
            )
            truncated = truncated or decoded_truncated
        return {
            "status_code": status_code,
            "headers": headers,
            "url": parsed["url"],
            "body": body,
            "truncated": truncated,
        }
    except ssl.SSLCertVerificationError as error:
        raise SafeResolveError(
            "failed",
            "TLS certificate verification failed for the destination.",
        ) from error
    except ssl.SSLError as error:
        raise SafeResolveError(
            "failed",
            "A secure TLS connection to the destination could not be established.",
        ) from error
    except TimeoutError as error:
        raise SafeResolveError(
            "failed",
            "Connection timed out.",
        ) from error
    except socket.timeout as error:
        raise SafeResolveError(
            "failed",
            "Connection timed out.",
        ) from error
    except OSError as error:
        raise SafeResolveError(
            "failed",
            "The destination could not be contacted.",
        ) from error
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _content_type_base(value):
    if not value:
        return ""
    return value.split(";", 1)[0].strip().lower()


def fetch_safe_page(url):
    """Revalidate and fetch limited HTML from a destination URL.

    Redirects are followed with the same SSRF controls as destination
    inspection. The final response body is capped and never rendered.
    """
    submitted_url = (url or "").strip()
    chain = []
    visited = set()
    redirects_followed = 0

    try:
        current = validate_destination_url(submitted_url)["url"]
    except SafeResolveError as error:
        return {
            "status": error.status,
            "reason": error.reason,
            "page_url": None,
            "content_type": None,
            "html": None,
            "truncated": False,
            "redirect_chain": [],
        }

    try:
        while True:
            if current in visited:
                raise SafeResolveError(
                    "redirect_loop",
                    "A redirect loop was detected.",
                )
            visited.add(current)

            prepared = prepare_destination(current)
            logger.info(
                "Safe page fetch host=%s pinned_ip=%s",
                prepared["hostname"],
                prepared["pinned_ip"],
            )
            exchange = http_exchange(
                prepared["url"],
                prepared["pinned_ip"],
                max_body_bytes=MAX_PAGE_BYTES,
                include_body=True,
            )
            status_code = exchange["status_code"]
            chain.append({"url": prepared["url"], "http_status": status_code})

            if status_code in REDIRECT_STATUS_CODES:
                if redirects_followed >= MAX_REDIRECTS:
                    raise SafeResolveError(
                        "redirect_limit_exceeded",
                        f"More than {MAX_REDIRECTS} redirects were encountered.",
                    )
                location = exchange["headers"].get("location")
                next_url = _next_location(prepared["url"], location)
                prepare_destination(next_url)
                redirects_followed += 1
                current = next_url
                continue

            content_type = _content_type_base(exchange["headers"].get("content-type"))
            if content_type not in ACCEPTED_HTML_CONTENT_TYPES:
                return {
                    "status": "unsupported_content_type",
                    "reason": "Unsupported content type.",
                    "page_url": prepared["url"],
                    "content_type": content_type or None,
                    "html": None,
                    "truncated": False,
                    "redirect_chain": chain,
                }

            html_text = exchange["body"].decode("utf-8", errors="replace")
            return {
                "status": "completed",
                "reason": None,
                "page_url": prepared["url"],
                "content_type": content_type,
                "html": html_text,
                "truncated": bool(exchange.get("truncated")),
                "redirect_chain": chain,
            }

    except SafeResolveError as error:
        logger.warning(
            "Safe page fetch stopped status=%s reason=%s",
            error.status,
            error.reason,
        )
        return {
            "status": error.status,
            "reason": error.reason,
            "page_url": None,
            "content_type": None,
            "html": None,
            "truncated": False,
            "redirect_chain": chain,
        }
    except Exception:
        logger.exception("Safe page fetch failed unexpectedly")
        return {
            "status": "failed",
            "reason": "Page inspection could not be completed.",
            "page_url": None,
            "content_type": None,
            "html": None,
            "truncated": False,
            "redirect_chain": chain,
        }


def _next_location(current_url, location_header):
    if location_header is None or not str(location_header).strip():
        raise SafeResolveError(
            "failed",
            "A redirect response did not include a usable Location header.",
        )
    joined = urljoin(current_url, str(location_header).strip())
    try:
        return normalize_destination_url(joined)
    except SafeResolveError:
        raise
    except Exception as error:
        raise SafeResolveError(
            "failed",
            "A redirect Location header could not be parsed safely.",
        ) from error


def resolve_redirect_chain(url):
    """Resolve a redirect chain with per-hop SSRF validation.

    Returns a structured result. Never raises raw network exceptions to callers.
    """
    submitted_url = (url or "").strip()
    chain = []
    visited = set()

    try:
        # Validate the original URL before normalization so userinfo and
        # disallowed schemes cannot be silently stripped away.
        current = validate_destination_url(submitted_url)["url"]
    except SafeResolveError as error:
        return {
            "status": error.status,
            "reason": error.reason,
            "submitted_url": submitted_url,
            "redirect_chain": [],
            "final_url": None,
            "redirect_count": 0,
        }

    redirects_followed = 0

    try:
        while True:
            if current in visited:
                raise SafeResolveError(
                    "redirect_loop",
                    "A redirect loop was detected.",
                )
            visited.add(current)

            prepared = prepare_destination(current)
            logger.info(
                "Safe resolver requesting host=%s pinned_ip=%s",
                prepared["hostname"],
                prepared["pinned_ip"],
            )
            exchange = http_exchange(prepared["url"], prepared["pinned_ip"])
            status_code = exchange["status_code"]
            chain.append(
                {
                    "url": prepared["url"],
                    "http_status": status_code,
                }
            )

            if status_code not in REDIRECT_STATUS_CODES:
                return {
                    "status": "resolved",
                    "reason": None,
                    "submitted_url": submitted_url,
                    "redirect_chain": chain,
                    "final_url": prepared["url"],
                    "redirect_count": redirects_followed,
                }

            if redirects_followed >= MAX_REDIRECTS:
                raise SafeResolveError(
                    "redirect_limit_exceeded",
                    f"More than {MAX_REDIRECTS} redirects were encountered.",
                )

            location = exchange["headers"].get("location")
            next_url = _next_location(prepared["url"], location)
            # Validate the next hop before any further request.
            prepare_destination(next_url)
            redirects_followed += 1
            current = next_url

    except SafeResolveError as error:
        logger.warning(
            "Safe resolver stopped status=%s reason=%s",
            error.status,
            error.reason,
        )
        return {
            "status": error.status,
            "reason": error.reason,
            "submitted_url": submitted_url,
            "redirect_chain": chain,
            "final_url": None,
            "redirect_count": redirects_followed,
        }
    except Exception:
        logger.exception("Safe resolver failed unexpectedly")
        return {
            "status": "failed",
            "reason": "Destination inspection could not be completed.",
            "submitted_url": submitted_url,
            "redirect_chain": chain,
            "final_url": None,
            "redirect_count": redirects_followed,
        }
