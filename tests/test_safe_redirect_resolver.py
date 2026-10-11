import ipaddress
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader

from app import app
from database.database import get_scan_by_id, get_scans
from services import safe_redirect_resolver as resolver
from tests.support import make_client, raw_client


def pdf_text(pdf_bytes):
    path = Path(tempfile.mkdtemp()) / "report.pdf"
    path.write_bytes(pdf_bytes)
    try:
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    finally:
        path.unlink(missing_ok=True)
        path.parent.rmdir()


PUBLIC_IPS = {
    "short.example": "1.1.1.1",
    "redirect.example": "1.0.0.1",
    "final.example": "8.8.8.8",
    "public.example": "8.8.4.4",
    "evil.example": "127.0.0.1",
    "mixed.example": ("8.8.8.8", "10.0.0.1"),
    "loop-a.example": "9.9.9.9",
    "loop-b.example": "9.9.9.10",
    "example.com": "93.184.216.34",
    "linkr.it": "104.21.1.1",
}


def public_ips_for(hostname):
    value = PUBLIC_IPS.get(hostname, "1.1.1.1")
    if isinstance(value, tuple):
        return [ipaddress.ip_address(item) for item in value]
    return [ipaddress.ip_address(value)]


class FakeExchange:
    def __init__(self, script):
        self.script = dict(script)
        self.calls = []

    def __call__(self, url, pinned_ip):
        self.calls.append({"url": url, "pinned_ip": pinned_ip})
        if url not in self.script:
            raise AssertionError(f"Unexpected HTTP exchange for {url}")
        value = self.script[url]
        if isinstance(value, Exception):
            raise value
        return value


class TestSafeRedirectResolver(unittest.TestCase):
    def test_safe_redirect_resolves_and_counts(self):
        fake = FakeExchange(
            {
                "https://short.example/a": {
                    "status_code": 302,
                    "headers": {"location": "https://redirect.example/b"},
                    "url": "https://short.example/a",
                },
                "https://redirect.example/b": {
                    "status_code": 302,
                    "headers": {"location": "https://final.example/login"},
                    "url": "https://redirect.example/b",
                },
                "https://final.example/login": {
                    "status_code": 200,
                    "headers": {},
                    "url": "https://final.example/login",
                },
            }
        )

        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = resolver.resolve_redirect_chain("https://short.example/a")

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["redirect_count"], 2)
        self.assertEqual(result["final_url"], "https://final.example/login")
        self.assertEqual(len(fake.calls), 3)

    def test_private_ipv4_blocked_before_connection(self):
        targets = [
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://169.254.169.254/",
        ]
        with patch.object(resolver, "http_exchange") as exchange:
            for url in targets:
                result = resolver.resolve_redirect_chain(url)
                self.assertEqual(result["status"], "blocked", url)
                self.assertIn("non-public", result["reason"].lower())
            exchange.assert_not_called()

    def test_private_ipv6_blocked_before_connection(self):
        targets = [
            "http://[::1]/",
            "http://[fc00::1]/",
            "http://[fe80::1]/",
        ]
        with patch.object(resolver, "http_exchange") as exchange:
            for url in targets:
                result = resolver.resolve_redirect_chain(url)
                self.assertEqual(result["status"], "blocked", url)
            exchange.assert_not_called()

    def test_dns_to_private_ip_is_blocked(self):
        with (
            patch.object(
                resolver,
                "dns_lookup",
                return_value=[ipaddress.ip_address("127.0.0.1")],
            ),
            patch.object(resolver, "http_exchange") as exchange,
        ):
            result = resolver.resolve_redirect_chain("http://evil.example/")
        self.assertEqual(result["status"], "blocked")
        exchange.assert_not_called()

    def test_mixed_dns_results_are_blocked(self):
        with (
            patch.object(
                resolver,
                "dns_lookup",
                return_value=[
                    ipaddress.ip_address("8.8.8.8"),
                    ipaddress.ip_address("10.0.0.1"),
                ],
            ),
            patch.object(resolver, "http_exchange") as exchange,
        ):
            result = resolver.resolve_redirect_chain("http://mixed.example/")
        self.assertEqual(result["status"], "blocked")
        exchange.assert_not_called()

    def test_redirect_to_private_ip_blocks_second_request(self):
        fake = FakeExchange(
            {
                "https://public.example/start": {
                    "status_code": 302,
                    "headers": {"location": "http://127.0.0.1/admin"},
                    "url": "https://public.example/start",
                }
            }
        )
        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = resolver.resolve_redirect_chain("https://public.example/start")

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(len(result["redirect_chain"]), 1)

    def test_metadata_address_and_redirect_are_blocked(self):
        with patch.object(resolver, "http_exchange") as exchange:
            direct = resolver.resolve_redirect_chain("http://169.254.169.254/")
            self.assertEqual(direct["status"], "blocked")
            exchange.assert_not_called()

        fake = FakeExchange(
            {
                "https://public.example/meta": {
                    "status_code": 302,
                    "headers": {"location": "http://169.254.169.254/"},
                    "url": "https://public.example/meta",
                }
            }
        )
        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            redirected = resolver.resolve_redirect_chain("https://public.example/meta")
        self.assertEqual(redirected["status"], "blocked")
        self.assertEqual(len(fake.calls), 1)

    def test_unsafe_schemes_are_rejected(self):
        schemes = [
            "file:///etc/passwd",
            "ftp://example.com/file",
            "gopher://example.com/",
            "data:text/plain,test",
            "javascript:alert(1)",
        ]
        with patch.object(resolver, "http_exchange") as exchange:
            for url in schemes:
                result = resolver.resolve_redirect_chain(url)
                self.assertIn(result["status"], {"blocked", "failed"}, url)
            exchange.assert_not_called()

    def test_redirect_loop_is_detected(self):
        fake = FakeExchange(
            {
                "https://loop-a.example/a": {
                    "status_code": 302,
                    "headers": {"location": "https://loop-b.example/b"},
                    "url": "https://loop-a.example/a",
                },
                "https://loop-b.example/b": {
                    "status_code": 302,
                    "headers": {"location": "https://loop-a.example/a"},
                    "url": "https://loop-b.example/b",
                },
            }
        )

        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = resolver.resolve_redirect_chain("https://loop-a.example/a")
        self.assertEqual(result["status"], "redirect_loop")
        self.assertEqual(len(fake.calls), 2)

    def test_redirect_limit_exceeded(self):
        script = {}
        for index in range(7):
            current = f"https://public.example/h{index}"
            nxt = f"https://public.example/h{index + 1}"
            script[current] = {
                "status_code": 302,
                "headers": {"location": nxt},
                "url": current,
            }
        fake = FakeExchange(script)
        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = resolver.resolve_redirect_chain("https://public.example/h0")
        self.assertEqual(result["status"], "redirect_limit_exceeded")
        self.assertLessEqual(len(fake.calls), 6)

    def test_timeout_returns_controlled_failure(self):
        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(
                resolver,
                "http_exchange",
                side_effect=resolver.SafeResolveError("failed", "Connection timed out."),
            ),
        ):
            result = resolver.resolve_redirect_chain("https://public.example/slow")
        self.assertEqual(result["status"], "failed")
        self.assertIn("timed out", result["reason"].lower())

    def test_tls_failure_does_not_disable_verification(self):
        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(
                resolver,
                "http_exchange",
                side_effect=resolver.SafeResolveError(
                    "failed",
                    "TLS certificate verification failed for the destination.",
                ),
            ),
        ):
            result = resolver.resolve_redirect_chain("https://public.example/tls")
        self.assertEqual(result["status"], "failed")
        self.assertIn("TLS certificate verification failed", result["reason"])

    def test_malformed_location_is_controlled_failure(self):
        fake = FakeExchange(
            {
                "https://public.example/bad-location": {
                    "status_code": 302,
                    "headers": {"location": "http://"},
                    "url": "https://public.example/bad-location",
                }
            }
        )
        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = resolver.resolve_redirect_chain("https://public.example/bad-location")
        self.assertIn(result["status"], {"failed", "blocked"})
        self.assertEqual(len(fake.calls), 1)

    def test_relative_redirect_is_resolved(self):
        fake = FakeExchange(
            {
                "https://example.com/a": {
                    "status_code": 302,
                    "headers": {"location": "/login"},
                    "url": "https://example.com/a",
                },
                "https://example.com/login": {
                    "status_code": 200,
                    "headers": {},
                    "url": "https://example.com/login",
                },
            }
        )
        with (
            patch.object(resolver, "dns_lookup", side_effect=public_ips_for),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = resolver.resolve_redirect_chain("https://example.com/a")
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["final_url"], "https://example.com/login")
        self.assertEqual(result["redirect_count"], 1)

    def test_userinfo_is_blocked(self):
        with patch.object(resolver, "http_exchange") as exchange:
            result = resolver.resolve_redirect_chain("http://user:password@example.com/")
        self.assertEqual(result["status"], "blocked")
        self.assertIn("credential", result["reason"].lower())
        exchange.assert_not_called()

    def test_http_exchange_maps_ssl_verification_errors(self):
        class BoomHTTPS(resolver._PinnedHTTPSConnection):
            def putrequest(self, *args, **kwargs):
                raise ssl.SSLCertVerificationError("bad cert")

        with patch.object(resolver, "_PinnedHTTPSConnection", BoomHTTPS):
            with self.assertRaises(resolver.SafeResolveError) as raised:
                resolver.http_exchange("https://example.com/", "93.184.216.34")
        self.assertEqual(raised.exception.status, "failed")
        self.assertIn("TLS certificate verification failed", raised.exception.reason)


class TestPinnedHttpsTransport(unittest.TestCase):
    def test_tls_context_keeps_verification_enabled(self):
        context = resolver.build_tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_tls_context_prefers_certifi_bundle(self):
        import certifi

        with patch("ssl.create_default_context") as create_ctx:
            create_ctx.return_value = ssl.create_default_context(cafile=certifi.where())
            resolver.build_tls_context()
        create_ctx.assert_called()
        kwargs = create_ctx.call_args.kwargs
        self.assertEqual(kwargs.get("cafile"), certifi.where())

    def test_connect_pins_ip_and_uses_hostname_sni(self):
        captured = {}

        class FakeSock:
            def settimeout(self, _timeout):
                return None

            def close(self):
                return None

        def fake_create_connection(address, timeout=None):
            captured["connect"] = address
            return FakeSock()

        context = resolver.build_tls_context()

        def fake_wrap(sock, server_hostname=None, **_kwargs):
            captured["sni"] = server_hostname
            raise ssl.SSLCertVerificationError(
                "certificate verify failed: Hostname mismatch"
            )

        with (
            patch.object(context, "wrap_socket", side_effect=fake_wrap),
            patch.object(resolver, "build_tls_context", return_value=context),
            patch(
                "services.safe_redirect_resolver.socket.create_connection",
                side_effect=fake_create_connection,
            ),
        ):
            with self.assertRaises(resolver.SafeResolveError) as raised:
                resolver.http_exchange("https://short.example/x", "1.1.1.1")

        self.assertEqual(captured["connect"][0], "1.1.1.1")
        self.assertEqual(captured["connect"][1], 443)
        self.assertEqual(captured["sni"], "short.example")
        self.assertIn("TLS certificate verification failed", raised.exception.reason)

    def test_host_header_uses_original_hostname_not_pinned_ip(self):
        seen = {}

        class FakeSock:
            def settimeout(self, _timeout):
                return None

            def close(self):
                return None

            def sendall(self, _data):
                return None

        class CaptureHTTPS(resolver._PinnedHTTPSConnection):
            def connect(self):
                seen["host_attr"] = self.host
                seen["pinned"] = self._pinned_ip
                self.sock = FakeSock()

            def putheader(self, header, *values):
                seen.setdefault("headers", {})[header.lower()] = values[0] if values else None
                return super().putheader(header, *values)

            def getresponse(self):
                class Response:
                    status = 200

                    def getheaders(self):
                        return []

                    def read(self, _n=-1):
                        return b""

                return Response()

        with patch.object(resolver, "_PinnedHTTPSConnection", CaptureHTTPS):
            result = resolver.http_exchange(
                "https://destination.example/login",
                "8.8.8.8",
            )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(seen["host_attr"], "destination.example")
        self.assertEqual(seen["pinned"], "8.8.8.8")
        self.assertEqual(seen["headers"]["host"], "destination.example")
        self.assertNotEqual(seen["headers"]["host"], "8.8.8.8")

    def test_hostname_mismatch_is_rejected(self):
        context = resolver.build_tls_context()

        def mismatch_wrap(sock, server_hostname=None, **_kwargs):
            self.assertEqual(server_hostname, "example.com")
            raise ssl.SSLCertVerificationError(
                "certificate verify failed: Hostname mismatch, certificate is not valid for 'example.com'"
            )

        with (
            patch.object(context, "wrap_socket", side_effect=mismatch_wrap),
            patch.object(resolver, "build_tls_context", return_value=context),
            patch(
                "services.safe_redirect_resolver.socket.create_connection",
                return_value=type(
                    "Sock",
                    (),
                    {"settimeout": lambda *_a, **_k: None, "close": lambda *_a, **_k: None},
                )(),
            ),
        ):
            with self.assertRaises(resolver.SafeResolveError) as raised:
                resolver.http_exchange("https://example.com/", "93.184.216.34")
        self.assertEqual(raised.exception.status, "failed")
        self.assertIn("TLS certificate verification failed", raised.exception.reason)

    def test_untrusted_certificate_is_rejected(self):
        context = resolver.build_tls_context()

        def untrusted_wrap(sock, server_hostname=None, **_kwargs):
            raise ssl.SSLCertVerificationError(
                "certificate verify failed: self-signed certificate"
            )

        with (
            patch.object(context, "wrap_socket", side_effect=untrusted_wrap),
            patch.object(resolver, "build_tls_context", return_value=context),
            patch(
                "services.safe_redirect_resolver.socket.create_connection",
                return_value=type(
                    "Sock",
                    (),
                    {"settimeout": lambda *_a, **_k: None, "close": lambda *_a, **_k: None},
                )(),
            ),
        ):
            with self.assertRaises(resolver.SafeResolveError) as raised:
                resolver.http_exchange("https://public.example/", "8.8.4.4")
        self.assertEqual(raised.exception.status, "failed")
        self.assertIn("TLS certificate verification failed", raised.exception.reason)

    def test_https_redirect_uses_per_hop_hostname_sni(self):
        snis = []

        class FakeSock:
            def settimeout(self, _timeout):
                return None

            def close(self):
                return None

            def sendall(self, _data):
                return None

        class TrackingHTTPS(resolver._PinnedHTTPSConnection):
            def connect(self):
                snis.append({"host": self.host, "pinned": self._pinned_ip})
                self.sock = FakeSock()

            def getresponse(self):
                class Response:
                    def __init__(self, status, headers):
                        self.status = status
                        self._headers = headers

                    def getheaders(self):
                        return list(self._headers.items())

                    def read(self, _n=-1):
                        return b""

                if self.host == "short.example":
                    return Response(302, {"location": "https://destination.example/login"})
                return Response(200, {})

        with (
            patch.object(resolver, "_PinnedHTTPSConnection", TrackingHTTPS),
            patch.object(
                resolver,
                "dns_lookup",
                side_effect=lambda host: (
                    [ipaddress.ip_address("1.1.1.1")]
                    if host == "short.example"
                    else [ipaddress.ip_address("8.8.8.8")]
                ),
            ),
        ):
            result = resolver.resolve_redirect_chain("https://short.example/x")

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["final_url"], "https://destination.example/login")
        self.assertEqual(
            snis,
            [
                {"host": "short.example", "pinned": "1.1.1.1"},
                {"host": "destination.example", "pinned": "8.8.8.8"},
            ],
        )


class TestDestinationInspectionRoutes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        app.config["TESTING"] = True
        self.client = make_client()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_shortener_analysis_does_not_auto_request_network(self):
        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            page = self.client.post(
                "/analyze",
                data={"url": "https://linkr.it/gKin2"},
            ).get_data(as_text=True)
            self.assertIn("LIMITED", page)
            self.assertIn("Destination Analysis", page)
            self.assertIn("Hidden Destination", page)
            self.assertIn("Inspect Final Destination", page)
            self.assertIn('action="/inspect-destination"', page)
            self.assertIn('method="post"', page.lower())
            self.assertIn('name="scan_id"', page)
            self.assertIn('name="csrf_token"', page)
            # One Destination Analysis block; inspect lives inside detailed analysis.
            self.assertEqual(page.count("Destination Analysis"), 1)
            self.assertNotIn("Destination Inspection", page)
            self.assertNotIn("NOT PERFORMED", page.upper())
            hidden_idx = page.find("Hidden Destination")
            inspect_idx = page.find("Inspect Final Destination")
            details_idx = page.find("View Detailed Analysis")
            self.assertGreater(inspect_idx, -1)
            self.assertGreater(details_idx, -1)
            self.assertLess(details_idx, hidden_idx)
            self.assertLess(hidden_idx, inspect_idx)
            self.assertIn("WAITING", page)
            self.assertNotIn("Inspect Page Content", page)
            exchange.assert_not_called()

    def test_fresh_direct_url_exposes_destination_inspection(self):
        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            page = self.client.post(
                "/analyze",
                data={"url": "https://example.com"},
            ).get_data(as_text=True)
            self.assertIn("Inspect Final Destination", page)
            self.assertIn("Destination Analysis", page)
            self.assertIn("NOT INSPECTED", page.upper())
            self.assertIn('action="/inspect-destination"', page)
            self.assertNotIn("Hidden Destination", page)
            self.assertNotIn("Destination Inspection", page)
            self.assertNotIn("NOT PERFORMED", page.upper())
            self.assertIn("WAITING", page)
            self.assertNotIn("Inspect Page Content", page)
            exchange.assert_not_called()

        scan_count = len(get_scans(scan_type="url"))
        self.assertEqual(scan_count, 1)

    def test_destination_inspection_then_exposes_page_inspection_same_scan(self):
        analyze = self.client.post("/analyze", data={"url": "https://example.com/workflow"})
        self.assertEqual(analyze.status_code, 200)
        fresh = analyze.get_data(as_text=True)
        self.assertIn("Inspect Final Destination", fresh)
        self.assertNotIn("Inspect Page Content", fresh)
        scan_id = get_scans(scan_type="url")[0]["id"]

        with patch(
            "app.resolve_redirect_chain",
            return_value={
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://example.com/workflow",
                "final_url": "https://example.com/workflow",
                "redirect_count": 0,
                "hops": [
                    {"url_text": "https://example.com/workflow", "http_status": 200},
                ],
            },
        ):
            response = self.client.post(
                "/inspect-destination",
                data={"scan_id": scan_id},
                follow_redirects=True,
            )
        detail = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Destination Analysis", detail)
        self.assertIn("Completed", detail)
        self.assertIn("AVAILABLE", detail)
        self.assertIn("Inspect Page Content", detail)
        self.assertIn('action="/inspect-page"', detail)
        self.assertEqual(len(get_scans(scan_type="url")), 1)
        self.assertEqual(get_scan_by_id(scan_id)["scan"]["id"], scan_id)

    def test_live_inspect_uses_post_and_existing_resolver(self):
        analyze = self.client.post("/analyze", data={"url": "https://bit.ly/example"})
        self.assertEqual(analyze.status_code, 200)
        page = analyze.get_data(as_text=True)
        self.assertIn("25", page)
        self.assertIn("LOW RISK", page)
        self.assertIn("Inspect Final Destination", page)
        scan_id = get_scans(scan_type="url")[0]["id"]
        self.assertEqual(get_scan_by_id(scan_id)["scan"]["risk_score"], 25)

        bare = raw_client()
        csrf_fail = bare.post("/inspect-destination", data={"scan_id": scan_id})
        self.assertIn(csrf_fail.status_code, {400, 403})

        with patch(
            "app.resolve_redirect_chain",
            return_value={
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://bit.ly/example",
                "final_url": "https://example.com/final",
                "redirect_count": 1,
                "hops": [
                    {"url_text": "https://bit.ly/example", "http_status": 302},
                    {"url_text": "https://example.com/final", "http_status": 200},
                ],
            },
        ) as resolve_mock:
            response = self.client.post(
                "/inspect-destination",
                data={"scan_id": scan_id},
                follow_redirects=False,
            )
        resolve_mock.assert_called_once_with("https://bit.ly/example")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], f"/scan/{scan_id}")
        self.assertEqual(get_scan_by_id(scan_id)["scan"]["risk_score"], 25)

    def test_stored_scan_get_has_no_yellow_banner_and_no_network(self):
        self.client.post("/analyze", data={"url": "https://bit.ly/example"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            with patch("app.resolve_redirect_chain") as resolver:
                detail = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
                exchange.assert_not_called()
                resolver.assert_not_called()
        self.assertIn("Stored Analysis", detail)
        self.assertNotIn(
            "This page displays the result stored when the scan was originally performed",
            detail,
        )
        self.assertNotIn("The URL has not been re-analyzed.", detail)

    def test_inspect_destination_stores_history_without_rerun_on_view(self):
        analyze = self.client.post("/analyze", data={"url": "https://linkr.it/gKin2"})
        self.assertEqual(analyze.status_code, 200)
        scan_id = get_scans(scan_type="url")[0]["id"]

        fake = FakeExchange(
            {
                "https://linkr.it/gKin2": {
                    "status_code": 302,
                    "headers": {"location": "https://final.example/login"},
                    "url": "https://linkr.it/gKin2",
                },
                "https://final.example/login": {
                    "status_code": 200,
                    "headers": {},
                    "url": "https://final.example/login",
                },
            }
        )

        with (
            patch("services.safe_redirect_resolver.dns_lookup", side_effect=public_ips_for),
            patch("services.safe_redirect_resolver.http_exchange", side_effect=fake),
        ):
            response = self.client.post(
                "/inspect-destination",
                data={"scan_id": scan_id},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], f"/scan/{scan_id}")

        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            detail = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
            exchange.assert_not_called()

        self.assertIn("Destination Analysis", detail)
        self.assertIn("Completed", detail)
        self.assertIn("RESOLVED", detail)
        self.assertIn("Redirect Chain", detail)
        self.assertIn("https://final.example/login", detail)
        self.assertNotIn('href="https://final.example/login"', detail)
        self.assertIn("Final Destination", detail)

        record = get_scan_by_id(scan_id)
        self.assertEqual(record["scan"]["analysis_coverage"], "comprehensive")
        self.assertEqual(record["redirect_inspection"]["status"], "resolved")
        self.assertEqual(record["redirect_inspection"]["final_url"], "https://final.example/login")

        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            report = self.client.get(f"/scan/{scan_id}/report")
            exchange.assert_not_called()
        self.assertEqual(report.status_code, 200)
        text = pdf_text(report.data)
        self.assertIn("Destination Analysis", text)
        self.assertIn("Status: Completed", text)
        self.assertIn("Final Destination", text)
        self.assertIn("https://final.example/login", text)

    def test_blocked_inspection_keeps_limited_coverage(self):
        self.client.post("/analyze", data={"url": "https://linkr.it/gKin2"})
        scan_id = get_scans(scan_type="url")[0]["id"]

        with (
            patch(
                "services.safe_redirect_resolver.dns_lookup",
                return_value=[ipaddress.ip_address("127.0.0.1")],
            ),
            patch("services.safe_redirect_resolver.http_exchange") as exchange,
        ):
            self.client.post("/inspect-destination", data={"scan_id": scan_id})
            exchange.assert_not_called()

        page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
        self.assertIn("BLOCKED", page)
        self.assertIn("Destination Analysis", page)
        self.assertIn("Inspection blocked for security reasons", page)
        self.assertIn("LIMITED", page)
        self.assertNotIn("Inspect Page Content", page)
        self.assertIn("UNAVAILABLE", page)
        self.assertNotIn("Destination Inspection", page)
        self.assertNotIn("NOT PERFORMED", page.upper())
        record = get_scan_by_id(scan_id)
        self.assertEqual(record["scan"]["analysis_coverage"], "limited")
        self.assertEqual(record["redirect_inspection"]["status"], "blocked")

    def test_regression_scores_unchanged_before_inspection(self):
        cases = [
            ("https://example.com/login", "10/100", "Low Risk"),
            ("https://g00gle.com/login", "45/100", "Suspicious"),
            (
                "http://192.168.1.10:8080/account/verify/password",
                "75/100",
                "High Risk",
            ),
            ("https://linkr.it/gKin2", "25/100", "Low Risk"),
        ]
        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            for url, score, classification in cases:
                page = self.client.post("/analyze", data={"url": url}).get_data(as_text=True)
                self.assertIn(score, page)
                self.assertIn(classification, page)
            exchange.assert_not_called()


if __name__ == "__main__":
    unittest.main()
