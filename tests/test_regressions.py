import os
import shutil
import ssl
import tempfile
import unittest
from unittest import mock

import report
import scanner
from checks import analyze_cookies, fetch_http_info, get_tls_info


def _make_response(url, status_code=200, headers=None, history=None):
    response = mock.Mock()
    response.url = url
    response.status_code = status_code
    response.headers = headers or {}
    response.history = history or []
    return response


class TargetNormalizationTests(unittest.TestCase):
    def test_empty_target_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            scanner.normalize_target("")

    def test_whitespace_target_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            scanner.normalize_target("   ")

    def test_malformed_url_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, "Invalid target"):
            scanner.normalize_target("https://")

    def test_url_with_port_normalizes_to_host(self):
        self.assertEqual(
            scanner.normalize_target("https://Example.COM:8443/path"),
            "example.com",
        )

    def test_uppercase_hostname_normalizes(self):
        self.assertEqual(scanner.normalize_target("EXAMPLE.COM"), "example.com")

    def test_trailing_dot_hostname_normalizes(self):
        self.assertEqual(scanner.normalize_target("example.com."), "example.com")

    def test_discover_subdomains_normalizes_url_input(self):
        captured = {}

        def fake_get(url, timeout):
            captured["url"] = url

            class Response:
                status_code = 200

                @staticmethod
                def json():
                    return [
                        {"name_value": "*.example.com\napi.example.com"},
                        {"name_value": "example.com"},
                    ]

            return Response()

        with mock.patch("scanner.requests.get", side_effect=fake_get):
            hosts = scanner.discover_subdomains("https://example.com/path?q=1", 5)

        self.assertEqual(
            captured["url"], "https://crt.sh/?q=%25.example.com&output=json"
        )
        self.assertEqual(hosts, ["api.example.com", "example.com"])

    def test_scan_wrapper_matches_scan_target_normalization(self):
        with mock.patch("scanner.scan_target", return_value={"target": "example.com"}) as mocked:
            result = scanner.scan("https://example.com/path")

        mocked.assert_called_once_with("example.com", timeout=5)
        self.assertEqual(result["target"], "example.com")


class RootHostPrioritizationTests(unittest.TestCase):
    def setUp(self):
        self.fake_resolve = lambda host, timeout: {"host": host, "resolved": False, "ips": []}

    def test_root_plus_many_subdomains_keeps_root_first(self):
        with mock.patch(
            "scanner.discover_subdomains",
            return_value=["api.example.com", "cdn.example.com", "example.com", "www.example.com"],
        ), mock.patch("scanner.resolve_host", side_effect=self.fake_resolve):
            result = scanner.scan_target("example.com", timeout=5, max_hosts=2)

        self.assertEqual(
            [host["host"] for host in result["hosts"]],
            ["example.com", "api.example.com"],
        )

    def test_dedup_with_root_already_present(self):
        with mock.patch(
            "scanner.discover_subdomains",
            return_value=["example.com", "api.example.com", "example.com"],
        ), mock.patch("scanner.resolve_host", side_effect=self.fake_resolve):
            result = scanner.scan_target("example.com", timeout=5)

        self.assertEqual(
            [host["host"] for host in result["hosts"]],
            ["example.com", "api.example.com"],
        )

    def test_max_hosts_one_scans_root(self):
        with mock.patch(
            "scanner.discover_subdomains",
            return_value=["api.example.com", "example.com", "www.example.com"],
        ), mock.patch("scanner.resolve_host", side_effect=self.fake_resolve):
            result = scanner.scan_target("example.com", timeout=5, max_hosts=1)

        self.assertEqual([host["host"] for host in result["hosts"]], ["example.com"])

    def test_max_hosts_one_bypasses_discovery(self):
        with mock.patch("scanner.discover_subdomains") as discover, mock.patch(
            "scanner.resolve_host", side_effect=self.fake_resolve
        ):
            result = scanner.scan_target("example.com", timeout=5, max_hosts=1)

        discover.assert_not_called()
        self.assertEqual([host["host"] for host in result["hosts"]], ["example.com"])

    def test_max_hosts_two_keeps_root(self):
        with mock.patch(
            "scanner.discover_subdomains",
            return_value=["api.example.com", "example.com", "www.example.com"],
        ), mock.patch("scanner.resolve_host", side_effect=self.fake_resolve):
            result = scanner.scan_target("example.com", timeout=5, max_hosts=2)

        self.assertEqual(
            [host["host"] for host in result["hosts"]],
            ["example.com", "api.example.com"],
        )

    def test_max_hosts_larger_than_length_keeps_all(self):
        with mock.patch(
            "scanner.discover_subdomains",
            return_value=["api.example.com", "example.com"],
        ), mock.patch("scanner.resolve_host", side_effect=self.fake_resolve):
            result = scanner.scan_target("example.com", timeout=5, max_hosts=10)

        self.assertEqual(
            [host["host"] for host in result["hosts"]],
            ["example.com", "api.example.com"],
        )


class RedirectBehaviorTests(unittest.TestCase):
    def test_https_request_lands_on_http_after_redirects(self):
        response = _make_response(
            "http://http.badssl.com/",
            headers={"Content-Type": "text/html"},
            history=[mock.Mock(status_code=301)],
        )

        with mock.patch("checks.requests.get", return_value=response):
            result = fetch_http_info("http.badssl.com", timeout=5)

        self.assertEqual(result["scheme_used"], "http")
        self.assertEqual(result["final_url"], "http://http.badssl.com/")
        self.assertEqual(result["redirect_count"], 1)

    def test_multiple_redirects_are_counted(self):
        response = _make_response(
            "https://example.com/final",
            headers={"Content-Type": "text/html"},
            history=[mock.Mock(status_code=301), mock.Mock(status_code=302)],
        )

        with mock.patch("checks.requests.get", return_value=response):
            result = fetch_http_info("example.com", timeout=5)

        self.assertEqual(result["scheme_used"], "https")
        self.assertEqual(result["redirect_count"], 2)

    def test_no_redirect_case(self):
        response = _make_response(
            "https://github.com/",
            headers={"Content-Type": "text/html"},
            history=[],
        )

        with mock.patch("checks.requests.get", return_value=response):
            result = fetch_http_info("github.com", timeout=5)

        self.assertEqual(result["scheme_used"], "https")
        self.assertEqual(result["redirect_count"], 0)


class CookieSeverityTests(unittest.TestCase):
    def test_missing_httponly_only_is_warning(self):
        result = analyze_cookies(
            {"set-cookie": "session=1; Path=/; Secure; SameSite=Lax"},
            https_used=True,
        )
        self.assertEqual([f["severity"] for f in result["findings"]], ["warning"])

    def test_missing_secure_only_is_warning(self):
        result = analyze_cookies(
            {"set-cookie": "session=1; Path=/; HttpOnly; SameSite=Lax"},
            https_used=True,
        )
        self.assertEqual([f["severity"] for f in result["findings"]], ["warning"])

    def test_samesite_none_without_secure_is_high_risk(self):
        result = analyze_cookies(
            {"set-cookie": "session=1; Path=/; HttpOnly; SameSite=None"},
            https_used=True,
        )
        severities = [f["severity"] for f in result["findings"]]
        self.assertIn("high_risk", severities)

    def test_multiple_cookies_with_mixed_severities(self):
        result = analyze_cookies(
            {
                "set-cookie": (
                    "warn=1; Path=/; Secure; SameSite=Lax, "
                    "risk=1; Path=/; HttpOnly; SameSite=None"
                )
            },
            https_used=True,
        )
        severities = [f["severity"] for f in result["findings"]]
        self.assertGreaterEqual(severities.count("warning"), 1)
        self.assertEqual(severities.count("high_risk"), 1)


class ScoreBehaviorTests(unittest.TestCase):
    def test_strong_headers_with_weak_cookie_issues_do_not_collapse_score(self):
        score = scanner.calculate_baseline_score(
            [],
            [{"severity": "warning", "message": "Cookie missing HttpOnly"}],
            {
                "present": True,
                "issuer": "CA",
                "not_after": "2027-01-01",
                "expired": False,
                "expires_soon": False,
                "verification_error": None,
                "failure_type": None,
            },
            "https",
        )
        self.assertEqual(score, 100)

    def test_broken_tls_materially_lowers_score(self):
        strong = scanner.calculate_baseline_score(
            [],
            [],
            {
                "present": True,
                "issuer": "CA",
                "not_after": "2027-01-01",
                "expired": False,
                "expires_soon": False,
                "verification_error": None,
                "failure_type": None,
            },
            "https",
        )
        broken = scanner.calculate_baseline_score(
            [],
            [],
            {
                "present": True,
                "issuer": "BadSSL",
                "not_after": "2028-01-01",
                "expired": False,
                "expires_soon": False,
                "verification_error": "self-signed certificate",
                "failure_type": "self_signed",
            },
            "https",
        )
        self.assertGreaterEqual(strong - broken, 30)

    def test_high_risk_cookie_findings_still_reduce_score_materially(self):
        strong = scanner.calculate_baseline_score(
            [],
            [],
            {
                "present": True,
                "issuer": "CA",
                "not_after": "2027-01-01",
                "expired": False,
                "expires_soon": False,
                "verification_error": None,
                "failure_type": None,
            },
            "https",
        )
        risky = scanner.calculate_baseline_score(
            [],
            [{"severity": "high_risk", "message": "SameSite=None without Secure"}],
            {
                "present": True,
                "issuer": "CA",
                "not_after": "2027-01-01",
                "expired": False,
                "expires_soon": False,
                "verification_error": None,
                "failure_type": None,
            },
            "https",
        )
        self.assertGreaterEqual(strong - risky, 10)

    def test_identical_findings_produce_deterministic_score(self):
        tls = {
            "present": True,
            "issuer": "CA",
            "not_after": "2027-01-01",
            "expired": False,
            "expires_soon": False,
            "verification_error": None,
            "failure_type": None,
        }
        findings = [{"severity": "warning", "message": "Cookie missing HttpOnly"}]
        score_a = scanner.calculate_baseline_score(
            ["Permissions-Policy"], findings, tls, "https"
        )
        score_b = scanner.calculate_baseline_score(
            ["Permissions-Policy"], findings, tls, "https"
        )
        self.assertEqual(score_a, score_b)


class TlsSchemaTests(unittest.TestCase):
    def _fake_context(self, cert=None, cert_der=b"cert", raise_error=None):
        ssock = mock.MagicMock()
        ssock.getpeercert.side_effect = lambda binary_form=False: cert_der if binary_form else (cert or {})
        ssock.__enter__.return_value = ssock
        ssock.__exit__.return_value = False

        ctx = mock.MagicMock()
        if raise_error is not None:
            ctx.wrap_socket.side_effect = raise_error
        else:
            ctx.wrap_socket.return_value = ssock
        return ctx

    def _socket_cm(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False
        return sock

    def test_expired_certificate_classification(self):
        contexts = [
            self._fake_context(raise_error=ssl.SSLError("certificate has expired")),
            self._fake_context(cert={}, cert_der=b"expired"),
        ]
        decoded = {
            "issuer": ((("commonName", "Expired CA"),),),
            "notAfter": "Apr 12 23:59:59 2015 GMT",
        }

        with mock.patch("checks.ssl.create_default_context", side_effect=contexts), mock.patch(
            "checks.socket.create_connection", return_value=self._socket_cm()
        ), mock.patch("checks._decode_der_cert", return_value=decoded):
            tls = get_tls_info("expired.badssl.com", timeout=5)

        self.assertEqual(tls["failure_type"], "expired")
        self.assertTrue(tls["present"])
        self.assertTrue(tls["expired"])
        self.assertEqual(tls["issuer"], "commonName=Expired CA")

    def test_expired_classification_is_stable_across_error_texts(self):
        contexts = [
            self._fake_context(raise_error=ssl.SSLError("A required certificate is not within its validity period")),
            self._fake_context(cert={}, cert_der=b"expired"),
        ]
        decoded = {
            "issuer": ((("commonName", "Expired CA"),),),
            "subject": ((("commonName", "*.badssl.com"),),),
            "notAfter": "Apr 12 23:59:59 2015 GMT",
        }

        with mock.patch("checks.ssl.create_default_context", side_effect=contexts), mock.patch(
            "checks.socket.create_connection", return_value=self._socket_cm()
        ), mock.patch("checks._decode_der_cert", return_value=decoded):
            tls = get_tls_info("expired.badssl.com", timeout=5)

        self.assertEqual(tls["failure_type"], "expired")

    def test_self_signed_certificate_classification(self):
        contexts = [
            self._fake_context(raise_error=ssl.SSLError("self-signed certificate")),
            self._fake_context(cert={}, cert_der=b"self"),
        ]
        decoded = {
            "subject": ((("commonName", "BadSSL"),),),
            "issuer": ((("commonName", "BadSSL"),),),
            "notAfter": "Mar 09 21:01:30 2028 GMT",
        }

        with mock.patch("checks.ssl.create_default_context", side_effect=contexts), mock.patch(
            "checks.socket.create_connection", return_value=self._socket_cm()
        ), mock.patch("checks._decode_der_cert", return_value=decoded):
            tls = get_tls_info("self-signed.badssl.com", timeout=5)

        self.assertEqual(tls["failure_type"], "self_signed")
        self.assertEqual(tls["issuer"], "commonName=BadSSL")

    def test_self_signed_classification_is_stable_across_error_texts(self):
        contexts = [
            self._fake_context(
                raise_error=ssl.SSLError(
                    "terminated in a root certificate which is not trusted by the trust provider"
                )
            ),
            self._fake_context(cert={}, cert_der=b"self"),
        ]
        decoded = {
            "subject": ((("commonName", "BadSSL"),),),
            "issuer": ((("commonName", "BadSSL"),),),
            "notAfter": "Mar 09 21:01:30 2028 GMT",
        }

        with mock.patch("checks.ssl.create_default_context", side_effect=contexts), mock.patch(
            "checks.socket.create_connection", return_value=self._socket_cm()
        ), mock.patch("checks._decode_der_cert", return_value=decoded):
            tls = get_tls_info("self-signed.badssl.com", timeout=5)

        self.assertEqual(tls["failure_type"], "self_signed")

    def test_hostname_mismatch_classification(self):
        contexts = [
            self._fake_context(
                raise_error=ssl.SSLError("certificate is not valid for requested host")
            ),
            self._fake_context(cert={}, cert_der=b"host"),
        ]
        decoded = {
            "issuer": ((("commonName", "Mismatch CA"),),),
            "notAfter": "Mar 09 21:01:30 2028 GMT",
        }

        with mock.patch("checks.ssl.create_default_context", side_effect=contexts), mock.patch(
            "checks.socket.create_connection", return_value=self._socket_cm()
        ), mock.patch("checks._decode_der_cert", return_value=decoded):
            tls = get_tls_info("wrong.host.badssl.com", timeout=5)

        self.assertEqual(tls["failure_type"], "hostname_mismatch")

    def test_protocol_failure_classification(self):
        contexts = [
            self._fake_context(
                raise_error=ssl.SSLError("tlsv1 alert protocol version")
            ),
            self._fake_context(raise_error=ssl.SSLError("tlsv1 alert protocol version")),
        ]

        with mock.patch("checks.ssl.create_default_context", side_effect=contexts), mock.patch(
            "checks.socket.create_connection", return_value=self._socket_cm()
        ):
            tls = get_tls_info("legacy.example", timeout=5)

        self.assertEqual(tls["failure_type"], "protocol_failure")
        self.assertFalse(tls["present"])

    def test_generic_tls_failure_classification(self):
        contexts = [
            self._fake_context(raise_error=ssl.SSLError("handshake failed")),
            self._fake_context(raise_error=ssl.SSLError("handshake failed")),
        ]

        with mock.patch("checks.ssl.create_default_context", side_effect=contexts), mock.patch(
            "checks.socket.create_connection", return_value=self._socket_cm()
        ):
            tls = get_tls_info("broken.example", timeout=5)

        self.assertEqual(tls["failure_type"], "other")
        self.assertFalse(tls["present"])
        self.assertIsNone(tls["issuer"])

    def test_all_scan_results_include_stable_tls_keys(self):
        expected_keys = {
            "present",
            "issuer",
            "not_after",
            "expired",
            "expires_soon",
            "verification_error",
            "failure_type",
        }

        with mock.patch(
            "scanner.discover_subdomains", return_value=["example.com"]
        ), mock.patch(
            "scanner.resolve_host", return_value={"host": "example.com", "resolved": False, "ips": []}
        ):
            result = scanner.scan_target("example.com", timeout=5, max_hosts=1)

        self.assertEqual(set(result["hosts"][0]["tls"].keys()), expected_keys)


class ReportAndAtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="surfacesnap-tests-")
        self.result = {
            "input_target": "https://example.com/path",
            "target": "example.com",
            "timestamp_utc": "2026-03-12T12:00:00Z",
            "hosts": [],
        }

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_reports_does_not_leave_partial_files_on_json_failure(self):
        real_write_json = report._write_json_to_path

        def failing_write_json(result, path):
            if path.endswith(".tmp"):
                raise report.ReportWriteError("boom")
            return real_write_json(result, path)

        with mock.patch("report._write_json_to_path", side_effect=failing_write_json):
            with self.assertRaises(report.ReportWriteError):
                report.write_reports(self.result, self.tmpdir)

        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, "report.html")))
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, "result.json")))
        leftovers = [name for name in os.listdir(self.tmpdir) if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_report_wording_is_precise(self):
        result = {
            "target": "example.com",
            "timestamp_utc": "2026-03-12T12:00:00+00:00",
            "hosts": [
                {
                    "host": "example.com",
                    "http": {
                        "scheme_used": "https",
                        "status_code": 200,
                        "final_url": "https://example.com/",
                        "redirect_count": 1,
                        "https_failed_reason": None,
                    },
                    "http_reachable": True,
                    "missing_headers": [],
                    "baseline_score": 97,
                    "resolve": {"resolved": True},
                    "header_check": {"present": {"Strict-Transport-Security": True}},
                    "cookies": {
                        "findings": [{"severity": "warning", "message": "Cookie missing HttpOnly"}]
                    },
                    "tls": {
                        "present": True,
                        "issuer": "CA",
                        "not_after": "2027-01-01",
                        "expired": False,
                        "expires_soon": False,
                        "verification_error": None,
                        "failure_type": None,
                    },
                    "risk_chains": [],
                },
                {
                    "host": "no-tls.example.com",
                    "http": {
                        "scheme_used": None,
                        "status_code": None,
                        "final_url": None,
                        "redirect_count": 0,
                        "https_failed_reason": "connection failed",
                    },
                    "http_reachable": False,
                    "missing_headers": [],
                    "baseline_score": 80,
                    "resolve": {"resolved": True},
                    "header_check": {"present": {"Strict-Transport-Security": False}},
                    "cookies": {"findings": []},
                    "tls": {
                        "present": False,
                        "issuer": None,
                        "not_after": None,
                        "expired": False,
                        "expires_soon": False,
                        "verification_error": None,
                        "failure_type": None,
                    },
                    "risk_chains": [],
                }
            ],
        }
        html_path, _ = report.write_reports(result, self.tmpdir)
        with open(html_path, "r", encoding="utf-8") as fh:
            html = fh.read()

        self.assertIn("Heuristic Score", html)
        self.assertIn("Final scheme", html)
        self.assertIn("Status code", html)
        self.assertIn("TLS result", html)
        self.assertIn("Cookie findings by severity", html)
        self.assertIn("TLS verification failed", html)
        self.assertIn("TLS metadata unavailable", html)


if __name__ == "__main__":
    unittest.main()
