import os
import re
import socket
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import certifi
import dns.resolver
import requests


def _format_cert_name(name: Any) -> str | None:
    """Convert OpenSSL-style subject/issuer tuples into a readable string."""
    if not name:
        return None

    parts: List[str] = []
    try:
        for rdn in name:
            for attr in rdn:
                if isinstance(attr, tuple) and len(attr) == 2:
                    parts.append(f"{attr[0]}={attr[1]}")
    except Exception:
        return str(name)
    return ", ".join(parts) if parts else str(name)


def _decode_der_cert(der_cert: bytes) -> Dict[str, Any]:
    """Decode a DER certificate with Python's built-in helper."""
    pem = ssl.DER_cert_to_PEM_cert(der_cert)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        suffix=".pem",
        delete=False,
    ) as temp_cert:
        temp_cert.write(pem)
        temp_path = temp_cert.name

    try:
        return ssl._ssl._test_decode_cert(temp_path)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


def _classify_tls_failure_type(
    verification_error: str | None,
    expired: bool = False,
    issuer_str: str | None = None,
    subject_str: str | None = None,
) -> str | None:
    """Normalize backend-specific TLS failures into stable categories."""
    error_lower = verification_error.lower() if verification_error else ""
    if expired:
        return "expired"
    if issuer_str and subject_str and issuer_str == subject_str:
        return "self_signed"
    if any(
        marker in error_lower
        for marker in (
            "hostname",
            "doesn't match",
            "does not match",
            "not valid for",
            "certificate is not valid for",
        )
    ):
        return "hostname_mismatch"
    if verification_error:
        if any(
            marker in error_lower
            for marker in (
                "self-signed",
                "self signed",
                "not trusted",
                "untrusted",
                "unable to get local issuer certificate",
                "unable to get issuer certificate",
                "unknown ca",
                "root certificate which is not trusted",
                "trust provider",
                "certificate chain",
            )
        ):
            return "untrusted"
        if any(
            marker in error_lower
            for marker in (
                "handshake failure",
                "sslv3 alert handshake failure",
                "tlsv1 alert protocol version",
                "wrong version number",
                "unsupported protocol",
                "alert protocol version",
            )
        ):
            return "protocol_failure"
        return "other"
    return None


def resolve_host(host: str, timeout: int) -> Dict[str, Any]:
    """Resolve a hostname to A/AAAA addresses within the requested timeout."""
    ips: List[str] = []
    try:
        for rtype in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(host, rtype, lifetime=timeout)
                for a in answers:
                    ips.append(str(a))
            except Exception:
                # ignore individual record failures
                pass
    except Exception:
        return {"host": host, "resolved": False, "ips": []}

    return {"host": host, "resolved": len(ips) > 0, "ips": ips}


def fetch_http_info(
    host: str,
    timeout: int,
    ca_bundle: str | None = None,
) -> Dict[str, Any]:
    """Fetch final-response HTTP metadata for a host."""
    wanted = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    session_headers = {"User-Agent": "SurfaceSnap/1.0"}

    # Try HTTPS first; fall back to HTTP if TLS fails.
    https_url = f"https://{host}"
    verify = ca_bundle if ca_bundle else certifi.where()
    try:
        resp = requests.get(
            https_url,
            allow_redirects=True,
            timeout=timeout,
            headers=session_headers,
            verify=verify,
        )
        normalized = {k.lower(): v for k, v in resp.headers.items()}

        baseline_keys = set(wanted)
        whitelist = {
            "server",
            "date",
            "content-type",
            "content-length",
            "cache-control",
            "location",
        }
        keep_keys = baseline_keys.union({"set-cookie"}).union(whitelist)

        response_headers = {k: normalized[k] for k in keep_keys if k in normalized}
        final_scheme = urlparse(resp.url).scheme or "https"

        return {
            "scheme_used": final_scheme,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirect_count": len(resp.history),
            "response_headers": response_headers,
            "https_failed_reason": None,
        }
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
        # Fall back to HTTP only when TLS never produced a usable response.
        https_reason = str(e)
        try:
            http_url = f"http://{host}"
            resp = requests.get(
                http_url,
                allow_redirects=True,
                timeout=timeout,
                headers=session_headers,
            )
            normalized = {k.lower(): v for k, v in resp.headers.items()}

            baseline_keys = set(wanted)
            whitelist = {
                "server",
                "date",
                "content-type",
                "content-length",
                "cache-control",
                "location",
            }
            keep_keys = baseline_keys.union({"set-cookie"}).union(whitelist)

            response_headers = {k: normalized[k] for k in keep_keys if k in normalized}
            final_scheme = urlparse(resp.url).scheme or "http"

            return {
                "scheme_used": final_scheme,
                "status_code": resp.status_code,
                "final_url": resp.url,
                "redirect_count": len(resp.history),
                "response_headers": response_headers,
                "https_failed_reason": https_reason,
            }
        except Exception:
            return {
                "scheme_used": None,
                "status_code": None,
                "final_url": None,
                "redirect_count": 0,
                "response_headers": {},
                "https_failed_reason": https_reason,
            }
    except Exception:
        # Other errors (e.g., invalid URL formation) - do not fallback to HTTP
        return {
            "scheme_used": None,
            "status_code": None,
            "final_url": None,
            "redirect_count": 0,
            "response_headers": {},
            "https_failed_reason": None,
        }


def check_http_reachable(
    host: str,
    timeout: int,
    ca_bundle: str | None = None,
) -> bool:
    """Return True when the host answers a plain-HTTP request at all."""
    try:
        headers = {"User-Agent": "SurfaceSnap/1.0"}
        resp = requests.head(
            f"http://{host}",
            allow_redirects=True,
            timeout=timeout,
            headers=headers,
        )
        return hasattr(resp, "status_code")
    except Exception:
        return False


def baseline_header_check(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check whether the tracked security headers appear in a response."""
    normalized = {k.lower(): v for k, v in (headers or {}).items()}

    baseline = {
        "strict-transport-security": "Strict-Transport-Security",
        "content-security-policy": "Content-Security-Policy",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    present = {display: (lower in normalized) for lower, display in baseline.items()}
    missing = [
        display for lower, display in baseline.items() if lower not in normalized
    ]
    return {"missing_headers": missing, "present": present}


def analyze_cookies(
    headers: Dict[str, str],
    https_used: bool = False,
) -> Dict[str, Any]:
    """Parse Set-Cookie values into findings and cookie metadata."""
    if not headers:
        return {"cookie_count": 0, "issues": [], "findings": [], "details": []}

    norm = {k.lower(): v for k, v in (headers or {}).items()}

    raw_value = norm.get("set-cookie")
    cookie_strs: List[str] = []

    if raw_value is None:
        return {"cookie_count": 0, "issues": [], "findings": [], "details": []}

    if isinstance(raw_value, (list, tuple)):
        for v in raw_value:
            if isinstance(v, str):
                cookie_strs.append(v)
    elif isinstance(raw_value, str):
        if "\n" in raw_value or "\r" in raw_value:
            cookie_strs.extend(re.split(r"\r\n|\n", raw_value))
        else:
            # Avoid splitting inside Expires dates while still handling merged headers.
            splitter = re.compile(r", (?=[^=;\s]+=[^=;\s]+)")
            parts = splitter.split(raw_value)
            cookie_strs.extend(parts)

    details: List[Dict[str, Any]] = []
    issues: List[str] = []
    findings: List[Dict[str, str]] = []

    for cstr in cookie_strs:
        c = cstr.strip()
        if not c:
            continue
        parts = [p.strip() for p in c.split(";")]
        name_val = parts[0] if parts else ""
        name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val

        attrs = [p.lower() for p in parts[1:]]
        secure = any(a == "secure" for a in attrs)
        httponly = any(a == "httponly" for a in attrs)

        samesite = "Unknown"
        for a in parts[1:]:
            if a.lower().startswith("samesite="):
                v = a.split("=", 1)[1].strip()
                if v.lower() in ("lax", "strict", "none"):
                    samesite = v.capitalize()
                else:
                    samesite = "Unknown"
                break

        details.append(
            {
                "name": name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "raw": c,
            }
        )

        # Keep the legacy `issues` strings, but also attach severity for reporting.
        if samesite == "None" and not secure:
            message = f"Cookie '{name}' uses SameSite=None but is missing Secure"
            issues.append(message)
            findings.append({"severity": "high_risk", "message": message})
        if not httponly:
            message = f"Cookie '{name}' is missing HttpOnly"
            issues.append(message)
            findings.append({"severity": "warning", "message": message})
        if https_used and not secure:
            message = (
                f"Cookie '{name}' is missing Secure while site appears to use HTTPS"
            )
            issues.append(message)
            findings.append({"severity": "warning", "message": message})

    return {
        "cookie_count": len(details),
        "issues": issues,
        "findings": findings,
        "details": details,
    }


def get_tls_info(
    host: str,
    timeout: int,
    ca_bundle: str | None = None,
) -> Dict[str, Any]:
    """Inspect TLS metadata and normalize verification failures."""
    verify = ca_bundle if ca_bundle else certifi.where()
    verification_error = None
    failure_type = None

    cert = None
    cert_der = None
    try:
        # Try a verified handshake first so trusted TLS stays trustworthy.
        verified_ctx = ssl.create_default_context(cafile=verify)
        verified_ctx.check_hostname = True
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with verified_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
    except Exception as exc:
        verification_error = str(exc)

    if cert is None:
        try:
            # Retry without trust checks so the report can still show metadata.
            inspect_ctx = ssl.create_default_context()
            inspect_ctx.check_hostname = False
            inspect_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with inspect_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
        except Exception:
            return {
                "present": False,
                "not_after": None,
                "expired": False,
                "expires_soon": False,
                "issuer": None,
                "verification_error": verification_error,
                "failure_type": _classify_tls_failure_type(verification_error),
            }

    enabled = True
    not_after_str = None
    expired = False
    expires_soon = False
    issuer_str = None
    subject_str = None

    if cert_der and not cert:
        try:
            cert = _decode_der_cert(cert_der)
        except Exception:
            cert = {}

    if cert:
        na = cert.get("notAfter")
        if na:
            parsed = None
            fmts = ["%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%b %d %H:%M:%S %Y"]
            for f in fmts:
                try:
                    parsed = datetime.strptime(na, f)
                    break
                except Exception:
                    parsed = None
            if parsed is not None:
                parsed = parsed.replace(tzinfo=timezone.utc)
                not_after_str = parsed.date().isoformat()
                now = datetime.now(timezone.utc)
                expired = now > parsed
                expires_soon = (parsed - now) <= timedelta(days=30)

        issuer = cert.get("issuer")
        if issuer:
            issuer_str = _format_cert_name(issuer)

        subject = cert.get("subject")
        if subject:
            subject_str = _format_cert_name(subject)

    failure_type = _classify_tls_failure_type(
        verification_error,
        expired=expired,
        issuer_str=issuer_str,
        subject_str=subject_str,
    )

    return {
        "present": enabled,
        "not_after": not_after_str,
        "expired": expired,
        "expires_soon": expires_soon,
        "issuer": issuer_str,
        "verification_error": verification_error,
        "failure_type": failure_type,
    }


def run_checks(data):
    """Legacy compatibility wrapper for older callers expecting issue dicts."""
    issues = []
    headers = {k.lower(): v for k, v in data.get("http_headers", {}).items()}

    if headers:
        if "strict-transport-security" not in headers:
            issues.append(
                {
                    "id": "hsts-missing",
                    "severity": "low",
                    "description": "HSTS header is missing",
                }
            )
        if "content-security-policy" not in headers:
            issues.append(
                {
                    "id": "csp-missing",
                    "severity": "low",
                    "description": "Content-Security-Policy header is missing",
                }
            )
        if "x-frame-options" not in headers:
            issues.append(
                {
                    "id": "xfo-missing",
                    "severity": "low",
                    "description": "X-Frame-Options header is missing",
                }
            )

    return issues
