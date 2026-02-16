import dns.resolver
import requests
import re
import socket
import ssl
import certifi
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any


def resolve_host(host: str, timeout: int) -> Dict[str, Any]:
    """Resolve `host` (A and AAAA). Return dict with keys: host, resolved (bool), ips (list).

    Uses dnspython with `lifetime=timeout`. On error returns resolved=False and empty ips.
    """
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


def fetch_http_info(host: str, timeout: int, ca_bundle: str | None = None) -> Dict[str, Any]:
    """Attempt HTTPS then HTTP GET to collect basic response info.

    Returns a dict with:
      - scheme_used: 'https'|'http'|None
      - status_code: int or None
      - final_url: str or None
      - response_headers: dict (only selected headers and Set-Cookie)
    """
    headers_out: Dict[str, Any] = {}
    wanted = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    session_headers = {"User-Agent": "SurfaceSnap/1.0"}

    # Try HTTPS first (with certificate verification). Only fall back to HTTP
    # when HTTPS fails due to connection/SSL errors.
    https_url = f"https://{host}"
    verify = ca_bundle if ca_bundle else certifi.where()
    try:
        resp = requests.get(https_url, allow_redirects=True, timeout=timeout, headers=session_headers, verify=verify)
        normalized = {k.lower(): v for k, v in resp.headers.items()}

        # Baseline keys (already used by header checks)
        baseline_keys = set(wanted)
        # Small whitelist to aid observability without bloating output
        whitelist = {"server", "date", "content-type", "content-length", "cache-control", "location"}
        keep_keys = baseline_keys.union({"set-cookie"}).union(whitelist)

        response_headers = {k: normalized[k] for k in keep_keys if k in normalized}

        return {
            "scheme_used": "https",
            "status_code": resp.status_code,
            "final_url": resp.url,
            "response_headers": response_headers,
            "https_failed_reason": None,
        }
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
        # Try HTTP only for connection/SSL errors
        https_reason = str(e)
        try:
            http_url = f"http://{host}"
            resp = requests.get(http_url, allow_redirects=True, timeout=timeout, headers=session_headers)
            normalized = {k.lower(): v for k, v in resp.headers.items()}

            baseline_keys = set(wanted)
            whitelist = {"server", "date", "content-type", "content-length", "cache-control", "location"}
            keep_keys = baseline_keys.union({"set-cookie"}).union(whitelist)

            response_headers = {k: normalized[k] for k in keep_keys if k in normalized}

            return {
                "scheme_used": "http",
                "status_code": resp.status_code,
                "final_url": resp.url,
                "response_headers": response_headers,
                "https_failed_reason": https_reason,
            }
        except Exception:
            return {"scheme_used": None, "status_code": None, "final_url": None, "response_headers": {}, "https_failed_reason": https_reason}
    except Exception:
        # Other errors (e.g., invalid URL formation) — do not fallback to HTTP
        return {"scheme_used": None, "status_code": None, "final_url": None, "response_headers": {}, "https_failed_reason": None}


def check_http_reachable(host: str, timeout: int, ca_bundle: str | None = None) -> bool:
    """Return True if a HEAD request to http://{host} returns any HTTP status code.

    Uses `User-Agent: SurfaceSnap/1.0`, `allow_redirects=True`, and given `timeout`.
    Returns False on connection errors or timeouts.
    """
    try:
        headers = {"User-Agent": "SurfaceSnap/1.0"}
        resp = requests.head(f"http://{host}", allow_redirects=True, timeout=timeout, headers=headers)
        return hasattr(resp, "status_code")
    except Exception:
        return False


def baseline_header_check(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check for presence of common security headers.

    Normalizes header keys to lowercase and checks exact key presence.

    Returns: {"missing_headers": [...display names...], "present": {display_name: bool, ...}}
    """
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
    missing = [display for lower, display in baseline.items() if lower not in normalized]
    return {"missing_headers": missing, "present": present}


def analyze_cookies(headers: Dict[str, str]) -> Dict[str, Any]:
    """Parse Set-Cookie headers and summarize cookie security properties.

    Returns:
      {
        "cookie_count": int,
        "issues": [str, ...],
        "details": [ {"name": str, "secure": bool, "httponly": bool, "samesite": str, "raw": str}, ... ]
      }

    Robustly handles `Set-Cookie` provided as a list or a single string. If parsing
    fails or no cookies present, returns cookie_count=0 with empty lists.
    """
    if not headers:
        return {"cookie_count": 0, "issues": [], "details": []}

    norm = {k.lower(): v for k, v in (headers or {}).items()}

    raw_value = norm.get("set-cookie")
    cookie_strs: List[str] = []

    if raw_value is None:
        return {"cookie_count": 0, "issues": [], "details": []}

    # Normalize possible list/tuple forms
    if isinstance(raw_value, (list, tuple)):
        for v in raw_value:
            if isinstance(v, str):
                cookie_strs.append(v)
    elif isinstance(raw_value, str):
        # If multiple lines, split on newlines first
        if "\n" in raw_value or "\r" in raw_value:
            cookie_strs.extend(re.split(r"\r\n|\n", raw_value))
        else:
            # Split combined Set-Cookie string on ", " only when followed by cookie-name=value
            # This avoids splitting inside Expires dates which contain commas.
            splitter = re.compile(r", (?=[^=;\s]+=[^=;\s]+)")
            parts = splitter.split(raw_value)
            cookie_strs.extend(parts)

    # Parse each cookie string
    details: List[Dict[str, Any]] = []
    issues: List[str] = []

    https_used = "strict-transport-security" in norm

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

        details.append({"name": name, "secure": secure, "httponly": httponly, "samesite": samesite, "raw": c})

        # Issues
        if samesite == "None" and not secure:
            issues.append(f"Cookie '{name}' uses SameSite=None but is missing Secure (high concern)")
        if not httponly:
            issues.append(f"Cookie '{name}' is missing HttpOnly")
        if https_used and not secure:
            issues.append(f"Cookie '{name}' is missing Secure while site appears to use HTTPS")

    return {"cookie_count": len(details), "issues": issues, "details": details}


def get_tls_info(host: str, timeout: int, ca_bundle: str | None = None) -> Dict[str, Any]:
    """Inspect TLS on host:443 using stdlib socket+ssl.

    Returns:
      {
        "enabled": bool,
        "not_after": "YYYY-MM-DD" or None,
        "expired": bool,
        "expires_soon": bool,
        "issuer": str or None
      }

    If connection or handshake fails, returns {"enabled": False, ...}.
    """
    # Use provided CA bundle or certifi's bundle for the SSL context
    verify = ca_bundle if ca_bundle else certifi.where()
    try:
        ctx = ssl.create_default_context(cafile=verify)
        # We do not require hostname checking for inspection
        ctx.check_hostname = False
    except Exception:
        # Fallback to an unverified context to still retrieve certs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception:
        return {"enabled": False, "not_after": None, "expired": False, "expires_soon": False, "issuer": None}

    enabled = True
    not_after_str = None
    expired = False
    expires_soon = False
    issuer_str = None

    if cert:
        na = cert.get("notAfter")
        if na:
            # Try parsing common formats
            parsed = None
            fmts = ["%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%b %d %H:%M:%S %Y"]
            for f in fmts:
                try:
                    parsed = datetime.strptime(na, f)
                    break
                except Exception:
                    parsed = None
            if parsed is not None:
                # Treat as UTC
                parsed = parsed.replace(tzinfo=timezone.utc)
                not_after_str = parsed.date().isoformat()
                now = datetime.now(timezone.utc)
                expired = now > parsed
                expires_soon = (parsed - now) <= timedelta(days=30)

        # Format issuer
        issuer = cert.get("issuer")
        if issuer:
            parts: List[str] = []
            try:
                for rdn in issuer:
                    # rdn is a sequence of tuples
                    for attr in rdn:
                        if isinstance(attr, tuple) and len(attr) == 2:
                            parts.append(f"{attr[0]}={attr[1]}")
                issuer_str = ", ".join(parts) if parts else str(issuer)
            except Exception:
                issuer_str = str(issuer)

    return {"enabled": enabled, "not_after": not_after_str, "expired": expired, "expires_soon": expires_soon, "issuer": issuer_str}


def run_checks(data):
    """
    Backward-compatible run_checks: uses `data['http_headers']` if present.
    Returns a list of issue dicts as before.
    """
    issues = []
    headers = {k.lower(): v for k, v in data.get("http_headers", {}).items()}

    if headers:
        if "strict-transport-security" not in headers:
            issues.append({"id": "hsts-missing", "severity": "low", "description": "HSTS header is missing"})
        if "content-security-policy" not in headers:
            issues.append({"id": "csp-missing", "severity": "low", "description": "Content-Security-Policy header is missing"})
        if "x-frame-options" not in headers:
            issues.append({"id": "xfo-missing", "severity": "low", "description": "X-Frame-Options header is missing"})

    return issues
