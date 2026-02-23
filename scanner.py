import requests
import dns.resolver
import socket
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse
from checks import (
    resolve_host,
    fetch_http_info,
    baseline_header_check,
    analyze_cookies,
    get_tls_info,
)
from checks import check_http_reachable
import certifi


def extract_hostname(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def scan(target):
    """Backward-compatible simple scan wrapper using default timeout."""
    return scan_target(target, timeout=5)


def build_risk_chains(result: Dict[str, Any]) -> List[str]:
    """Build simple risk chains from a per-host `result` dict.

    Returns a deduplicated list of human-readable risk chain descriptions.
    """
    chains: List[Dict[str, str]] = []

    http_info = result.get("http") or {}
    header_check = result.get("header_check") or {}
    cookies = result.get("cookies") or {}

    http_reachable = bool(result.get("http_reachable", False))
    hsts_missing = "Strict-Transport-Security" in (header_check.get("missing_headers") or [])

    # Downgrade risk: only when plain HTTP is reachable and HSTS is missing
    downgrade_risk = http_reachable and hsts_missing
    if downgrade_risk:
        chains.append({"severity": "MEDIUM", "text": "Possible SSL stripping / downgrade risk (missing HSTS)."})

        # Check for high-severity cookie issues indicating exposure
        cookie_issues = cookies.get("issues", []) if isinstance(cookies, dict) else []
        cookie_details = cookies.get("details", []) if isinstance(cookies, dict) else []
        insecure_cookie = any(not d.get("secure", False) for d in cookie_details)
        high_cookie_issue = any(
            (
                "high concern" in str(it).lower()
                or "samesite=" in str(it).lower() and "none" in str(it).lower()
                or "missing secure" in str(it).lower()
            )
            for it in cookie_issues
        ) or insecure_cookie

        if high_cookie_issue:
            chains.append({"severity": "HIGH", "text": "Chain: Downgrade (no HSTS) → cookie exposure → session hijack risk."})

    # CSP note: only when CSP is missing
    csp_missing = "content-security-policy" in (header_check.get("missing_headers") or [])
    if csp_missing:
        chains.append({"severity": "INFO", "text": "Missing CSP increases impact of injection/XSS if any vector exists."})

    # Deduplicate while preserving order
    # Deduplicate while preserving order, based on text
    seen = set()
    dedup: List[Dict[str, str]] = []
    for c in chains:
        t = c.get("text")
        if t and t not in seen:
            dedup.append(c)
            seen.add(t)
    return dedup


def discover_subdomains(domain: str, timeout: int) -> list[str]:
    """
    Discover subdomains for `domain` by querying crt.sh.

    - Queries: https://crt.sh/?q=%25.<domain>&output=json
    - Parses `name_value` fields, splits multiline entries
    - Normalizes (lowercase, strip, remove leading "*.")
    - Deduplicates and always includes the root domain

    Returns a sorted list of domains. On any error, returns [domain].
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return [domain]
        try:
            data = resp.json()
        except Exception:
            return [domain]

        results = set()
        # Expecting a list of objects with "name_value"
        if isinstance(data, list):
            for item in data:
                nv = item.get("name_value") if isinstance(item, dict) else None
                if not nv:
                    continue
                # name_value can contain multiple names separated by newlines
                for name in str(nv).splitlines():
                    n = name.strip().lower()
                    if not n:
                        continue
                    # Remove leading wildcard
                    if n.startswith("*."):
                        n = n[2:]
                    results.add(n)

        # Filter results: only allow labels matching ^[a-z0-9.-]+$ and that end with the domain
        import re
        valid_re = re.compile(r"^[a-z0-9.-]+$")
        filtered = set()
        for n in results:
            # reject entries with spaces or invalid chars
            if not valid_re.match(n):
                continue
            # keep only names that are exactly the domain or end with .domain
            if n == domain.lower() or n.endswith("." + domain.lower()):
                filtered.add(n)

        # Always include the root domain
        filtered.add(domain.lower())

        return sorted(filtered)
    except Exception:
        return [domain]


def sanity_check_crt_entries(domain: str, timeout: int) -> None:
    """Simple sanity check: print how many crt.sh entries were dropped as invalid."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            print(f"crt.sh request failed: status {resp.status_code}")
            return
        data = resp.json()
    except Exception as e:
        print(f"crt.sh request error: {e}")
        return

    raw_count = 0
    raw_names = []
    if isinstance(data, list):
        for item in data:
            nv = item.get("name_value") if isinstance(item, dict) else None
            if not nv:
                continue
            for name in str(nv).splitlines():
                n = name.strip().lower()
                if n:
                    raw_count += 1
                    raw_names.append(n)

    cleaned = discover_subdomains(domain, timeout)
    dropped = raw_count - len(cleaned)
    print(f"crt.sh entries: {raw_count}, kept: {len(cleaned)}, dropped invalid: {dropped}")


def scan_target(domain: str, timeout: int, max_hosts: int | None = None, ca_bundle: str | None = None) -> Dict[str, Any]:
    """Discover subdomains and run baseline checks on each host.

    Returns a dict with target, timestamp_utc, hosts list, and summary counts.
    """
    hosts_list = discover_subdomains(domain, timeout)
    if max_hosts is not None and isinstance(max_hosts, int) and max_hosts > 0:
        hosts_list = hosts_list[:max_hosts]
    hosts_results: List[Dict[str, Any]] = []

    total_hosts = len(hosts_list)
    resolved_hosts = 0
    missing_hsts_hosts = 0
    missing_csp_hosts = 0

    for host in hosts_list:
        entry: Dict[str, Any] = {"host": host}

        # Ensure `http` is always a dict for schema consistency
        entry["http"] = {
            "scheme_used": None,
            "status_code": None,
            "final_url": None,
            "response_headers": {},
            "https_failed_reason": None,
        }

        # DNS resolution
        host_for_dns = extract_hostname(host)
        res = resolve_host(host_for_dns, timeout)
        entry["resolve"] = res

        if res.get("resolved"):
            resolved_hosts += 1

            # HTTP info and headers
            http_info = fetch_http_info(host, timeout, ca_bundle=ca_bundle)
            entry["http"] = http_info

            # Determine whether plain HTTP is reachable via a direct request
            http_reachable = check_http_reachable(host, timeout, ca_bundle=ca_bundle)
            entry["http_reachable"] = http_reachable

            headers = http_info.get("response_headers", {}) or {}
            header_check = baseline_header_check(headers)
            entry["header_check"] = header_check
            # expose missing headers and present map at top level for convenience
            entry["missing_headers"] = header_check.get("missing_headers", [])
            entry["headers_present"] = header_check.get("present", {})

            # Cookies analysis
            cookies = analyze_cookies(headers)
            entry["cookies"] = cookies

            # Baseline score calculation
            score = 100
            missing = set(entry.get("missing_headers") or [])
            if "Strict-Transport-Security" in missing:
                score -= 30
            if "Content-Security-Policy" in missing:
                score -= 20
            if "X-Frame-Options" in missing:
                score -= 10
            if "X-Content-Type-Options" in missing:
                score -= 10
            if "Referrer-Policy" in missing:
                score -= 5
            if "Permissions-Policy" in missing:
                score -= 5

            # any HIGH cookie issue
            cookie_issues = cookies.get("issues", []) if isinstance(cookies, dict) else []
            high_cookie = any("high concern" in str(it).lower() or "missing secure" in str(it).lower() for it in cookie_issues)
            if high_cookie:
                score -= 15

            # Clamp
            score = max(0, min(100, score))
            entry["baseline_score"] = score

            # TLS info: collect when HTTPS was used, or when port 443 appears reachable
            def port_443_open(h: str, to: int) -> bool:
                try:
                    with socket.create_connection((h, 443), timeout=to):
                        return True
                except Exception:
                    return False

            try_tls = (http_info.get("scheme_used") == "https") or port_443_open(host, timeout)
            if try_tls:
                tls = get_tls_info(host, timeout, ca_bundle=ca_bundle)
            else:
                tls = {"enabled": False, "not_after": None, "expired": False, "expires_soon": False, "issuer": None}
            entry["tls"] = tls

            # Risk chains (with severities)
            chains = build_risk_chains(entry)
            entry["risk_chains"] = chains

            # Summary counters
            if "Strict-Transport-Security" in (entry.get("missing_headers") or []):
                missing_hsts_hosts += 1
            if "Content-Security-Policy" in (entry.get("missing_headers") or []):
                missing_csp_hosts += 1

        else:
            entry["header_check"] = {"missing_headers": [], "present": {}}
            entry["cookies"] = {"cookie_count": 0, "issues": [], "details": []}
            entry["tls"] = {"enabled": False, "not_after": None, "expired": False, "expires_soon": False, "issuer": None}
            entry["risk_chains"] = []

        hosts_results.append(entry)

    summary = {
        "total_hosts": total_hosts,
        "resolved_hosts": resolved_hosts,
        "missing_hsts_hosts": missing_hsts_hosts,
        "missing_csp_hosts": missing_csp_hosts,
    }

    # average baseline score
    scores = [h.get("baseline_score", 0) for h in hosts_results if isinstance(h.get("baseline_score"), int)]
    avg = int(sum(scores) / len(scores)) if scores else 0
    summary["average_baseline_score"] = avg

    ca_used = ca_bundle if ca_bundle else certifi.where()
    return {"target": domain, "timestamp_utc": datetime.utcnow().replace(microsecond=0).isoformat() + "Z", "hosts": hosts_results, "summary": summary, "ca_bundle_used": ca_used}
