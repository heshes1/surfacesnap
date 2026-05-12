import os
import re
import random
import socket
import string
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import certifi
import dns.resolver
import requests

from checks import (
    analyze_cookies,
    analyze_csp,
    baseline_header_check,
    check_http_reachable,
    fetch_http_info,
    get_tls_info,
    resolve_host,
)


def extract_hostname(target: str) -> str:
    """Return the hostname portion of a user-supplied target."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def normalize_target(target: str) -> str:
    """Normalize user input into a lowercase hostname."""
    if not isinstance(target, str):
        raise ValueError("Target must be a string.")

    raw = target.strip()
    if not raw:
        raise ValueError("Target must not be empty.")

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid target: {target}")

    normalized = hostname.rstrip(".").lower()
    if not normalized:
        raise ValueError(f"Invalid target: {target}")

    if not re.fullmatch(r"[a-z0-9.-]+", normalized):
        raise ValueError(f"Invalid target: {target}")

    if ".." in normalized:
        raise ValueError(f"Invalid target: {target}")

    return normalized


def scan(target: str):
    """Backward-compatible simple scan wrapper using default timeout."""
    host = normalize_target(target)
    return scan_target(host, timeout=5)


def calculate_baseline_score(
    missing_headers: List[str],
    cookie_findings: List[Dict[str, str]],
    tls: Dict[str, Any],
    scheme_used: str | None,
) -> int:
    """Convert collected findings into the heuristic score shown in reports."""
    score = 100
    missing = set(missing_headers or [])

    # Missing baseline headers drive most of the heuristic score.
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

    # Warning-only cookie findings stay visible without dominating the score.
    if any(f.get("severity") == "high_risk" for f in cookie_findings):
        score -= 10

    failure_type = tls.get("failure_type")
    # TLS failures should outweigh low-confidence HTTP hygiene findings.
    if tls.get("expired"):
        score -= 35
    elif failure_type == "self_signed":
        score -= 30
    elif failure_type == "hostname_mismatch":
        score -= 30
    elif failure_type == "untrusted":
        score -= 25
    elif tls.get("verification_error"):
        score -= 25
    elif scheme_used == "https" and not tls.get("present", False):
        score -= 15

    if tls.get("expires_soon"):
        score -= 5

    return max(0, min(100, score))


def build_risk_chains(result: Dict[str, Any]) -> List[str]:
    """Build short, human-readable chains that connect related weak signals."""
    chains: List[Dict[str, str]] = []

    header_check = result.get("header_check") or {}
    cookies = result.get("cookies") or {}

    http_reachable = bool(result.get("http_reachable", False))
    hsts_missing = "Strict-Transport-Security" in (
        header_check.get("missing_headers") or []
    )

    # Plain HTTP plus missing HSTS suggests downgrade exposure.
    downgrade_risk = http_reachable and hsts_missing
    if downgrade_risk:
        chains.append(
            {
                "severity": "MEDIUM",
                "text": "Possible SSL stripping / downgrade risk (missing HSTS).",
            }
        )

        # High-risk cookie findings make downgrade chains more meaningful.
        cookie_findings = (
            cookies.get("findings", []) if isinstance(cookies, dict) else []
        )
        high_cookie_issue = any(
            finding.get("severity") == "high_risk" for finding in cookie_findings
        )

        if high_cookie_issue:
            chains.append(
                {
                    "severity": "HIGH",
                    "text": "Chain: Downgrade (no HSTS) -> cookie exposure -> session hijack risk.",
                }
            )

    # Missing CSP still matters even without a proven injection vector.
    csp_missing = "Content-Security-Policy" in (
        header_check.get("missing_headers") or []
    )
    if csp_missing:
        chains.append(
            {
                "severity": "INFO",
                "text": "Missing CSP increases impact of injection/XSS if any vector exists.",
            }
        )

    # Preserve the first occurrence of each chain so the report stays concise.
    seen = set()
    dedup: List[Dict[str, str]] = []
    for c in chains:
        t = c.get("text")
        if t and t not in seen:
            dedup.append(c)
            seen.add(t)
    return dedup


def _ensure_root_host_first(domain: str, hosts: list[str]) -> list[str]:
    """Ensure the root domain is first in the host list, deduplicated."""
    seen = set([domain])
    result = [domain]
    for host in hosts:
        if host != domain and host not in seen:
            result.append(host)
            seen.add(host)
    return result


def discover_subdomains(domain: str, timeout: int, wordlist_path: str | None = None) -> list[str]:
    """Query crt.sh and optionally wordlist, returning normalized subdomains for a target."""
    if "://" in domain:
        domain = normalize_target(domain)

    normalized_domain = normalize_target(domain)
    
    # Get crt.sh results
    crt_hosts = _discover_crt_subdomains(normalized_domain, timeout)
    
    # Get wordlist results if provided
    wordlist_hosts: list[str] = []
    if wordlist_path:
        wordlist_hosts = _discover_wordlist_subdomains(normalized_domain, wordlist_path)
        
        # Detect wildcard DNS and filter false positives from wordlist
        if wordlist_hosts and _has_wildcard_dns(normalized_domain, timeout):
            wordlist_hosts = _filter_wildcard_false_positives(
                normalized_domain, wordlist_hosts, timeout
            )
    
    # Merge and deduplicate while preserving stable order
    seen = set()
    merged: list[str] = []
    for host in crt_hosts + wordlist_hosts:
        if host not in seen:
            merged.append(host)
            seen.add(host)
    
    # Ensure root domain is present and first
    return _ensure_root_host_first(normalized_domain, merged)


def _discover_crt_subdomains(normalized_domain: str, timeout: int) -> list[str]:
    """Query crt.sh and return normalized subdomains for a target."""
    import time
    url = f"https://crt.sh/?q=%25.{normalized_domain}&output=json"
    
    # Retry with exponential backoff for rate limiting
    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                break
            elif resp.status_code == 502 and attempt < max_retries - 1:
                # Rate limited, wait and retry
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                time.sleep(wait_time)
                continue
            else:
                return [normalized_domain]
        except requests.exceptions.RequestException:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                time.sleep(wait_time)
                continue
            return [normalized_domain]
    
    try:
        data = resp.json()
    except ValueError:
        return [normalized_domain]

    results = set()
    if isinstance(data, list):
        for item in data:
            nv = item.get("name_value") if isinstance(item, dict) else None
            if not nv:
                continue
            for name in str(nv).splitlines():
                n = name.strip().lower()
                if not n:
                    continue
                if n.startswith("*."):
                    n = n[2:]
                results.add(n)

    valid_re = re.compile(r"^[a-z0-9.-]+$")
    filtered = set()
    for n in results:
        if not valid_re.match(n):
            continue
        if n == normalized_domain or n.endswith("." + normalized_domain):
            filtered.add(n)

    # Keep the root host even if crt.sh returns only subdomains.
    filtered.add(normalized_domain)

    return sorted(filtered)


def _discover_wordlist_subdomains(root_domain: str, wordlist_path: str) -> list[str]:
    """Read a wordlist file and return constructed subdomain names."""
    if not os.path.isfile(wordlist_path):
        return []
    
    results: list[str] = []
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            for line in f:
                entry = line.strip()
                # Skip empty lines and comments
                if not entry or entry.startswith("#"):
                    continue
                
                # If entry already looks like a full domain, validate and use it
                if "." in entry:
                    candidate = entry.lower()
                else:
                    # Otherwise, construct entry.rootdomain
                    candidate = f"{entry}.{root_domain}".lower()
                
                # Validate the candidate
                if re.match(r"^[a-z0-9.-]+$", candidate) and not ".." in candidate:
                    # Ensure it's under the root domain or is the root domain
                    if candidate == root_domain or candidate.endswith("." + root_domain):
                        results.append(candidate)
    except Exception:
        return []
    
    return results


def _has_wildcard_dns(domain: str, timeout: int) -> bool:
    """Detect wildcard DNS by resolving random subdomains under the root domain."""
    results = []
    # Try at least two random subdomains
    for _ in range(2):
        # Generate random subdomain label
        random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        random_subdomain = f"{random_label}.{domain}"
        
        try:
            res = resolve_host(random_subdomain, timeout)
            results.append(res.get("resolved", False))
        except Exception:
            results.append(False)
    
    # Wildcard DNS detected if both random subdomains resolved
    return all(results) and len(results) >= 2


def _filter_wildcard_false_positives(
    root_domain: str,
    wordlist_hosts: list[str],
    timeout: int
) -> list[str]:
    """Filter out wordlist results that are likely wildcard DNS false positives."""
    # Get the IPs that the wildcard resolves to
    wildcard_ips = set()
    try:
        for _ in range(2):
            random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            random_subdomain = f"{random_label}.{root_domain}"
            res = resolve_host(random_subdomain, timeout)
            if res.get("resolved"):
                wildcard_ips.update(res.get("ips", []))
    except Exception:
        pass
    
    # Keep only hosts that don't resolve to the wildcard IPs
    filtered = []
    for host in wordlist_hosts:
        try:
            res = resolve_host(host, timeout)
            if res.get("resolved"):
                host_ips = set(res.get("ips", []))
                # If host IPs differ from wildcard IPs, it's likely legitimate
                if not host_ips.issubset(wildcard_ips):
                    filtered.append(host)
            else:
                # Non-resolving hosts can't be false positives
                filtered.append(host)
        except Exception:
            # On error, keep the host
            filtered.append(host)
    
    return filtered


def discover_subdomains_deprecated(domain: str, timeout: int) -> list[str]:
    """DEPRECATED: Use discover_subdomains() instead."""
    return discover_subdomains(domain, timeout)


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
    print(
        f"crt.sh entries: {raw_count}, kept: {len(cleaned)}, dropped invalid: {dropped}"
    )


def scan_target(
    domain: str,
    timeout: int,
    max_hosts: int | None = None,
    ca_bundle: str | None = None,
    wordlist_path: str | None = None,
) -> Dict[str, Any]:
    """Run host checks for a target and its selected hosts."""
    input_target = domain
    normalized_target = normalize_target(domain)

    if max_hosts == 1:
        hosts_list = [normalized_target]
    else:
        hosts_list = discover_subdomains(normalized_target, timeout, wordlist_path=wordlist_path)
        # Ensure root is first (discover_subdomains should already do this, but mocks may bypass it)
        hosts_list = _ensure_root_host_first(normalized_target, hosts_list)


    if max_hosts is not None and isinstance(max_hosts, int) and max_hosts > 0:
        hosts_list = hosts_list[:max_hosts]
    hosts_results: List[Dict[str, Any]] = []

    total_hosts = len(hosts_list)
    resolved_hosts = 0
    missing_hsts_hosts = 0
    missing_csp_hosts = 0

    for host in hosts_list:
        entry: Dict[str, Any] = {"host": host}

        # Keep a stable schema even when later network steps fail.
        entry["http"] = {
            "scheme_used": None,
            "status_code": None,
            "final_url": None,
            "redirect_count": 0,
            "response_headers": {},
            "https_failed_reason": None,
        }

        host_for_dns = extract_hostname(host)
        res = resolve_host(host_for_dns, timeout)
        entry["resolve"] = res

        if res.get("resolved"):
            resolved_hosts += 1

            http_info = fetch_http_info(host, timeout, ca_bundle=ca_bundle)
            entry["http"] = http_info

            # Skip deeper checks if host did not respond to HTTP/HTTPS.
            if http_info.get("scheme_used") is None:
                entry["header_check"] = {"missing_headers": [], "present": {}}
                entry["cookies"] = {
                    "cookie_count": 0,
                    "issues": [],
                    "findings": [],
                    "details": [],
                }
                entry["csp"] = {"findings": []}
                entry["tls"] = {
                    "present": False,
                    "not_after": None,
                    "expired": False,
                    "expires_soon": False,
                    "issuer": None,
                    "verification_error": None,
                    "failure_type": None,
                }
                entry["risk_chains"] = []
                entry["baseline_score"] = 0
                hosts_results.append(entry)
                continue

            # Track plain HTTP separately for downgrade-style risk chains.
            http_reachable = check_http_reachable(host, timeout, ca_bundle=ca_bundle)
            entry["http_reachable"] = http_reachable

            headers = http_info.get("response_headers", {}) or {}
            header_check = baseline_header_check(headers)
            entry["header_check"] = header_check
            entry["missing_headers"] = header_check.get("missing_headers", [])
            entry["headers_present"] = header_check.get("present", {})

            cookies = analyze_cookies(
                headers,
                https_used=http_info.get("scheme_used") == "https",
            )
            entry["cookies"] = cookies

            # Analyze CSP header for unsafe directives.
            csp = analyze_csp(headers)
            entry["csp"] = csp

            def port_443_open(h: str, to: int) -> bool:
                try:
                    with socket.create_connection((h, 443), timeout=to):
                        return True
                except Exception:
                    return False

            try_tls = port_443_open(host, timeout)
            if try_tls:
                tls = get_tls_info(host, timeout, ca_bundle=ca_bundle)
            else:
                tls = {
                    "present": False,
                    "not_after": None,
                    "expired": False,
                    "expires_soon": False,
                    "issuer": None,
                    "verification_error": None,
                    "failure_type": "tls_absent",
                }
            entry["tls"] = tls

            cookie_findings = (
                cookies.get("findings", [])
                if isinstance(cookies, dict)
                else []
            )
            score = calculate_baseline_score(
                entry.get("missing_headers") or [],
                cookie_findings,
                tls,
                http_info.get("scheme_used"),
            )
            entry["baseline_score"] = score

            chains = build_risk_chains(entry)
            entry["risk_chains"] = chains

            if "Strict-Transport-Security" in (entry.get("missing_headers") or []):
                missing_hsts_hosts += 1
            if "Content-Security-Policy" in (entry.get("missing_headers") or []):
                missing_csp_hosts += 1
        else:
            entry["header_check"] = {"missing_headers": [], "present": {}}
            entry["cookies"] = {
                "cookie_count": 0,
                "issues": [],
                "findings": [],
                "details": [],
            }
            entry["csp"] = {"findings": []}
            entry["tls"] = {
                "present": False,
                "not_after": None,
                "expired": False,
                "expires_soon": False,
                "issuer": None,
                "verification_error": None,
                "failure_type": None,
            }
            entry["risk_chains"] = []
            entry["baseline_score"] = 0

        hosts_results.append(entry)

    summary = {
        "total_hosts": total_hosts,
        "resolved_hosts": resolved_hosts,
        "missing_hsts_hosts": missing_hsts_hosts,
        "missing_csp_hosts": missing_csp_hosts,
    }

    scores = [
        h.get("baseline_score", 0)
        for h in hosts_results
        if isinstance(h.get("baseline_score"), int)
    ]
    avg = int(sum(scores) / len(scores)) if scores else 0
    summary["average_baseline_score"] = avg

    ca_used = ca_bundle if ca_bundle else certifi.where()
    return {
        "input_target": input_target,
        "target": normalized_target,
        "timestamp_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "hosts": hosts_results,
        "summary": summary,
        "ca_bundle_used": ca_used,
    }
