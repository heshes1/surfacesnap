SurfaceSnap
===========

SurfaceSnap is a Python-based baseline security analyzer that performs non-intrusive attack surface checks, evaluates OWASP Secure Headers posture, and generates automated HTML/JSON security reports with risk-chain analysis.

Installation
------------

Install required dependencies:

```bash
pip install -r requirements.txt
```

Usage
-----

Run a surface scan and write reports to an output directory:

```bash
python main.py scan --target example.com --out out
```

You can provide a custom CA bundle for HTTPS verification with `--ca-bundle`:

```bash
python main.py scan --target example.com --out out --ca-bundle C:\path\to\corp-root.pem
```

Notes
-----

- All checks are non-intrusive (DNS lookups, TLS inspection, HTTP header retrieval). Do not run this tool against targets you are not authorized to test. Use it only for authorized security testing and asset discovery within your scope.

Project layout
--------------

- `main.py` — CLI entrypoint
- `scanner.py` — orchestration and subdomain discovery
- `checks.py` — low-level network and header checks
- `report.py` — JSON and HTML report writers
- `templates/` — Jinja2 templates for HTML report
- `requirements.txt` — Python dependencies

License
-------

(Add your preferred license file before publishing.)
# SurfaceSnap

SurfaceSnap is a minimal baseline security analyzer that performs non-intrusive surface checks (DNS resolution, certificate discovery, and basic HTTP header checks) and generates a simple HTML report.

Installation

- Create a virtual environment and install dependencies:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Quick example

```powershell
python main.py scan --target example.com --out out --timeout 3
```

Screenshot instructions

- Open the generated `out/report.html` in your browser and use your OS/browser screenshot tool (or `Print -> Save as PDF`) to capture the report. On Windows use `Win+Shift+S` to capture a region.

What it checks (baseline)

- DNS resolution and certificate entries discovered via crt.sh (passive).
- HTTP(S) reachability and selected security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- Cookie attributes (`Secure`, `HttpOnly`, `SameSite`) and simple TLS certificate expiry checks.

Why HSTS matters (short)

- HSTS tells browsers to only use HTTPS for a host. Without HSTS an attacker on the network could downgrade connections (SSL stripping), exposing cookies and session tokens. SurfaceSnap flags missing HSTS as a baseline risk.

Example output (CLI)

```
Scanned: 10 host(s); Resolved: 3; Missing HSTS: 3
Reports: out\report.html, out\result.json
```

Example snippet (JSON host entry)

```json
{
	"host": "example.com",
	"resolve": {"host": "example.com", "resolved": true, "ips": ["93.184.216.34"]},
	"http": {"scheme_used": "https", "status_code": 200},
	"header_check": {"missing_headers": ["content-security-policy"], "present": {"strict-transport-security": true}},
	"cookies": {"cookie_count": 1, "issues": ["Cookie 'sid' missing HttpOnly"]},
	"tls": {"enabled": true, "not_after": "2026-09-01"},
	"risk_chains": ["Possible SSL stripping / downgrade risk (missing HSTS)."]
}
```

Legal / Ethical note

- Non-intrusive checks only. Use only with authorization. Always obtain permission before scanning systems you do not own.

Design choices

- crt.sh: public Certificate Transparency data is a low-impact way to discover issued names for a domain without active probing.
- Headers baseline: checking a small set of widely-adopted security headers gives quick, low-risk indicators of hardening (HSTS, CSP, XFO, etc.).
- Risk chains: simple, human-readable chains (e.g., downgrade → cookie exposure) make it easier to reason about combined weaknesses without overclaiming.
