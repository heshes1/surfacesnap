# SurfaceSnap

SurfaceSnap is a Python based, non intrusive security surface analyzer.

It performs passive discovery and baseline security posture checks, generating structured JSON and HTML reports. It is designed for authorized security testing and asset visibility. It does not perform exploitation.

## Features

For each target, SurfaceSnap:

- Discovers subdomains via Certificate Transparency (crt.sh)
    
- Performs DNS resolution (A / AAAA)
    
- Attempts HTTPS first
    
- Collects HTTP response headers
    
- Evaluates baseline security headers:
    
    - `Strict-Transport-Security`
        
    - `Content-Security-Policy`
        
    - `X-Frame-Options`
        
    - `X-Content-Type-Options`
        
    - `Referrer-Policy`
        
    - `Permissions-Policy`
        
- Analyzes cookies (`Secure`, `HttpOnly`, `SameSite`)
    
- Inspects TLS certificate metadata (if HTTPS succeeds)
    
- Builds simple risk chains
    
- Calculates a `baseline_score` (0–100)
    

All checks are non-intrusive.

## Target Input

You may provide:

- `example.com`
    
- `http://example.com`
    
- `https://example.com`
    
- `https://example.com/some/path`
    

DNS resolution is performed against the extracted hostname.

## Installation

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install -r requirements.txt
```

### Dependencies

- requests
    
- dnspython
    
- jinja2
    
- certifi
    
- truststore
    
- typer

## Usage

SurfaceSnap uses a Typer-based CLI.

### Scan a Single Target

```bash
python main.py scan --target example.com --out out
```

### Scan Multiple Targets

```bash
python main.py scan --targets-file targets.txt --out out
```

Example `targets.txt`:

```
https://example.com
https://example.org
```

---

### Optional Parameters

```bash
python main.py scan \
  --target example.com \
  --timeout 5 \
  --max-hosts 10 \
  --ca-bundle /path/to/ca.pem
```

Options:

- `--timeout` (default: 5)
    
- `--max-hosts` (0 = unlimited)
    
- `--ca-bundle` custom PEM file (otherwise certifi is used)

## Output

Two files are generated in the output directory:

- `report.html`
    
- `result.json`
    

### JSON Structure

- `target`
    
- `timestamp_utc`
    
- `hosts[]`
    
    - `http`
        
    - `resolve`
        
    - `http_reachable`
        
    - `header_check`
        
    - `missing_headers`
        
    - `headers_present`
        
    - `cookies`
        
    - `baseline_score`
        
    - `tls`
        
    - `risk_chains`
        
- `summary`
    
- `ca_bundle_used`

## HTTPS & TLS Behavior

- HTTPS is attempted first.
    
- If HTTPS negotiation succeeds, TLS metadata is collected.
    
- If HTTPS fails, TLS fields remain disabled.
    
- DNS resolution failures prevent HTTP checks.
  
## Scoring

Each resolved host receives a `baseline_score` between 0 and 100.

Score reductions occur due to:

- Missing security headers
    
- Cookie security issues
    
- Certain downgrade scenarios (e.g., missing HSTS)
    

Example scores:

- `example.com` → 20
    
- `juice-shop.herokuapp.com` → 40

## Legal Use

SurfaceSnap performs passive checks only (DNS, TLS inspection, HTTP headers).

Use only against systems you own or are explicitly authorized to test.
