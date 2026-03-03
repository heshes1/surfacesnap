# SurfaceSnap

SurfaceSnap is a small Python tool for checking the external security surface of a domain.

It discovers subdomains using Certificate Transparency logs and runs a set of basic checks such as DNS resolution, HTTP headers, cookies, and TLS certificate information. Results are written to JSON and an HTML report.

## Features

For each target, SurfaceSnap:

- Discovers subdomains using crt.sh
- Resolves DNS records (A and AAAA)
- Attempts HTTPS first, then falls back to HTTP if needed
- Collects selected HTTP response headers
- Checks common security headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Analyzes cookies (Secure, HttpOnly, SameSite)
- Inspects TLS certificate metadata
- Builds simple risk chain indicators
- Calculates a baseline security score
- Generates JSON and HTML reports

## Installation

Create a virtual environment:

python -m venv venv

Activate it.

Linux / macOS

source venv/bin/activate

Windows

venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

## Usage

Scan a single target:

python main.py scan --target example.com --out out

Scan multiple targets:

python main.py scan --targets-file targets.txt --out out

Example `targets.txt`:

https://example.com
https://example.org

## Options

--timeout      Network timeout in seconds (default: 5)  
--max-hosts    Limit number of hosts discovered (0 = unlimited)  
--ca-bundle    Path to a custom CA bundle for HTTPS verification  

## Output

The scan writes two files to the output directory:

report.html  
result.json  

The HTML report shows discovered hosts, missing security headers, cookie issues, TLS information, and baseline scores.
