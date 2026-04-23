# SurfaceSnap

SurfaceSnap is a lightweight passive scanner that inspects a host's HTTP security headers, TLS certificate metadata, cookies, and basic HTTP behavior. It generates both JSON and HTML reports.

## Installation

```bash
git clone https://github.com/heshes1/surfacesnap
cd surfacesnap

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
```

## Run

Single target:

```bash
python main.py scan --target example.com
```

Targets from file:

```bash
python main.py scan --targets-file targets.txt
```

Optional flags:

```bash
--max-hosts 10
--timeout 3
--out out
--ca-bundle path/to/ca-bundle.pem
```

Example:

```bash
python main.py scan --target example.com --max-hosts 5 --timeout 3 --out out
```

## Output

The scan creates two files in the output directory:

```text
report.html   human-readable scan report
result.json   structured scan results
```

## Example

```bash
python main.py scan --target github.com
```

This scans the host and generates the report files.
