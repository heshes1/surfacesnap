# SurfaceSnap

SurfaceSnap is a lightweight passive scanner that inspects a host's
HTTP security headers, TLS certificate metadata, cookies, and basic
HTTP behavior. It produces a quick security snapshot and generates both
JSON and HTML reports.

## Installation

```bash
git clone https://github.com/heshes1/surfacesnap
cd surfacesnap

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
```

## Run

```bash
python main.py scan --target example.com
python main.py scan --targets-file targets.txt
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
