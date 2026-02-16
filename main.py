import argparse
import os
import truststore
# Inject the OS/system trust store into Python's SSL handling early so
# downstream imports that make HTTPS requests (requests, ssl) will use it.
truststore.inject_into_ssl()
from scanner import scan_target
from checks import run_checks
from report import write_reports


def main():
    parser = argparse.ArgumentParser(description="SurfaceSnap - baseline security analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Run a surface scan against a target")
    scan_p.add_argument("--target", required=True, help="Target domain or hostname to scan (non-intrusive)")
    scan_p.add_argument("--out", default="out", help="Output directory for reports")
    scan_p.add_argument("--timeout", type=int, default=5, help="Timeout (seconds) for network operations")
    scan_p.add_argument("--max-hosts", type=int, default=0, help="Maximum number of hosts to scan (0 = no limit)")
    scan_p.add_argument("--ca-bundle", dest="ca_bundle", default=None, help="Path to a PEM CA bundle to use for HTTPS verification")

    args = parser.parse_args()

    if args.cmd == "scan":
        out_dir = args.out
        # Ensure output directory exists
        os.makedirs(out_dir, exist_ok=True)

        # Run scan with provided timeout, optional host cap and optional custom CA bundle
        max_hosts = args.max_hosts if args.max_hosts and args.max_hosts > 0 else None
        result = scan_target(args.target, timeout=args.timeout, max_hosts=max_hosts, ca_bundle=args.ca_bundle)

        # Write reports (HTML + JSON)
        html_path, json_path = write_reports(result, out_dir)

        # Concise summary from result
        summary = result.get("summary", {})
        print(
            f"Scanned: {summary.get('total_hosts', 0)} host(s); Resolved: {summary.get('resolved_hosts', 0)}; Missing HSTS: {summary.get('missing_hsts_hosts', 0)}"
        )
        print(f"Reports: {html_path}, {json_path}")


if __name__ == "__main__":
    main()
