#!/usr/bin/env python3
"""
XSS Detector - A Cross-Site Scripting vulnerability detection tool
Usage: python3 xss_detector.py <target_url> [options]
Requires: payloads.txt in the same folder
"""

import argparse
import sys
import os
import time
import json
import re
import urllib.parse
from datetime import datetime

# ─── Optional dependency check ────────────────────────────────────────────────
try:
    import requests
    from requests.exceptions import RequestException, SSLError, ConnectionError, Timeout
except ImportError:
    print("[!] 'requests' not found. Run: pip install requests --break-system-packages")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

def color(text: str, code: str) -> str:
    colors = {
        "red": RED, "green": GREEN, "yellow": YELLOW,
        "blue": BLUE, "cyan": CYAN, "bold": BOLD,
        "dim": DIM, "reset": RESET,
    }
    return f"{colors.get(code, '')}{text}{RESET}"

def log(level: str, msg: str):
    icons = {
        "info":    f"{BLUE}[*]{RESET}",
        "success": f"{GREEN}[+]{RESET}",
        "vuln":    f"{RED}[!]{RESET}",
        "warn":    f"{YELLOW}[~]{RESET}",
        "error":   f"{RED}[x]{RESET}",
        "skip":    f"{DIM}[-]{RESET}",
    }
    print(f"{icons.get(level, '[?]')} {msg}")

# ─── Load Payloads from File ───────────────────────────────────────────────────
def load_payloads(filepath="payloads.txt"):
    # Look in same directory as this script first
    script_dir = os.path.dirname(os.path.abspath(__file__))
    full_path  = os.path.join(script_dir, filepath)

    # Fall back to current working directory
    if not os.path.exists(full_path):
        full_path = os.path.join(os.getcwd(), filepath)

    if not os.path.exists(full_path):
        print(f"{RED}[x]{RESET} Payload file '{filepath}' not found!")
        print(f"{YELLOW}[!]{RESET} Place 'payloads.txt' in the same folder as this script and retry.")
        sys.exit(1)

    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        payloads = [
            line.strip() for line in f
            if line.strip() and not line.startswith("#")
        ]

    if not payloads:
        print(f"{RED}[x]{RESET} '{filepath}' has no usable payloads!")
        sys.exit(1)

    print(f"{GREEN}[+]{RESET} Loaded {BOLD}{len(payloads)}{RESET} payloads from '{filepath}'")
    return payloads

# ─── Reflection Detection Patterns ────────────────────────────────────────────
REFLECTED_PATTERNS = [
    re.compile(r'<script[^>]*>.*?alert\s*\(', re.IGNORECASE | re.DOTALL),
    re.compile(r'onerror\s*=\s*["\']?\s*alert', re.IGNORECASE),
    re.compile(r'onload\s*=\s*["\']?\s*alert', re.IGNORECASE),
    re.compile(r'onmouseover\s*=\s*["\']?\s*alert', re.IGNORECASE),
    re.compile(r'onfocus\s*=\s*["\']?\s*alert', re.IGNORECASE),
    re.compile(r'<svg[^>]*onload', re.IGNORECASE),
    re.compile(r'<img[^>]*onerror', re.IGNORECASE),
    re.compile(r'javascript\s*:\s*alert', re.IGNORECASE),
    re.compile(r'<iframe[^>]*src\s*=\s*["\']?javascript', re.IGNORECASE),
    re.compile(r'ontoggle\s*=\s*["\']?\s*alert', re.IGNORECASE),
    re.compile(r'<details[^>]*ontoggle', re.IGNORECASE),
    re.compile(r'<body[^>]*onload', re.IGNORECASE),
]

# ─── Banner ────────────────────────────────────────────────────────────────────
def banner():
    art = """
 ██╗  ██╗███████╗███████╗    ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
 ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
  ╚███╔╝ ███████╗███████╗    █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
  ██╔██╗ ╚════██║╚════██║    ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║███████║    ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
"""
    print(CYAN + art + RESET)
    print(RED + "  " + "─" * 70 + RESET)
    print(YELLOW + "  " + "Cross-Site Scripting Vulnerability Scanner".center(70) + RESET)
    print(DIM + "  " + "v2.0  |  For Authorized Testing Only".center(70) + RESET)
    print(RED + "  " + "─" * 70 + RESET)
    print()

# ─── Form Extraction ───────────────────────────────────────────────────────────
def extract_forms(url, session, timeout):
    forms = []
    try:
        resp = session.get(url, timeout=timeout)
        if not BS4_AVAILABLE:
            raw_forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL | re.IGNORECASE)
            for form_html in raw_forms:
                inputs   = re.findall(r'<input[^>]*name=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
                action_m = re.search(r'<form[^>]*action=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
                method_m = re.search(r'<form[^>]*method=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
                forms.append({
                    "action": action_m.group(1) if action_m else url,
                    "method": method_m.group(1).upper() if method_m else "GET",
                    "inputs": inputs,
                })
        else:
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action", url)
                method = form.get("method", "get").upper()
                inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
                forms.append({"action": action, "method": method, "inputs": inputs})
    except Exception as e:
        log("warn", f"Could not extract forms: {e}")
    return forms

# ─── Reflection Check ──────────────────────────────────────────────────────────
def is_payload_reflected(response_text, payload):
    if payload in response_text:
        for pattern in REFLECTED_PATTERNS:
            if pattern.search(response_text):
                return True
    return False

# ─── Scanners ──────────────────────────────────────────────────────────────────
def scan_url_params(url, session, payloads, timeout, delay, results):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        log("skip", "No URL parameters found to test.")
        return

    log("info", f"Found {len(params)} URL parameter(s): {', '.join(params.keys())}")

    for param in params:
        for payload in payloads:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_query = urllib.parse.urlencode(test_params)
            test_url   = urllib.parse.urlunparse(parsed._replace(query=test_query))
            try:
                resp = session.get(test_url, timeout=timeout)
                if is_payload_reflected(resp.text, payload):
                    log("vuln", f"{RED}REFLECTED XSS in param '{param}' | Payload: {payload[:60]}{RESET}")
                    results.append({
                        "type": "Reflected XSS",
                        "location": f"URL parameter: {param}",
                        "payload": payload,
                        "url": test_url,
                        "status": resp.status_code,
                    })
                else:
                    log("skip", f"  param='{param}' → no reflection")
            except Exception as e:
                log("warn", f"  Request failed for param '{param}': {e}")
            if delay:
                time.sleep(delay)


def scan_forms(base_url, forms, session, payloads, timeout, delay, results):
    if not forms:
        return
    log("info", f"Found {len(forms)} form(s) to test.")
    for i, form in enumerate(forms, 1):
        action = form["action"]
        if not action.startswith("http"):
            parsed_base = urllib.parse.urlparse(base_url)
            action = urllib.parse.urljoin(f"{parsed_base.scheme}://{parsed_base.netloc}", action)
        log("info", f"  Form {i}: method={form['method']} action={action} inputs={form['inputs']}")
        for field in form["inputs"]:
            for payload in payloads:
                data = {inp: "test" for inp in form["inputs"]}
                data[field] = payload
                try:
                    if form["method"] == "POST":
                        resp = session.post(action, data=data, timeout=timeout)
                    else:
                        resp = session.get(action, params=data, timeout=timeout)
                    if is_payload_reflected(resp.text, payload):
                        log("vuln", f"{RED}REFLECTED XSS in form field '{field}' | Payload: {payload[:60]}{RESET}")
                        results.append({
                            "type": "Reflected XSS (Form)",
                            "location": f"Form field: {field} ({form['method']} {action})",
                            "payload": payload,
                            "url": action,
                            "status": resp.status_code,
                        })
                    else:
                        log("skip", f"    field='{field}' → no reflection")
                except Exception as e:
                    log("warn", f"    Request failed for field '{field}': {e}")
                if delay:
                    time.sleep(delay)


def scan_headers(url, session, payloads, timeout, delay, results):
    headers_to_test = ["Referer", "User-Agent", "X-Forwarded-For", "X-Original-URL"]
    log("info", f"Testing {len(headers_to_test)} HTTP headers for reflection.")
    for header in headers_to_test:
        for payload in payloads[:10]:
            try:
                resp = session.get(url, headers={header: payload}, timeout=timeout)
                if is_payload_reflected(resp.text, payload):
                    log("vuln", f"{RED}REFLECTED XSS via header '{header}' | Payload: {payload[:60]}{RESET}")
                    results.append({
                        "type": "Header-based Reflected XSS",
                        "location": f"HTTP Header: {header}",
                        "payload": payload,
                        "url": url,
                        "status": resp.status_code,
                    })
            except Exception as e:
                log("warn", f"  Header test failed for '{header}': {e}")
            if delay:
                time.sleep(delay)

# ─── Terminal Report ───────────────────────────────────────────────────────────
def print_report(results, target, start_time):
    duration = time.time() - start_time
    print(f"\n{CYAN}{'=' * 54}{RESET}")
    print(f"{BOLD}  SCAN REPORT{RESET}")
    print(f"{CYAN}{'=' * 54}{RESET}")
    print(f"  Target  : {target}")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration: {duration:.2f}s")
    vuln_color = RED if results else GREEN
    print(f"  Found   : {vuln_color}{len(results)} vulnerability/ies{RESET}")
    print(f"{DIM}{'-' * 54}{RESET}")
    if results:
        for i, r in enumerate(results, 1):
            print(f"\n  {RED}[#{i}]{RESET} {BOLD}{r['type']}{RESET}")
            print(f"    Location : {r['location']}")
            print(f"    Payload  : {YELLOW}{r['payload'][:80]}{RESET}")
            print(f"    URL      : {r['url'][:80]}")
            print(f"    Status   : {r['status']}")
    else:
        print(f"\n  {GREEN}No XSS vulnerabilities detected.{RESET}")
        print(f"  {DIM}Note: This tool tests for reflected XSS only.{RESET}")
        print(f"  {DIM}DOM-based and Stored XSS require manual testing.{RESET}")
    print(f"{CYAN}{'=' * 54}{RESET}\n")
    return duration

# ─── File Reports ──────────────────────────────────────────────────────────────
def save_json_report(results, target, output_file):
    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "total_vulnerabilities": len(results),
        "vulnerabilities": results,
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    log("success", f"JSON report  → {output_file}")


def save_html_report(results, target, duration, output_file, payload_count,
                     scanned_forms, scanned_headers):
    scan_time    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status_color = "#e74c3c" if results else "#2ecc71"
    status_text  = f"{len(results)} Vulnerability/ies Found" if results else "No Vulnerabilities Detected"

    vuln_rows = ""
    for i, r in enumerate(results, 1):
        vuln_rows += f"""
        <tr>
          <td>{i}</td>
          <td><span class="badge" style="background:#e74c3c">HIGH</span></td>
          <td>{r['type']}</td>
          <td>{r['location']}</td>
          <td class="payload">{r['payload']}</td>
          <td>{r['status']}</td>
        </tr>"""

    if not vuln_rows:
        vuln_rows = """
        <tr><td colspan="6" style="text-align:center;color:#2ecc71;padding:24px;">
          ✔ No XSS vulnerabilities were detected during this scan.
        </td></tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Scan Report — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Sora:wght@400;600;700&display=swap');
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Sora',sans-serif;font-size:14px;line-height:1.6;padding:40px 24px}}
  .container{{max-width:1000px;margin:0 auto}}
  .header{{border:1px solid #30363d;border-radius:12px;padding:32px 36px;margin-bottom:28px;
    background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);position:relative;overflow:hidden}}
  .header::before{{content:'';position:absolute;top:-60px;right:-60px;width:200px;height:200px;
    border-radius:50%;background:radial-gradient(circle,rgba(231,76,60,.15) 0%,transparent 70%)}}
  .header h1{{font-family:'JetBrains Mono',monospace;font-size:22px;color:#58a6ff;letter-spacing:2px;margin-bottom:6px}}
  .header .subtitle{{color:#8b949e;font-size:12px;letter-spacing:1px}}
  .status-badge{{display:inline-block;margin-top:18px;padding:8px 20px;border-radius:20px;
    font-weight:700;font-size:13px;background:{status_color}22;color:{status_color};
    border:1px solid {status_color}55;letter-spacing:.5px}}
  .meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}}
  .meta-card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 20px}}
  .meta-card .label{{color:#8b949e;font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px}}
  .meta-card .value{{color:#e6edf3;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:700;word-break:break-all}}
  .section-title{{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#8b949e;
    margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #21262d}}
  .config-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px}}
  .config-item{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;
    display:flex;align-items:center;gap:10px}}
  .config-item .icon{{font-size:18px}}
  .config-item .info .label{{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}}
  .config-item .info .val{{font-size:12px;font-weight:600;color:#e6edf3;font-family:'JetBrains Mono',monospace}}
  .table-wrap{{border:1px solid #30363d;border-radius:10px;overflow:hidden;margin-bottom:28px}}
  table{{width:100%;border-collapse:collapse}}
  thead{{background:#161b22}}
  thead th{{padding:12px 16px;text-align:left;font-size:11px;letter-spacing:1px;
    text-transform:uppercase;color:#8b949e;border-bottom:1px solid #30363d}}
  tbody tr{{border-bottom:1px solid #21262d;transition:background .15s}}
  tbody tr:last-child{{border-bottom:none}}
  tbody tr:hover{{background:#161b22}}
  tbody td{{padding:12px 16px;vertical-align:top;color:#c9d1d9;font-size:13px}}
  .badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1px;color:#fff}}
  .payload{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#f0883e;word-break:break-all}}
  .footer{{text-align:center;color:#484f58;font-size:11px;margin-top:40px;padding-top:20px;border-top:1px solid #21262d}}
  .footer span{{color:#e74c3c}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>⚡ XSS SCAN REPORT</h1>
    <div class="subtitle">CROSS-SITE SCRIPTING VULNERABILITY ASSESSMENT</div>
    <div class="status-badge">{status_text}</div>
  </div>
  <div class="meta-grid">
    <div class="meta-card"><div class="label">Target</div><div class="value">{target}</div></div>
    <div class="meta-card"><div class="label">Scan Time</div><div class="value">{scan_time}</div></div>
    <div class="meta-card"><div class="label">Duration</div><div class="value">{duration:.2f}s</div></div>
    <div class="meta-card"><div class="label">Total Findings</div><div class="value" style="color:{status_color}">{len(results)}</div></div>
  </div>
  <p class="section-title">Scan Configuration</p>
  <div class="config-grid">
    <div class="config-item"><span class="icon">🎯</span><div class="info"><div class="label">Payloads Used</div><div class="val">{payload_count}</div></div></div>
    <div class="config-item"><span class="icon">📋</span><div class="info"><div class="label">Form Scan</div><div class="val">{'Enabled' if scanned_forms else 'Disabled'}</div></div></div>
    <div class="config-item"><span class="icon">📡</span><div class="info"><div class="label">Header Scan</div><div class="val">{'Enabled' if scanned_headers else 'Disabled'}</div></div></div>
  </div>
  <p class="section-title">Vulnerability Findings</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>Severity</th><th>Type</th><th>Location</th><th>Payload</th><th>Status</th></tr></thead>
      <tbody>{vuln_rows}</tbody>
    </table>
  </div>
  <div class="footer">
    Generated by <span>XSS Detector v2.0</span> &nbsp;|&nbsp;
    For authorized penetration testing only. Unauthorized use is illegal.
  </div>
</div>
</body>
</html>"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    log("success", f"HTML report  → {output_file}")

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner()

    # Load payloads AFTER all imports are ready
    payloads = load_payloads("payloads.txt")

    parser = argparse.ArgumentParser(
        description="XSS Detection Tool — Scans URLs and forms for XSS vulnerabilities.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("url",            help="Target URL (e.g. http://example.com/search?q=test)")
    parser.add_argument("--scan-forms",   action="store_true", help="Scan HTML forms on the page")
    parser.add_argument("--scan-headers", action="store_true", help="Test XSS via HTTP headers")
    parser.add_argument("--timeout",      type=int,   default=10,  help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay",        type=float, default=0.0, help="Delay between requests in seconds")
    parser.add_argument("--report-dir",   metavar="DIR", default=".", help="Directory to save reports (default: current dir)")
    parser.add_argument("--cookie",       metavar="COOKIE", help='Session cookie e.g. "session=abc123"')
    parser.add_argument("--proxy",        metavar="URL",    help="HTTP proxy e.g. http://127.0.0.1:8080")
    parser.add_argument("--no-verify",    action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        log("error", "URL must start with http:// or https://")
        sys.exit(1)

    log("info", f"Target      : {args.url}")
    log("info", f"Payloads    : {len(payloads)} loaded from payloads.txt")
    if not BS4_AVAILABLE:
        log("warn", "BeautifulSoup not found — using regex fallback for forms.")
        log("warn", "Install: pip install beautifulsoup4 --break-system-packages")

    # Session setup
    session = requests.Session()
    session.headers.update({"User-Agent": "XSS-Detector/2.0"})
    if args.cookie:
        session.headers.update({"Cookie": args.cookie})
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    verify_ssl = not args.no_verify

    # Connectivity check
    log("info", "Checking connectivity...")
    try:
        r = session.get(args.url, timeout=args.timeout, verify=verify_ssl)
        log("success", f"Connected — HTTP {r.status_code} ({len(r.content)} bytes)")
    except SSLError:
        log("error", "SSL error. Try --no-verify to skip certificate verification.")
        sys.exit(1)
    except ConnectionError:
        log("error", "Cannot connect to target. Check the URL and your network.")
        sys.exit(1)
    except Timeout:
        log("error", f"Connection timed out after {args.timeout}s.")
        sys.exit(1)

    # Begin scan
    results    = []
    start_time = time.time()
    print()

    print(f"{CYAN}▶ [1/3] Scanning URL parameters...{RESET}")
    scan_url_params(args.url, session, payloads, args.timeout, args.delay, results)

    if args.scan_forms:
        print(f"{CYAN}\n▶ [2/3] Scanning HTML forms...{RESET}")
        forms = extract_forms(args.url, session, args.timeout)
        scan_forms(args.url, forms, session, payloads, args.timeout, args.delay, results)
    else:
        print(f"{DIM}\n▶ [2/3] Form scanning skipped (use --scan-forms to enable){RESET}")

    if args.scan_headers:
        print(f"{CYAN}\n▶ [3/3] Testing HTTP headers...{RESET}")
        scan_headers(args.url, session, payloads, args.timeout, args.delay, results)
    else:
        print(f"{DIM}\n▶ [3/3] Header scanning skipped (use --scan-headers to enable){RESET}")

    # Terminal report
    duration = print_report(results, args.url, start_time)

    # Auto-save reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = re.sub(r'[^\w\-]', '_', urllib.parse.urlparse(args.url).netloc)
    base_name = f"xss_report_{safe_host}_{timestamp}"
    os.makedirs(args.report_dir, exist_ok=True)

    json_path = os.path.join(args.report_dir, base_name + ".json")
    html_path = os.path.join(args.report_dir, base_name + ".html")

    print(f"{CYAN}📄 Saving reports...{RESET}")
    save_json_report(results, args.url, json_path)
    save_html_report(results, args.url, duration, html_path,
                     len(payloads), args.scan_forms, args.scan_headers)

    print(f"\n{YELLOW}⚠  Disclaimer: For authorized testing only. Always get written permission.{RESET}\n")
    sys.exit(0 if not results else 1)


if __name__ == "__main__":
    main()
