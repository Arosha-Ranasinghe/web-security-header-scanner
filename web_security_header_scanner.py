#!/usr/bin/env python3
"""
Web Security Header Scanner (Advanced)
=====================================

A pentest-style HTTP security header scanner.

Features:
- CLI flags: --url, --paths, --timeout, --json, --no-color, --no-values, --insecure
- Scans multiple endpoints because headers can differ per route
- Detects redirect chains + basic HTTP->HTTPS behavior issues
- Checks presence of key security headers
- Performs basic misconfiguration checks (simple heuristics)
- Clean colored report + optional JSON output

Disclaimer:
Only scan targets you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests


# ----------------------------
# Terminal styling (ANSI)
# ----------------------------

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


def supports_color(no_color: bool) -> bool:
    """Enable colors only when output is a terminal and user didn't disable it."""
    if no_color:
        return False
    return sys.stdout.isatty()


def c(text: str, enable: bool, *styles: str) -> str:
    """Colorize text if enabled."""
    if not enable:
        return text
    return "".join(styles) + text + Color.RESET


def hr(width: int = 88, char: str = "-") -> str:
    return char * width


# ----------------------------
# Data model
# ----------------------------

@dataclass
class HeaderRule:
    name: str
    purpose: str
    recommended: str


@dataclass
class Finding:
    header: str
    endpoint: str
    status: str  # PRESENT / MISSING / WEAK
    severity: str  # INFO/LOW/MEDIUM/HIGH
    message: str


@dataclass
class EndpointResult:
    endpoint: str
    final_url: str
    status_code: int
    redirect_chain: List[str]
    headers: Dict[str, str]
    findings: List[Finding]
    score_points: int
    score_max: int


@dataclass
class ScanReport:
    target: str
    timestamp_utc: str
    endpoints_scanned: List[str]
    results: List[EndpointResult]
    total_points: int
    total_max: int
    percentage: float
    risk: str


# ----------------------------
# Rules (headers to check)
# ----------------------------

def rules() -> List[HeaderRule]:
    return [
        HeaderRule(
            name="Content-Security-Policy",
            purpose="Mitigates XSS/content injection by restricting permitted sources.",
            recommended="Use a strict policy; avoid 'unsafe-inline'/'unsafe-eval' where possible.",
        ),
        HeaderRule(
            name="Strict-Transport-Security",
            purpose="Forces HTTPS; mitigates SSL stripping/downgrade attacks.",
            recommended="Prefer: max-age>=15552000; includeSubDomains; preload (as appropriate).",
        ),
        HeaderRule(
            name="X-Frame-Options",
            purpose="Mitigates clickjacking by blocking framing/embedding.",
            recommended="Use DENY or SAMEORIGIN (or CSP frame-ancestors).",
        ),
        HeaderRule(
            name="X-Content-Type-Options",
            purpose="Prevents MIME sniffing to reduce content-type confusion attacks.",
            recommended="Use: nosniff",
        ),
        HeaderRule(
            name="Referrer-Policy",
            purpose="Reduces referrer leakage (privacy + info exposure).",
            recommended="Prefer: no-referrer or strict-origin-when-cross-origin.",
        ),
        HeaderRule(
            name="Permissions-Policy",
            purpose="Restricts powerful browser features (camera/mic/geolocation/etc.).",
            recommended="Disable features by default; allow only what you need.",
        ),
    ]


# ----------------------------
# Input helpers
# ----------------------------

def normalize_url(user_input: str) -> str:
    """Normalize URL and add https:// if missing."""
    url = user_input.strip()
    if not url:
        raise ValueError("Target URL cannot be empty.")
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL scheme must be http or https.")
    if not parsed.netloc:
        raise ValueError("Invalid URL. Example: https://example.com")
    return url


def normalize_paths(paths_csv: str) -> List[str]:
    """
    Convert comma-separated paths to a clean list.
    Ensures each path begins with /, and includes / by default.
    """
    parts = [p.strip() for p in paths_csv.split(",") if p.strip()]
    if not parts:
        return ["/"]

    normed: List[str] = []
    for p in parts:
        if not p.startswith("/"):
            p = "/" + p
        normed.append(p)

    if "/" not in normed:
        normed.insert(0, "/")

    return normed


# ----------------------------
# HTTP fetching
# ----------------------------

def fetch(url: str, timeout: int, verify_tls: bool) -> requests.Response:
    """
    Fetch a URL. Try HEAD first, then GET fallback.
    """
    req_headers = {
        "User-Agent": "Web-Security-Header-Scanner/3.0 (advanced; educational; pentest-style)",
        "Accept": "*/*",
    }

    try:
        r = requests.head(url, headers=req_headers, allow_redirects=True, timeout=timeout, verify=verify_tls)
        if r.status_code == 405:
            raise requests.exceptions.RequestException("HEAD not allowed")
        return r
    except requests.exceptions.RequestException:
        return requests.get(url, headers=req_headers, allow_redirects=True, timeout=timeout, verify=verify_tls)


def redirect_chain(resp: requests.Response) -> List[str]:
    """Build redirect chain from requests history + final URL."""
    chain = [h.url for h in resp.history] + [resp.url]
    cleaned: List[str] = []
    for u in chain:
        if not cleaned or cleaned[-1] != u:
            cleaned.append(u)
    return cleaned


# ----------------------------
# Analysis helpers
# ----------------------------

def lower_dict(headers: Dict[str, str]) -> Dict[str, str]:
    """Lowercase header names for case-insensitive matching."""
    return {k.lower(): v for k, v in headers.items()}


def check_presence(endpoint: str, headers: Dict[str, str]) -> List[Finding]:
    """Presence checks for required headers."""
    findings: List[Finding] = []
    h = lower_dict(headers)

    for r in rules():
        if r.name.lower() not in h or not str(h.get(r.name.lower(), "")).strip():
            findings.append(
                Finding(
                    header=r.name,
                    endpoint=endpoint,
                    status="MISSING",
                    severity="MEDIUM",
                    message=f"Missing {r.name}. {r.purpose} Recommendation: {r.recommended}",
                )
            )
    return findings


def check_quality(endpoint: str, headers: Dict[str, str]) -> List[Finding]:
    """Basic misconfiguration checks (heuristics)."""
    findings: List[Finding] = []
    h = lower_dict(headers)

    # HSTS checks
    if "strict-transport-security" in h:
        v = str(h["strict-transport-security"])
        m = re.search(r"max-age\s*=\s*(\d+)", v, flags=re.IGNORECASE)
        if not m:
            findings.append(
                Finding("Strict-Transport-Security", endpoint, "WEAK", "HIGH",
                        "HSTS present but max-age is missing; policy may be ineffective.")
            )
        else:
            max_age = int(m.group(1))
            if max_age < 15552000:
                findings.append(
                    Finding("Strict-Transport-Security", endpoint, "WEAK", "MEDIUM",
                            f"HSTS max-age appears low ({max_age}); consider >= 15552000.")
                )
        if "includesubdomains" not in v.lower():
            findings.append(
                Finding("Strict-Transport-Security", endpoint, "WEAK", "LOW",
                        "HSTS missing includeSubDomains; subdomains may still be reachable over HTTP.")
            )

    # CSP checks
    if "content-security-policy" in h:
        v = str(h["content-security-policy"]).lower()
        if "unsafe-inline" in v:
            findings.append(
                Finding("Content-Security-Policy", endpoint, "WEAK", "MEDIUM",
                        "CSP allows 'unsafe-inline' which weakens protection against XSS.")
            )
        if "unsafe-eval" in v:
            findings.append(
                Finding("Content-Security-Policy", endpoint, "WEAK", "MEDIUM",
                        "CSP allows 'unsafe-eval' which can increase XSS risk in some scenarios.")
            )
        if "frame-ancestors" not in v:
            findings.append(
                Finding("Content-Security-Policy", endpoint, "WEAK", "LOW",
                        "CSP present but missing 'frame-ancestors' (modern clickjacking control).")
            )

    # X-Content-Type-Options
    if "x-content-type-options" in h:
        v = str(h["x-content-type-options"]).strip().lower()
        if v != "nosniff":
            findings.append(
                Finding("X-Content-Type-Options", endpoint, "WEAK", "LOW",
                        f"X-Content-Type-Options is '{v}' (expected 'nosniff').")
            )

    # X-Frame-Options
    if "x-frame-options" in h:
        v = str(h["x-frame-options"]).strip().upper()
        if v not in ("DENY", "SAMEORIGIN"):
            findings.append(
                Finding("X-Frame-Options", endpoint, "WEAK", "LOW",
                        f"X-Frame-Options is '{v}'. Prefer DENY or SAMEORIGIN.")
            )

    # Referrer-Policy
    if "referrer-policy" in h:
        v = str(h["referrer-policy"]).strip().lower()
        if v in {"unsafe-url", "no-referrer-when-downgrade"}:
            findings.append(
                Finding("Referrer-Policy", endpoint, "WEAK", "LOW",
                        f"Referrer-Policy is '{v}', which may leak more referrer info than desired.")
            )

    return findings


def check_http_to_https_behavior(endpoint: str, original_url: str, final_url: str) -> Optional[Finding]:
    """Flag if scanning over HTTP does not end on HTTPS."""
    o = urlparse(original_url)
    f = urlparse(final_url)
    if o.scheme == "http" and f.scheme != "https":
        return Finding(
            header="Transport",
            endpoint=endpoint,
            status="WEAK",
            severity="HIGH",
            message="Target was scanned over HTTP and did not end on HTTPS. Consider enforcing HTTPS redirection.",
        )
    return None


# ----------------------------
# Scoring
# ----------------------------

def compute_score(headers: Dict[str, str], findings: List[Finding]) -> Tuple[int, int]:
    """
    Simple scoring:
    - +1 for each required header present (max 6)
    - -1 for each WEAK finding (can't go below 0)
    """
    max_points = 6
    h = lower_dict(headers)

    present = 0
    for r in rules():
        if r.name.lower() in h and str(h.get(r.name.lower(), "")).strip():
            present += 1

    penalty = sum(1 for f in findings if f.status == "WEAK")
    points = max(0, present - penalty)
    return points, max_points


def overall_risk(percentage: float) -> str:
    if percentage >= 85:
        return "LOW"
    if percentage >= 60:
        return "MEDIUM"
    return "HIGH"


# ----------------------------
# Reporting
# ----------------------------

def print_banner(color_on: bool) -> None:
    print(c(hr(char="=", width=88), color_on, Color.CYAN))
    print(c(f"{'WEB SECURITY HEADER SCANNER':^88}", color_on, Color.CYAN, Color.BOLD))
    print(c(f"{'Advanced pentest-style header audit':^88}", color_on, Color.CYAN))
    print(c(hr(char="=", width=88), color_on, Color.CYAN))


def sev_color(sev: str) -> str:
    return {"INFO": Color.GRAY, "LOW": Color.YELLOW, "MEDIUM": Color.YELLOW, "HIGH": Color.RED}.get(sev, Color.GRAY)


def print_endpoint_result(color_on: bool, res: EndpointResult, show_values: bool) -> None:
    print(c(f"[*] Endpoint: {res.endpoint}", color_on, Color.BLUE, Color.BOLD))
    print(f"{'Final URL':<18}: {res.final_url}")
    print(f"{'Status Code':<18}: {res.status_code}")
    print(f"{'Redirects':<18}: {len(res.redirect_chain) - 1}")
    print(f"{'Score':<18}: {res.score_points}/{res.score_max}")
    print()

    col1, col2 = 32, 10
    print(c(f"{'Header':<{col1}} {'Status':<{col2}} Details", color_on, Color.BOLD))
    print(c(hr(width=88), color_on, Color.GRAY))

    h = lower_dict(res.headers)
    for r in rules():
        val = h.get(r.name.lower())
        present = val is not None and str(val).strip() != ""
        status = "PRESENT" if present else "MISSING"
        status_color = Color.GREEN if present else Color.RED
        print(f"{r.name:<{col1}} {c(status, color_on, status_color, Color.BOLD):<{col2}} {r.purpose}")

        if present and show_values:
            wrapped = textwrap.fill(str(val).strip(), width=88, initial_indent=" " * 4, subsequent_indent=" " * 4)
            print(c("    Observed:", color_on, Color.GRAY) + " " + wrapped.strip())

        if not present:
            rec = textwrap.fill(r.recommended, width=88, initial_indent=" " * 4, subsequent_indent=" " * 4)
            print(c("    Recommendation:", color_on, Color.GRAY) + " " + rec.strip())
        print()

    if res.findings:
        print(c("[*] Findings", color_on, Color.MAGENTA, Color.BOLD))
        for f in res.findings:
            sev = c(f.severity, color_on, sev_color(f.severity), Color.BOLD)
            print(f"- [{sev}] {f.header}: {f.message}")
        print()

    print(c(hr(width=88), color_on, Color.GRAY))
    print()


def print_overall_summary(color_on: bool, report: ScanReport) -> None:
    risk_col = Color.GREEN if report.risk == "LOW" else (Color.YELLOW if report.risk == "MEDIUM" else Color.RED)
    pct = report.percentage

    bar_width = 40
    filled = int((pct / 100) * bar_width)
    bar = "[" + ("#" * filled) + ("-" * (bar_width - filled)) + "]"

    print(c("[*] Overall Summary", color_on, Color.BLUE, Color.BOLD))
    print(f"{'Total Score':<18}: {report.total_points}/{report.total_max} ({pct:.0f}%)")
    print(f"{'Risk Rating':<18}: {c(report.risk, color_on, risk_col, Color.BOLD)}")
    print(f"{'Score Bar':<18}: {bar}")
    print()


# ----------------------------
# Scan orchestrator
# ----------------------------

def scan_target(base_url: str, paths: List[str], timeout: int, verify_tls: bool) -> ScanReport:
    endpoint_urls = [urljoin(base_url.rstrip("/") + "/", p.lstrip("/")) for p in paths]

    results: List[EndpointResult] = []
    total_points = 0
    total_max = 0

    for p, full_url in zip(paths, endpoint_urls):
        resp = fetch(full_url, timeout=timeout, verify_tls=verify_tls)
        headers = dict(resp.headers)
        chain = redirect_chain(resp)

        findings: List[Finding] = []
        findings.extend(check_presence(p, headers))
        findings.extend(check_quality(p, headers))

        tf = check_http_to_https_behavior(p, full_url, str(resp.url))
        if tf:
            findings.append(tf)

        pts, mx = compute_score(headers, findings)
        results.append(
            EndpointResult(
                endpoint=p,
                final_url=str(resp.url),
                status_code=int(resp.status_code),
                redirect_chain=chain,
                headers=headers,
                findings=findings,
                score_points=pts,
                score_max=mx,
            )
        )
        total_points += pts
        total_max += mx

    pct = (total_points / total_max * 100) if total_max else 0.0
    risk = overall_risk(pct)

    return ScanReport(
        target=base_url,
        timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        endpoints_scanned=paths,
        results=results,
        total_points=total_points,
        total_max=total_max,
        percentage=pct,
        risk=risk,
    )


# ----------------------------
# CLI
# ----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Advanced pentest-style scanner for HTTP security headers.")
    p.add_argument("--url", required=True, help="Target base URL (e.g. https://example.com)")
    p.add_argument("--paths", default="/", help="Comma-separated paths (default: /). Example: /,/login,/admin")
    p.add_argument("--timeout", type=int, default=12, help="Request timeout in seconds (default: 12)")
    p.add_argument("--json", dest="json_out", help="Write full JSON report to a file path.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colored output.")
    p.add_argument("--no-values", action="store_true", help="Do not print observed header values.")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (NOT recommended).")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    color_on = supports_color(args.no_color)

    try:
        base_url = normalize_url(args.url)
    except ValueError as e:
        print(c(f"[!] Input error: {e}", color_on, Color.RED, Color.BOLD))
        sys.exit(1)

    paths = normalize_paths(args.paths)

    try:
        report = scan_target(base_url, paths, timeout=args.timeout, verify_tls=(not args.insecure))
    except requests.exceptions.RequestException as e:
        print(c("[!] Connection error: Could not reach the target.", color_on, Color.RED, Color.BOLD))
        print(c(f"    Details: {e}", color_on, Color.GRAY))
        sys.exit(1)

    print_banner(color_on)
    print(f"{'Target':<18}: {report.target}")
    print(f"{'Timestamp':<18}: {report.timestamp_utc}")
    print(f"{'Endpoints':<18}: {', '.join(report.endpoints_scanned)}")
    print(c(hr(width=88), color_on, Color.GRAY))
    print()

    for res in report.results:
        print_endpoint_result(color_on, res, show_values=(not args.no_values))

    print_overall_summary(color_on, report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2)
        print(c(f"[*] JSON report written to: {args.json_out}", color_on, Color.GREEN, Color.BOLD))

    print(c(hr(char="=", width=88), color_on, Color.CYAN))
    print(c("Scan complete.", color_on, Color.CYAN, Color.BOLD))
    print(c(hr(char="=", width=88), color_on, Color.CYAN))


if __name__ == "__main__":
    main()
