from __future__ import annotations
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, urlparse
from colorama import Fore, Style
DISCLAIMER = '\nETHICAL USE DISCLAIMER\nThis toolkit is for educational and authorized security testing only.\nScan only systems and websites that you own or have written permission to test.\nNo exploitation, brute force, malware, privilege escalation, persistence, or data extraction is performed.\n'
SUSPICIOUS_URL_PATTERNS = ['@', '%00', '\\.\\.', '(?:http|https)://(?:\\d{1,3}\\.){3}\\d{1,3}', '(?:login|verify|secure|account).*\\.(?:zip|exe|scr)$']

def ensure_output_dir(path: str='output') -> Path:
    output_dir = Path(path)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

def normalize_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned.startswith(('http://', 'https://')):
        cleaned = f'https://{cleaned}'
    return cleaned

def parse_url(url: str) -> ParseResult:
    return urlparse(normalize_url(url))

def is_valid_url(url: str) -> bool:
    parsed = parse_url(url)
    return parsed.scheme in {'http', 'https'} and bool(parsed.netloc)

def detect_suspicious_url(url: str) -> list[str]:
    indicators: list[str] = []
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(pattern)
    return indicators

def now_timestamp() -> str:
    return datetime.now().strftime('%Y%m%d_%H%M%S')

def severity_color(severity: str) -> str:
    severity_map = {'Low': Fore.GREEN, 'Medium': Fore.YELLOW, 'High': Fore.RED, 'Critical': Fore.MAGENTA}
    return severity_map.get(severity, Fore.WHITE)

def color_status(text: str, severity: str) -> str:
    return f'{severity_color(severity)}{text}{Style.RESET_ALL}'

def calculate_risk_score(results: dict[str, Any]) -> tuple[int, str, list[str]]:
    score = 0
    recommendations: list[str] = []
    url_scan = results.get('url_scan', {})
    if url_scan.get('suspicious_indicators'):
        score += 10
        recommendations.append('Review suspicious URL patterns and avoid testing untrusted targets.')
    if url_scan.get('missing_security_headers'):
        score += min(25, len(url_scan['missing_security_headers']) * 5)
        recommendations.append('Add missing HTTP security headers such as CSP, HSTS, and X-Frame-Options.')
    open_ports = [item for item in results.get('port_scan', []) if item.get('status') == 'Open']
    if open_ports:
        score += min(25, len(open_ports) * 5)
        recommendations.append('Close unused open ports or restrict them with a firewall.')
    sql_results = results.get('sql_injection', [])
    if any((item.get('vulnerable') for item in sql_results)):
        score += 25
        recommendations.append('Use parameterized queries and generic database error handling.')
    xss_results = results.get('xss', [])
    if any((item.get('vulnerable') for item in xss_results)):
        score += 25
        recommendations.append('Apply output encoding and strict input validation to reflected parameters.')
    ssl_status = results.get('ssl', {})
    ssl_error = str(ssl_status.get('error', ''))
    if 'not HTTPS' in ssl_error:
        score += 10
        recommendations.append('Use HTTPS for encrypted transport and certificate-based identity.')
    elif ssl_status.get('expired') or not ssl_status.get('valid', True):
        score += 20
        recommendations.append('Renew or replace the TLS certificate and verify certificate chains.')
    score = min(score, 100)
    if score >= 80:
        severity = 'Critical'
    elif score >= 50:
        severity = 'High'
    elif score >= 25:
        severity = 'Medium'
    else:
        severity = 'Low'
    if not recommendations:
        recommendations.append('Maintain regular patching, monitoring, backups, and secure configuration reviews.')
    return (score, severity, recommendations)