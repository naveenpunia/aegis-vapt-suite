from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import requests
from utils.helpers import detect_suspicious_url, is_valid_url, normalize_url
SECURITY_HEADERS = {'Content-Security-Policy': 'Reduces XSS and content injection risk', 'Strict-Transport-Security': 'Forces HTTPS for supported browsers', 'X-Frame-Options': 'Helps prevent clickjacking', 'X-Content-Type-Options': 'Prevents MIME sniffing', 'Referrer-Policy': 'Limits sensitive referrer leakage', 'Permissions-Policy': 'Restricts browser feature access'}

@dataclass
class URLScanner:
    timeout: int = 10
    user_agent: str = 'MiniPentestToolkit/1.0 Educational Scanner'
    session: requests.Session = field(default_factory=requests.Session)

    def scan(self, url: str) -> dict[str, Any]:
        normalized_url = normalize_url(url)
        result: dict[str, Any] = {'target': normalized_url, 'valid': is_valid_url(normalized_url), 'suspicious_indicators': detect_suspicious_url(normalized_url), 'status_code': None, 'reason': None, 'final_url': None, 'redirects': [], 'headers': {}, 'server': 'Unknown', 'security_headers': {}, 'missing_security_headers': [], 'error': None}
        if not result['valid']:
            result['error'] = 'Malformed or unsupported URL'
            return result
        try:
            response = self.session.get(normalized_url, timeout=self.timeout, allow_redirects=True, headers={'User-Agent': self.user_agent})
            result['status_code'] = response.status_code
            result['reason'] = response.reason
            result['final_url'] = response.url
            result['redirects'] = [{'status_code': item.status_code, 'url': item.url} for item in response.history]
            result['headers'] = dict(response.headers)
            result['server'] = response.headers.get('Server', 'Unknown')
            result['security_headers'] = {header: response.headers.get(header) for header in SECURITY_HEADERS if response.headers.get(header)}
            result['missing_security_headers'] = [header for header in SECURITY_HEADERS if header not in response.headers]
        except requests.RequestException as exc:
            result['error'] = str(exc)
        return result