from __future__ import annotations
import html
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import requests
from utils.helpers import normalize_url

try:
    from bs4 import BeautifulSoup
except ModuleNotFoundError:
    BeautifulSoup = None

SAFE_XSS_PAYLOADS = ['xss_test_12345', '<b>xss_test_12345</b>', '"><xss-test>safe</xss-test>']

@dataclass
class XSSScanner:
    timeout: int = 10
    session: requests.Session = field(default_factory=requests.Session)

    def scan(self, url: str) -> list[dict[str, Any]]:
        normalized_url = normalize_url(url)
        parsed = urlparse(normalized_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return [{
                'parameter': 'N/A',
                'payload': 'N/A',
                'vulnerable': False,
                'evidence': 'No query parameters found to test safely.',
                'severity': 'Low'
            }]

        findings: list[dict[str, Any]] = []
        for param_name, original_value in params:
            for payload in SAFE_XSS_PAYLOADS:
                test_params = [
                    (name, payload if name == param_name else value)
                    for name, value in params
                ]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                body = self._safe_get_text(test_url)
                
                reflected_raw = payload in body
                reflected_encoded = html.escape(payload) in body
                dom_context = self._detect_dom_reflection(body, payload)
                
                # If raw special characters in the payload are reflected, it's vulnerable
                has_special_chars = any(char in payload for char in ['<', '>', '"', "'"])
                vulnerable = reflected_raw and has_special_chars
                
                evidence = 'Payload not reflected'
                if reflected_raw:
                    evidence = 'Raw payload reflected in HTML response'
                elif reflected_encoded:
                    evidence = 'Payload reflected after HTML entity encoding (Safe)'
                elif dom_context:
                    evidence = dom_context

                findings.append({
                    'parameter': param_name,
                    'original_value': original_value,
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'evidence': evidence,
                    'severity': 'Medium' if vulnerable else 'Low',
                    'sanitized': reflected_encoded and (not reflected_raw)
                })
        return findings

    def _safe_get_text(self, url: str) -> str:
        try:
            response = self.session.get(url, timeout=self.timeout)
            return response.text[:200000]
        except requests.RequestException:
            return 'REQUEST_ERROR'

    @staticmethod
    def _detect_dom_reflection(body: str, payload: str) -> str:
        if BeautifulSoup is None:
            if 'xss_test_12345' in body and ('<script' in body.lower() or '<input' in body.lower()):
                return 'Marker reflected near script or form content'
            return ''
        soup = BeautifulSoup(body, 'html.parser')
        marker = 'xss_test_12345'
        for script in soup.find_all('script'):
            if script.string and marker in script.string:
                return 'Marker reflected inside script content'
        for tag in soup.find_all(['input', 'textarea']):
            if marker in str(tag.get('value', '')) or marker in tag.get_text():
                return 'Marker reflected inside a form field'
        return ''