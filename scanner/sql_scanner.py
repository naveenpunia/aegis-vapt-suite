from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import requests
from utils.helpers import normalize_url

SQL_ERROR_PATTERNS = [
    'SQL syntax.*MySQL', 'Warning.*mysql_', 'PostgreSQL.*ERROR', 
    'valid PostgreSQL result', 'Microsoft OLE DB Provider', 
    'ODBC SQL Server Driver', 'SQLite/JDBCDriver', 
    'sqlite3\\.OperationalError', 'ORA-\\d{5}', 
    'unterminated quoted string', 'you have an error in your sql syntax'
]
SAFE_SQL_PAYLOADS = ["'", '"', "'--", '")', "' OR '1'='1", "'; SELECT pg_sleep(1.5)--", "' OR SLEEP(1.5)--"]

@dataclass
class SQLInjectionScanner:
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
        baseline_text, baseline_time, _ = self._safe_get_response(normalized_url)

        for param_name, original_value in params:
            for payload in SAFE_SQL_PAYLOADS:
                test_params = [
                    (name, f'{value}{payload}' if name == param_name else value)
                    for name, value in params
                ]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                response_text, response_time, headers = self._safe_get_response(test_url)

                # Evidence 1: SQL syntax error pattern in text
                evidence = self._find_sql_error(response_text)
                
                # Evidence 2: Response size anomaly
                response_difference = abs(len(response_text) - len(baseline_text))
                size_anomaly = response_difference > max(800, len(baseline_text) * 0.35)

                # Evidence 3: Database error in headers
                header_evidence = ''
                for k, v in headers.items():
                    if 'db-error' in k.lower() or 'sql-error' in k.lower():
                        header_evidence = f"DB header anomaly: {k}={v}"

                # Evidence 4: Time-based delay anomaly
                time_delay = response_time - baseline_time
                time_anomaly = 'sleep' in payload.lower() and time_delay > 1.2

                vulnerable = bool(evidence) or size_anomaly or bool(header_evidence) or time_anomaly

                vuln_evidence = []
                if evidence:
                    vuln_evidence.append(evidence)
                if size_anomaly:
                    vuln_evidence.append(f'Response size diff: {response_difference} chars')
                if header_evidence:
                    vuln_evidence.append(header_evidence)
                if time_anomaly:
                    vuln_evidence.append(f'Time delay anomaly: {time_delay:.2f}s (payload: {payload})')

                findings.append({
                    'parameter': param_name,
                    'original_value': original_value,
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'evidence': ' | '.join(vuln_evidence) if vulnerable else 'No anomaly detected',
                    'severity': 'High' if vulnerable else 'Low'
                })
        return findings

    def _safe_get_response(self, url: str) -> tuple[str, float, dict[str, str]]:
        start = time.perf_counter()
        try:
            response = self.session.get(url, timeout=self.timeout)
            duration = time.perf_counter() - start
            return response.text[:200000], duration, dict(response.headers)
        except requests.RequestException:
            return 'REQUEST_ERROR', self.timeout, {}

    @staticmethod
    def _find_sql_error(text: str) -> str:
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f'SQL error indicator matched: {match.group(0)}'
        return ''