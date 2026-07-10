from __future__ import annotations
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from utils.helpers import normalize_url

@dataclass
class SSLChecker:
    timeout: int = 10

    def check(self, url: str) -> dict[str, Any]:
        parsed = urlparse(normalize_url(url))
        hostname = parsed.hostname
        port = parsed.port or 443
        result: dict[str, Any] = {'host': hostname, 'port': port, 'issuer': 'Unknown', 'subject': 'Unknown', 'expiry_date': 'Unknown', 'days_remaining': None, 'tls_version': 'Unknown', 'valid': False, 'expired': False, 'error': None}
        if not hostname:
            result['error'] = 'No hostname found'
            return result
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    result['tls_version'] = secure_sock.version()
            expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (expiry - now).days
            result['issuer'] = self._format_name(cert.get('issuer', ()))
            result['subject'] = self._format_name(cert.get('subject', ()))
            result['expiry_date'] = expiry.strftime('%Y-%m-%d %H:%M:%S UTC')
            result['days_remaining'] = days_remaining
            result['expired'] = days_remaining < 0
            result['valid'] = not result['expired']
        except Exception as exc:
            result['error'] = str(exc)
        return result

    @staticmethod
    def _format_name(name_parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
        values: list[str] = []
        for group in name_parts:
            for key, value in group:
                values.append(f'{key}={value}')
        return ', '.join(values) if values else 'Unknown'