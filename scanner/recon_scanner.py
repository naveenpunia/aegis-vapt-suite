from __future__ import annotations
import socket
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
import requests

# Curated list of common subdomains for safe educational reconnaissance checks
COMMON_SUBDOMAINS = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
    'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'admin', 'portal',
    'test', 'shop', 'git', 'cpanel', 'support'
]

# Signature mapping for technology fingerprinting
TECH_SIGNATURES = {
    'WordPress': {'headers': ['X-Powered-By', 'Link'], 'body': ['wp-content', 'wp-includes', 'wordpress']},
    'Joomla': {'headers': ['X-Content-Encoded-By'], 'body': ['joomla', 'option=com_']},
    'Drupal': {'headers': ['X-Generator', 'X-Drupal-Cache'], 'body': ['Drupal.settings', 'sites/all']},
    'Cloudflare': {'headers': ['CF-RAY', 'CF-Cache-Status', 'Server'], 'body': ['cloudflare-nginx', '__cfduid']},
    'Nginx': {'headers': ['Server'], 'body': []},
    'Apache': {'headers': ['Server'], 'body': []},
    'Microsoft-IIS': {'headers': ['Server', 'X-AspNet-Version'], 'body': []},
    'PHP': {'headers': ['X-Powered-By'], 'body': []},
    'ASP.NET': {'headers': ['X-Powered-By', 'X-AspNet-Version'], 'body': []},
    'React': {'headers': [], 'body': ['react.development.js', 'react.production.min.js', 'data-reactroot']},
    'jQuery': {'headers': [], 'body': ['jquery.js', 'jquery.min.js', 'jQuery']},
    'Bootstrap': {'headers': [], 'body': ['bootstrap.css', 'bootstrap.min.css', 'bootstrap.js', 'bootstrap.min.js']}
}

@dataclass
class ReconScanner:
    timeout: int = 8
    max_threads: int = 15
    session: requests.Session = field(default_factory=requests.Session)

    def scan(self, url: str) -> dict[str, Any]:
        """Runs subdomain mapping and technology fingerprinting on the target URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        if not hostname:
            return {'error': 'Invalid URL or Hostname'}

        results: dict[str, Any] = {
            'subdomains': [],
            'technologies': [],
            'server_headers': {},
            'ip_addresses': []
        }

        # 1. Resolve host IP addresses
        try:
            ips = socket.getaddrinfo(hostname, None)
            results['ip_addresses'] = sorted(list(set(ip[4][0] for ip in ips)))
        except socket.gaierror:
            results['ip_addresses'] = []

        # 2. Tech Fingerprinting
        self._fingerprint_tech(url, results)

        # 3. Subdomain Scanning (Safe, educational passive check)
        self._scan_subdomains(hostname, results)

        return results

    def _fingerprint_tech(self, url: str, results: dict[str, Any]) -> None:
        try:
            response = self.session.get(url, timeout=self.timeout, headers={'User-Agent': 'VAPT-Suite-Educational/1.0'})
            headers = response.headers
            results['server_headers'] = {k: v for k, v in headers.items() if k in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator', 'Via', 'X-Cache']}
            
            body = response.text.lower()
            detected_tech = set()

            # Analyze signatures
            for tech, sig in TECH_SIGNATURES.items():
                # Check headers
                for h_name in sig['headers']:
                    h_val = headers.get(h_name, '')
                    if h_val and (tech.lower() in h_val.lower() or (tech == 'Nginx' and 'nginx' in h_val.lower()) or (tech == 'Apache' and 'apache' in h_val.lower())):
                        detected_tech.add(tech)

                # Check body content
                for key in sig['body']:
                    if key.lower() in body:
                        detected_tech.add(tech)

            results['technologies'] = list(detected_tech)
        except Exception as e:
            results['error_recon'] = f"Tech fingerprinting failed: {e}"

    def _scan_subdomains(self, base_domain: str, results: dict[str, Any]) -> None:
        # If the base domain is an IP address, skip subdomain check
        if base_domain.replace('.', '').isdigit():
            return

        # Strip 'www.' if present for clean base domain scanning
        clean_domain = base_domain
        if base_domain.startswith('www.'):
            clean_domain = base_domain[4:]

        discovered_subdomains = []
        lock = threading.Lock()

        def resolve_subdomain(sub: str) -> None:
            subdomain_host = f"{sub}.{clean_domain}"
            try:
                ip = socket.gethostbyname(subdomain_host)
                with lock:
                    discovered_subdomains.append({'subdomain': subdomain_host, 'ip': ip})
            except socket.gaierror:
                pass

        threads = []
        for sub in COMMON_SUBDOMAINS:
            t = threading.Thread(target=resolve_subdomain, args=(sub,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        results['subdomains'] = discovered_subdomains
