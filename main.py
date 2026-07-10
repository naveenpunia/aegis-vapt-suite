from __future__ import annotations
import argparse
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from colorama import Fore, Style, init
from reports.report_generator import ReportGenerator
from scanner.port_scanner import COMMON_PORTS, PortScanner
from scanner.sql_scanner import SQLInjectionScanner
from scanner.ssl_checker import SSLChecker
from scanner.url_scanner import URLScanner
from scanner.xss_scanner import XSSScanner
from utils.helpers import DISCLAIMER, ensure_output_dir, normalize_url, now_timestamp
from utils.logger import setup_logger

def parse_ports(raw_ports: str | None) -> list[int]:
    if not raw_ports:
        return COMMON_PORTS
    ports: set[int] = set()
    for part in raw_ports.split(','):
        item = part.strip()
        if not item:
            continue
        if '-' in item:
            start_text, end_text = item.split('-', 1)
            start, end = (int(start_text), int(end_text))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    return sorted((port for port in ports if 1 <= port <= 65535))

def resolve_host(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    if not parsed.hostname:
        raise ValueError('Could not determine hostname from target URL.')
    return parsed.hostname

def print_progress(message: str) -> None:
    print(f'{Fore.CYAN}[+] {message}{Style.RESET_ALL}')

def append_history(summary: dict[str, Any], history_file: str='output/scan_history.jsonl') -> None:
    path = Path(history_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as file_obj:
        file_obj.write(json.dumps(summary, default=str) + '\n')

def run_scan(target_url: str, ports: list[int], timeout: int, skip_ports: bool) -> dict[str, Any]:
    normalized_url = normalize_url(target_url)
    host = resolve_host(normalized_url)
    results: dict[str, Any] = {
        'target_url': normalized_url,
        'target_host': host,
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'url_scan': {},
        'port_scan': [],
        'sql_injection': [],
        'xss': [],
        'ssl': {},
        'recon_scan': {'subdomains': [], 'technologies': [], 'server_headers': {}, 'ip_addresses': []}
    }
    print_progress('Running URL scanner')
    results['url_scan'] = URLScanner(timeout=timeout).scan(normalized_url)
    
    print_progress('Running technology profiling and DNS subdomain mapping')
    from scanner.recon_scanner import ReconScanner
    results['recon_scan'] = ReconScanner(timeout=timeout).scan(normalized_url)

    if skip_ports:
        print_progress('Skipping port scanner')
    else:
        print_progress(f'Running threaded port scanner against {host}')
        results['port_scan'] = PortScanner(timeout=1.0).scan(host, ports)
    print_progress('Running safe SQL injection indicator tests')
    results['sql_injection'] = SQLInjectionScanner(timeout=timeout).scan(normalized_url)
    print_progress('Running safe reflected XSS checks')
    results['xss'] = XSSScanner(timeout=timeout).scan(normalized_url)
    if normalized_url.startswith('https://'):
        print_progress('Checking SSL/TLS certificate')
        results['ssl'] = SSLChecker(timeout=timeout).check(normalized_url)
    else:
        results['ssl'] = {'host': host, 'valid': False, 'expired': False, 'error': 'SSL check skipped because target is not HTTPS.'}
    return results

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Educational Mini Penetration Testing Toolkit', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('targets', nargs='+', help='Target URL(s), for example https://example.com')
    parser.add_argument('--ports', help='Ports to scan, for example 80,443,8080 or 1-1024')
    parser.add_argument('--timeout', type=int, default=10, help='HTTP/SSL timeout in seconds')
    parser.add_argument('--skip-ports', action='store_true', help='Skip TCP port scanning')
    parser.add_argument('--no-export', action='store_true', help='Only print console report')
    return parser

def main() -> None:
    init(autoreset=True)
    ensure_output_dir()
    logger = setup_logger()
    parser = build_parser()
    args = parser.parse_args()
    ports = parse_ports(args.ports)
    report_generator = ReportGenerator()
    for index, target_url in enumerate(args.targets, start=1):
        print(Fore.YELLOW + DISCLAIMER + Style.RESET_ALL)
        print_progress(f'Starting authorized scan {index}/{len(args.targets)}: {target_url}')
        try:
            results = run_scan(target_url, ports, args.timeout, args.skip_ports)
            report_generator.print_console(results)
            enriched = report_generator.enrich_results(results)
            base_name = f"report_{socket.getfqdn(resolve_host(target_url)).replace('.', '_')}_{now_timestamp()}"
            exported_paths: dict[str, str] = {}
            if not args.no_export:
                exported_paths = report_generator.save_all(results, base_name)
                print_progress('Reports exported:')
                for report_type, path in exported_paths.items():
                    print(f'  {report_type.upper()}: {path}')
            append_history({'target': normalize_url(target_url), 'scan_time': enriched['scan_time'], 'risk_score': enriched['risk_score'], 'risk_severity': enriched['risk_severity'], 'reports': exported_paths})
            logger.info('Completed scan for %s', target_url)
        except Exception as exc:
            logger.exception('Scan failed for %s', target_url)
            print(f'{Fore.RED}Scan failed for {target_url}: {exc}{Style.RESET_ALL}')
if __name__ == '__main__':
    main()