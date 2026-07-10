from __future__ import annotations
import json
import os
import mimetypes
import socket
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse, parse_qs
import hashlib

# Imports from scanning and utility packages
from reports.report_generator import ReportGenerator
from scanner.port_scanner import COMMON_PORTS, PortScanner
from scanner.sql_scanner import SQLInjectionScanner
from scanner.ssl_checker import SSLChecker
from scanner.url_scanner import URLScanner
from scanner.xss_scanner import XSSScanner
from scanner.recon_scanner import ReconScanner
from utils.helpers import calculate_risk_score, ensure_output_dir, normalize_url, now_timestamp
from utils.logger import setup_logger

HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 8000))
OUTPUT_DIR = ensure_output_dir()
LOGGER = setup_logger()
HISTORY_FILE = Path('history_db.json')
USERS_FILE = Path('users_db.json')

def load_user_history(username: str) -> list[dict[str, Any]]:
    if not HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding='utf-8'))
        return data.get(username, [])
    except Exception:
        LOGGER.exception('Failed to load history database')
        return []

def save_scan_to_history(username: str, results: dict[str, Any]) -> None:
    if not username:
        return
    data = {}
    if HISTORY_FILE.exists():
        try:
            data = json.loads(HISTORY_FILE.read_text(encoding='utf-8'))
        except Exception:
            LOGGER.exception('Failed to read existing history database')
    if username not in data:
        data[username] = []
    
    data[username].append({
        'timestamp': results.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        'target': results.get('target_url'),
        'results': results
    })
    
    if len(data[username]) > 50:
        data[username] = data[username][-50:]
    try:
        HISTORY_FILE.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    except Exception:
        LOGGER.exception('Failed to write to history database')

def delete_user_scan_history(username: str, timestamp: str) -> bool:
    if not username or not HISTORY_FILE.exists():
        return False
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding='utf-8'))
        if username in data:
            original_len = len(data[username])
            data[username] = [item for item in data[username] if item.get('timestamp') != timestamp]
            if len(data[username]) < original_len:
                HISTORY_FILE.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
                return True
        return False
    except Exception:
        LOGGER.exception('Failed to delete history item')
        return False

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def load_users() -> dict[str, dict[str, Any]]:
    if not USERS_FILE.exists():
        default_users = {
            'admin': {
                'username': 'admin',
                'email': 'admin@securelab.local',
                'password_hash': hash_password('admin123!'),
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        }
        try:
            USERS_FILE.write_text(json.dumps(default_users, indent=2), encoding='utf-8')
        except Exception:
            pass
        return default_users
    try:
        return json.loads(USERS_FILE.read_text(encoding='utf-8'))
    except Exception:
        LOGGER.exception('Failed to load users database')
        return {}

def save_users(users: dict[str, dict[str, Any]]) -> None:
    try:
        USERS_FILE.write_text(json.dumps(users, indent=2), encoding='utf-8')
    except Exception:
        LOGGER.exception('Failed to save users database')

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

def scan_target(payload: dict[str, Any]) -> dict[str, Any]:
    import time
    start_time = time.perf_counter()
    target_url = normalize_url(str(payload.get('target', '')).strip())
    host = resolve_host(target_url)
    timeout = max(1, min(int(payload.get('timeout', 8)), 30))
    ports = parse_ports(str(payload.get('ports', '')))
    scan_options = payload.get('options', {})
    
    results: dict[str, Any] = {
        'target_url': target_url,
        'target_host': host,
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'url_scan': {},
        'port_scan': [],
        'sql_injection': [],
        'xss': [],
        'ssl': {},
        'recon_scan': {'subdomains': [], 'technologies': [], 'server_headers': {}, 'ip_addresses': []}
      }
      
    if scan_options.get('url', True):
        results['url_scan'] = URLScanner(timeout=timeout).scan(target_url)
    if scan_options.get('ports', True):
        results['port_scan'] = PortScanner(timeout=1.0).scan(host, ports)
    if scan_options.get('sql', True):
        results['sql_injection'] = SQLInjectionScanner(timeout=timeout).scan(target_url)
    if scan_options.get('xss', True):
        results['xss'] = XSSScanner(timeout=timeout).scan(target_url)
    if scan_options.get('ssl', True):
        if target_url.startswith('https://'):
            results['ssl'] = SSLChecker(timeout=timeout).check(target_url)
        else:
            results['ssl'] = {'host': host, 'valid': False, 'expired': False, 'error': 'SSL check skipped because target is not HTTPS.'}
    if scan_options.get('recon', True):
        results['recon_scan'] = ReconScanner(timeout=timeout).scan(target_url)

    risk_score, risk_severity, recommendations = calculate_risk_score(results)
    results['risk_score'] = risk_score
    results['risk_severity'] = risk_severity
    results['recommendations'] = recommendations
    
    report_name = f"web_report_{host.replace('.', '_')}_{now_timestamp()}"
    exported = ReportGenerator().save_all(results, report_name)
    results['reports'] = {report_type: f'/output/{Path(path).name}' for report_type, path in exported.items()}
    duration = time.perf_counter() - start_time
    results['scan_duration'] = f'{duration:.1f}s'
    return results

class ToolkitRequestHandler(BaseHTTPRequestHandler):
    server_version = 'VAPTSuiteWeb/2.0'

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {'/', '/index.html'}:
            index_path = Path('templates/index.html')
            if index_path.exists():
                self._send_html(index_path.read_text(encoding='utf-8'))
            else:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, 'index.html template missing')
            return
        if parsed.path == '/api/history':
            username = self.headers.get('X-Operator-User', '').strip()
            if not username:
                self._send_json({'ok': False, 'error': 'Operator user header missing'}, HTTPStatus.BAD_REQUEST)
                return
            history = load_user_history(username)
            self._send_json({'ok': True, 'history': history})
            return
        if parsed.path.startswith('/output/'):
            self._serve_output_file(parsed.path)
            return
        if parsed.path.startswith('/static/'):
            self._serve_static_file(parsed.path)
            return
        self.send_error(HTTPStatus.NOT_FOUND, 'Not found')

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in {
            '/api/scan', '/api/register', '/api/login', 
            '/api/delete_history'
        }:
            self.send_error(HTTPStatus.NOT_FOUND, 'Not found')
            return
        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            content_type = self.headers.get('Content-Type', '')
            if 'application/x-www-form-urlencoded' in content_type:
                body = self.rfile.read(content_length).decode('utf-8')
                parsed_body = parse_qs(body)
                payload = {k: v[0] for k, v in parsed_body.items()}
            else:
                payload = json.loads(self.rfile.read(content_length).decode('utf-8')) if content_length > 0 else {}
            
            if path == '/api/register':
                username = payload.get('username', '').strip()
                password = payload.get('password', '')
                import re
                if not re.match('^[a-zA-Z0-9_-]{3,20}$', username):
                    self._send_json({'ok': False, 'error': 'Username must be 3-20 characters long and contain only letters, numbers, hyphens, or underscores.'}, HTTPStatus.BAD_REQUEST)
                    return
                if len(password) < 8:
                    self._send_json({'ok': False, 'error': 'Password must be at least 8 characters long.'}, HTTPStatus.BAD_REQUEST)
                    return
                users = load_users()
                if username.lower() in {u.lower() for u in users}:
                    self._send_json({'ok': False, 'error': 'Username is already registered.'}, HTTPStatus.BAD_REQUEST)
                    return
                users[username] = {
                    'username': username,
                    'email': f'{username}@securelab.local',
                    'password_hash': hash_password(password),
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                save_users(users)
                self._send_json({'ok': True})
                return
                
            if path == '/api/login':
                login_id = payload.get('loginId', '').strip()
                password = payload.get('password', '')
                if not login_id or not password:
                    self._send_json({'ok': False, 'error': 'All fields are required'}, HTTPStatus.BAD_REQUEST)
                    return
                users = load_users()
                target_user = None
                for uinfo in users.values():
                    if uinfo['username'].lower() == login_id.lower() or uinfo['email'].lower() == login_id.lower():
                        target_user = uinfo
                        break
                if target_user and target_user['password_hash'] == hash_password(password):
                    self._send_json({'ok': True, 'username': target_user['username']})
                else:
                    self._send_json({'ok': False, 'error': 'Invalid Username or Access Key.'}, HTTPStatus.BAD_REQUEST)
                return
                
            if path == '/api/scan':
                results = scan_target(payload)
                username = self.headers.get('X-Operator-User', '').strip()
                if username:
                    save_scan_to_history(username, results)
                LOGGER.info('Web scan completed for %s', results['target_url'])
                self._send_json({'ok': True, 'results': results})
                return

            if path == '/api/delete_history':
                username = self.headers.get('X-Operator-User', '').strip()
                timestamp = payload.get('timestamp', '')
                if not username or not timestamp:
                    self._send_json({'ok': False, 'error': 'Parameters missing'}, HTTPStatus.BAD_REQUEST)
                    return
                ok = delete_user_scan_history(username, timestamp)
                self._send_json({'ok': ok})
                return
        except Exception as exc:
            LOGGER.exception('Request failed')
            self._send_json({'ok': False, 'error': str(exc)}, HTTPStatus.BAD_REQUEST)

    def log_message(self, format_string: str, *args: Any) -> None:
        LOGGER.info('web: ' + format_string, *args)

    def _send_html(self, html: str) -> None:
        data = html.encode('utf-8')
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, body: dict[str, Any], status: HTTPStatus=HTTPStatus.OK) -> None:
        data = json.dumps(body, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_output_file(self, request_path: str) -> None:
        file_name = Path(unquote(request_path)).name
        file_path = (OUTPUT_DIR / file_name).resolve()
        output_root = OUTPUT_DIR.resolve()
        if output_root not in file_path.parents and file_path != output_root:
            self.send_error(HTTPStatus.FORBIDDEN, 'Forbidden')
            return
        if not file_path.exists() or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, 'File not found')
            return
        content_type = mimetypes.guess_type(file_path.name)[0] or 'application/octet-stream'
        data = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_static_file(self, request_path: str) -> None:
        static_dir = Path('static').resolve()
        parts = request_path.lstrip('/').split('/', 1)
        if len(parts) < 2:
            self.send_error(HTTPStatus.NOT_FOUND, 'File not found')
            return
        rel_path = unquote(parts[1])
        file_path = (static_dir / rel_path).resolve()
        if static_dir not in file_path.parents and file_path != static_dir:
            self.send_error(HTTPStatus.FORBIDDEN, 'Forbidden')
            return
        if not file_path.exists() or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, 'File not found')
            return
        content_type = mimetypes.guess_type(file_path.name)[0] or 'application/octet-stream'
        data = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def main() -> None:
    ensure_output_dir()
    server_address = (HOST, PORT)
    LOGGER.info('Starting Web UI VAPT Server on %s:%d', HOST, PORT)
    httpd = ThreadingHTTPServer(server_address, ToolkitRequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info('Stopping Web server')
        httpd.server_close()

if __name__ == '__main__':
    main()