from __future__ import annotations
import socket
import threading
from dataclasses import dataclass
from queue import Queue
from typing import Any
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

@dataclass
class PortScanner:
    timeout: float = 1.0
    max_threads: int = 50

    def scan(self, host: str, ports: list[int] | None=None) -> list[dict[str, Any]]:
        selected_ports = ports or COMMON_PORTS
        queue: Queue[int] = Queue()
        results: list[dict[str, Any]] = []
        lock = threading.Lock()
        for port in sorted(set(selected_ports)):
            queue.put(port)

        def worker() -> None:
            while True:
                try:
                    port = queue.get_nowait()
                except Exception:
                    return
                row = self._scan_single_port(host, port)
                with lock:
                    results.append(row)
                queue.task_done()
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(self.max_threads, len(selected_ports)))]
        for thread in threads:
            thread.start()
        queue.join()
        return sorted(results, key=lambda item: item['port'])

    def _scan_single_port(self, host: str, port: int) -> dict[str, Any]:
        service = self._service_name(port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                status = 'Open' if sock.connect_ex((host, port)) == 0 else 'Closed'
        except socket.gaierror:
            status = 'Host resolution failed'
        except OSError as exc:
            status = f'Error: {exc}'
        return {'port': port, 'service': service, 'status': status}

    @staticmethod
    def _service_name(port: int) -> str:
        try:
            return socket.getservbyport(port, 'tcp')
        except OSError:
            return 'unknown'