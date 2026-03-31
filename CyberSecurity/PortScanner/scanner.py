import socket
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

TARGET = "scanme.nmap.org"
MAX_THREADS = 100
TIMEOUT = 2.0

def identify_service(banner, port):
    banner_lower = banner.lower()

    if "ssh-" in banner_lower:
        return "ssh"
    if "http/" in banner_lower or "server:" in banner_lower:
        return "http"
    if "ftp" in banner_lower and banner_lower.startswith("220"):
        return "ftp"
    if "smtp" in banner_lower or "esmtp" in banner_lower:
        return "smtp"
    if "pop3" in banner_lower:
        return "pop3"
    if "imap" in banner_lower:
        return "imap"
    if "mysql" in banner_lower:
        return "mysql"

    # Considerando que os serviços estariam rodando na porta padrão
    common_ports = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        3389: "rdp"
    }

    return common_ports.get(port, "desconhecido")

def grab_banner(host, port, timeout):
    """Tenta capturar banner com conexão separada"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            try:
                data = s.recv(1024)
                if data:
                    return data.decode(errors="ignore").strip()
            except socket.timeout:
                pass

    except Exception:
        return ""

    return ""

def http_probe(host, port, timeout):
    """Tenta identificar serviço HTTP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode())

            data = s.recv(1024)
            if data:
                return data.decode(errors="ignore").split("\r\n")[0]

    except Exception:
        return ""

    return ""

def scan(host, port, timeout):
    state = "closed"
    banner = ""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))

        if result == 0:
            state = "open"
            banner = grab_banner(host, port, timeout)

            if not banner:
                banner = http_probe(host, port, timeout)
            if not banner:
                banner = "No banner"

            service = identify_service(banner, port)

            return (port, state, service, banner)

        elif result == errno.ECONNREFUSED:
            state = "closed"
        elif result in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            state = "filtered"
        else:
            state = f"unknown ({result})"

        return (port, state, "", "")

    except Exception as e:
        return (port, "error", "", str(e))

def print_header():
    print(f"\n{'='*95}")
    print(f"SCAN | Alvo: {TARGET}")
    print(f"Horário: {datetime.now().strftime('%H:%M:%S')} | Timeout: {TIMEOUT}s")
    print(f"{'='*95}\n")
    print(f"{'PORTA':<8} | {'ESTADO':<8} | {'SERVIÇO':<16} | {'BANNER/INFO'}")
    print(f"{'-'*8:<8} | {'-'*8:<8} | {'-'*16:<16} | {'-'*50}")

if __name__ == "__main__":
    start_time = datetime.now()
    print_header()

    results = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(scan, TARGET, port, TIMEOUT)
            for port in range(1, 1025)
        ]

        for future in as_completed(futures):
            try:
                port, state, service, banner = future.result()

                if state == "open":
                    results.append((port, state, service, banner))
                    print(f"{port:<8} | {state:<8} | {service:<16} | {banner[:50]}")

            except Exception:
                pass

    results.sort(key=lambda x: x[0])

    duration = datetime.now() - start_time
    print(f"\n{'='*95}")
    print(f"Finalizado em {duration.total_seconds():.2f}s")
    print(f"Portas abertas: {len(results)}")
    print(f"{'='*95}")