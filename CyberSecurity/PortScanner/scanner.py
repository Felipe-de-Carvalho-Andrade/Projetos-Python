import socket
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))

            if result == 0:
                state = "open"
            elif result == errno.ECONNREFUSED:
                state = "closed"
            elif result in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
                state = "filtered"
            else:
                state = f"unknown ({result})"

            return (port, state)

    except Exception as e:
        return (port, f"error ({e})")


if __name__ == "__main__":
    target = "google.com"
    timeout = 1.0

    print(f"Escaneando {target}...\n")

    results = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [
            executor.submit(scan, target, port, timeout)
            for port in range(1, 1025)
        ]

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"Erro em thread: {e}")

    # Ordena resultados
    results.sort(key=lambda x: x[0])

    print(f"{'PORTA':<7} | {'ESTADO':<10}")
    print("-" * 20)

    for port, state in results:
        if state == "open":
            print(f"{port:<7} | {state}")

    print("\nScan finalizado.")