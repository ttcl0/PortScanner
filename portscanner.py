import socket
import ipaddress
import threading
import sys
import os
import msvcrt
from queue import Queue

LIGHT_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 512,
    513, 514, 515, 520, 587, 631, 636, 873, 989, 990, 993, 995, 1080, 1194,
    1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3260, 3306, 3389, 3690,
    4444, 4899, 5000, 5060, 5061, 5432, 5555, 5900, 5901, 5985, 5986, 6379,
    6443, 6667, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    9418, 9443, 10000, 11211, 15672, 18080, 27017, 27018, 27019,
]

TARGETED_PORTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targeted_ports.txt")

open_ports = []
lock = threading.Lock()


def validate_ip(ip_str: str):
    addr = ipaddress.ip_address(ip_str)
    return str(addr), addr.version


def scan_port(ip: str, port: int, family: int, timeout: float):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                with lock:
                    open_ports.append((port, service))
                    print(f"  \033[92m[OPEN]\033[0m  Port {port:<6}  {service}")
    except (socket.error, OSError):
        pass


def worker(ip: str, family: int, queue: Queue, timeout: float):
    while True:
        try:
            port = queue.get_nowait()
        except Exception:
            break
        scan_port(ip, port, family, timeout)
        queue.task_done()


def scan(ip: str, version: int, ports: list, timeout: float, threads: int):
    family = socket.AF_INET if version == 4 else socket.AF_INET6
    queue = Queue()
    for port in ports:
        queue.put(port)

    thread_list = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker, args=(ip, family, queue, timeout), daemon=True)
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    return sorted(open_ports)


def load_targeted_ports() -> list:
    if not os.path.exists(TARGETED_PORTS_FILE):
        with open(TARGETED_PORTS_FILE, "w") as f:
            f.write("# Enter one port number per line. Lines starting with # are ignored.\n")
            f.write("# Example:\n# 80\n# 443\n# 8080\n")
        print(f"\n  Template created: {TARGETED_PORTS_FILE}")
        print("  Add your ports to that file and re-run the targeted scan.")
        return []

    ports = []
    with open(TARGETED_PORTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                p = int(line)
                if 1 <= p <= 65535:
                    ports.append(p)
                else:
                    print(f"  \033[93m[WARN]\033[0m  Ignoring out-of-range port: {p}")
            except ValueError:
                print(f"  \033[93m[WARN]\033[0m  Ignoring invalid value: '{line}'")

    return list(dict.fromkeys(ports))


def choose_scan_mode():
    print("\nSelect scan mode:")
    print("  [1]  Light scan    — common ports (~100 ports, very fast)")
    print("  [2]  Deep scan     — all ports 1-65535 (thorough, slower)")
    print("  [3]  Targeted scan — ports listed in targeted_ports.txt")

    while True:
        choice = input("\nEnter choice (1/2/3): ").strip()
        if choice in ("1", "2", "3"):
            return choice
        print("  Invalid choice. Please enter 1, 2, or 3.")


def main():
    print("=" * 52)
    print("            IP Port Scanner")
    print("            Made by TTCL")
    print("            https://github.com/ttcl0")
    print("=" * 52)

    while True:
        raw = input("\nEnter an IPv4 or IPv6 address to scan: ").strip()
        if not raw:
            print("  No input provided. Please try again.")
            continue
        try:
            ip, version = validate_ip(raw)
            break
        except ValueError:
            print(f"  '{raw}' is not a valid IPv4 or IPv6 address. Please try again.")

    mode = choose_scan_mode()

    if mode == "1":
        ports   = LIGHT_PORTS
        timeout = 0.5
        threads = 300
        label   = f"{len(ports)} common ports (light scan)"
    elif mode == "2":
        ports   = list(range(1, 65536))
        timeout = 0.5
        threads = 1000
        label   = "ports 1-65535 (deep scan)"
    else:
        ports = load_targeted_ports()
        if not ports:
            sys.exit(0)
        timeout = 0.5
        threads = 300
        label   = f"{len(ports)} targeted port(s)"

    print(f"\nScanning {ip} (IPv{version}) — {label} ...")
    print("Open ports will appear below as they are found.\n")

    results = scan(ip, version, ports, timeout, threads)

    print("\n" + "-" * 52)
    if results:
        print(f"Scan complete. {len(results)} open port(s) found:\n")
        print(f"  {'PORT':<10} {'SERVICE'}")
        print(f"  {'-'*8}  {'-'*20}")
        for port, service in results:
            print(f"  {port:<10} {service}")
    else:
        print("Scan complete. No open ports found.")
    print("-" * 52)
    print("\nPress any key to exit...")
    msvcrt.getch()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        print("\nPress any key to exit...")
        msvcrt.getch()
        sys.exit(0)
