import socket
import httpx

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080]

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "dev",
    "staging",
    "mail",
    "admin",
    "test",
]


def scan_ports(host: str):
    open_ports = []

    for port in COMMON_PORTS:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            result = sock.connect_ex((host, port))

            if result == 0:
                open_ports.append(port)

        except Exception:
            pass

        finally:
            if sock:
                sock.close()

    return open_ports


def detect_technology(url: str):
    try:
        response = httpx.get(
            url,
            timeout=8,
            follow_redirects=True,
            headers={"User-Agent": "AttackSurfacePlatform/1.0"},
        )

        headers = response.headers
        tech = []

        server = headers.get("server")
        powered_by = headers.get("x-powered-by")
        via = headers.get("via")

        if server:
            tech.append(server)

        if powered_by:
            tech.append(powered_by)

        if via:
            tech.append(via)

        # remove duplicates while preserving order
        unique = []
        for item in tech:
            if item not in unique:
                unique.append(item)

        return unique

    except Exception:
        return []


def find_subdomains(domain: str):
    found = []

    for sub in COMMON_SUBDOMAINS:
        host = f"{sub}.{domain}"

        try:
            socket.gethostbyname(host)
            found.append(host)
        except Exception:
            pass

    return found