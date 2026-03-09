import socket
import httpx

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    8080: "http-alt",
}

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

    for port, service in COMMON_PORTS.items():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            result = sock.connect_ex((host, port))

            if result == 0:
                open_ports.append(f"{port} ({service})")

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

        # basic CDN / WAF hints
        if "cf-ray" in headers or "cloudflare" in (server or "").lower():
            tech.append("Cloudflare")

        if "x-served-by" in headers:
            tech.append("Reverse Proxy / CDN")

        unique = []
        for item in tech:
            if item and item not in unique:
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