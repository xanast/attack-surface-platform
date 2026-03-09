import socket
import httpx

COMMON_PORTS = [21,22,25,53,80,110,143,443,3306,8080]

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "dev",
    "staging",
    "mail",
    "admin",
    "test"
]


def scan_ports(host):

    open_ports = []

    for port in COMMON_PORTS:

        try:
            sock = socket.socket()
            sock.settimeout(0.5)

            sock.connect((host, port))

            open_ports.append(port)

            sock.close()

        except:
            pass

    return open_ports


def detect_technology(url):

    try:

        r = httpx.get(url, timeout=5)

        headers = r.headers

        tech = []

        if "server" in headers:
            tech.append(headers["server"])

        if "x-powered-by" in headers:
            tech.append(headers["x-powered-by"])

        return tech

    except:

        return []


def find_subdomains(domain):

    found = []

    for sub in COMMON_SUBDOMAINS:

        host = f"{sub}.{domain}"

        try:

            socket.gethostbyname(host)

            found.append(host)

        except:

            pass

    return found