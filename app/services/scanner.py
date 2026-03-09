import httpx
import ssl
import socket
from urllib.parse import urlparse


def scan_headers(url):

    r = httpx.get(url)

    headers = r.headers

    score = 100

    missing = []

    required = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options"
    ]

    for h in required:
        if h not in headers:
            missing.append(h)
            score -= 10

    return score, missing


def check_tls(url):

    hostname = urlparse(url).hostname

    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443)) as sock:

        with context.wrap_socket(sock, server_hostname=hostname) as s:

            return s.version()


def run_scan(domain):

    if not domain.startswith("http"):
        domain = "https://" + domain

    headers_score, missing = scan_headers(domain)

    tls = check_tls(domain)

    findings = ",".join(missing)

    return {
        "headers_score": headers_score,
        "tls": tls,
        "findings": findings
    }