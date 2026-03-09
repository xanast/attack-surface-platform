import httpx
import ssl
import socket
from urllib.parse import urlparse

from app.services.recon import scan_ports, detect_technology, find_subdomains


REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy"
]


def scan_headers(url: str):
    response = httpx.get(url, timeout=10)
    headers = response.headers

    present = []
    missing = []

    for header in REQUIRED_HEADERS:
        if header in headers:
            present.append(header)
        else:
            missing.append(header)

    return {
        "present": present,
        "missing": missing
    }


def check_tls(url: str):
    hostname = urlparse(url).hostname

    if not hostname:
        return "Unknown"

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                return secure_sock.version() or "Unknown"
    except Exception:
        return "Unavailable"


def build_findings(headers_result: dict, open_ports: list[int], tech: list[str], subdomains: list[str], tls_version: str):
    findings = []

    for header in headers_result["missing"]:
        findings.append(f"Missing security header: {header}")

    risky_ports = [21, 25, 3306, 8080]
    exposed_risky_ports = [str(port) for port in open_ports if port in risky_ports]

    if exposed_risky_ports:
        findings.append(f"Potentially sensitive open ports: {', '.join(exposed_risky_ports)}")

    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
        findings.append(f"Outdated TLS version detected: {tls_version}")

    if subdomains:
        findings.append(f"Discovered subdomains: {', '.join(subdomains)}")

    if tech:
        findings.append(f"Detected technologies: {', '.join(tech)}")

    if not findings:
        findings.append("No major issues detected during this scan")

    return findings


def calculate_risk(headers_result: dict, open_ports: list[int], tls_version: str):
    score = 100

    score -= len(headers_result["missing"]) * 8

    if 21 in open_ports:
        score -= 8
    if 25 in open_ports:
        score -= 6
    if 3306 in open_ports:
        score -= 10
    if 8080 in open_ports:
        score -= 4

    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
        score -= 15
    elif tls_version == "Unavailable":
        score -= 10

    score = max(score, 0)

    if score >= 85:
        level = "Low"
    elif score >= 60:
        level = "Medium"
    else:
        level = "High"

    return score, level


def run_scan(domain: str):
    if not domain.startswith("http"):
        domain = f"https://{domain}"

    clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")

    headers_result = scan_headers(domain)
    tls_version = check_tls(domain)
    open_ports = scan_ports(clean_domain)
    technologies = detect_technology(domain)
    subdomains = find_subdomains(clean_domain)

    risk_score, risk_level = calculate_risk(
        headers_result=headers_result,
        open_ports=open_ports,
        tls_version=tls_version
    )

    findings = build_findings(
        headers_result=headers_result,
        open_ports=open_ports,
        tech=technologies,
        subdomains=subdomains,
        tls_version=tls_version
    )

    return {
        "headers_score": risk_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "tls": tls_version,
        "findings": findings,
        "ports": open_ports,
        "tech": technologies,
        "subdomains": subdomains,
        "present_headers": headers_result["present"],
        "missing_headers": headers_result["missing"]
    }