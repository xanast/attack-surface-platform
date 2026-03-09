import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from app.services.recon import scan_ports, detect_technology, find_subdomains


REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


def normalize_domain(domain: str):
    domain = domain.strip()

    if not domain.startswith(("http://", "https://")):
        domain = f"https://{domain}"

    parsed = urlparse(domain)
    hostname = parsed.hostname or domain.replace("https://", "").replace("http://", "")
    hostname = hostname.strip("/")

    normalized_url = f"https://{hostname}"

    return normalized_url, hostname


def scan_headers(url: str):
    try:
        response = httpx.get(
            url,
            timeout=10,
            follow_redirects=True,
            headers={"User-Agent": "AttackSurfacePlatform/1.0"},
        )

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
            "missing": missing,
            "status_code": response.status_code,
        }

    except Exception:
        return {
            "present": [],
            "missing": REQUIRED_HEADERS.copy(),
            "status_code": None,
        }


def check_tls_details(hostname: str):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                tls_version = secure_sock.version() or "Unknown"

                expiry_days = None
                if cert and "notAfter" in cert:
                    not_after = cert["notAfter"]
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    expiry_days = (expiry_date - now).days

                return {
                    "tls_version": tls_version,
                    "cert_expiry_days": expiry_days,
                }

    except Exception:
        return {
            "tls_version": "Unavailable",
            "cert_expiry_days": None,
        }


def build_findings(headers_result, open_ports, tech, subdomains, tls_details):
    findings = []

    for header in headers_result["missing"]:
        findings.append(f"Missing security header: {header}")

    risky_port_keywords = ["21", "25", "3306", "8080"]
    exposed_risky_ports = [port for port in open_ports if any(keyword in port for keyword in risky_port_keywords)]

    if exposed_risky_ports:
        findings.append(f"Potentially sensitive open ports: {', '.join(exposed_risky_ports)}")

    tls_version = tls_details["tls_version"]
    cert_expiry_days = tls_details["cert_expiry_days"]

    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
        findings.append(f"Outdated TLS version detected: {tls_version}")

    if tls_version == "Unavailable":
        findings.append("TLS handshake unavailable or failed")

    if cert_expiry_days is not None:
        if cert_expiry_days < 0:
            findings.append("TLS certificate appears expired")
        elif cert_expiry_days <= 30:
            findings.append(f"TLS certificate expires soon ({cert_expiry_days} days remaining)")

    if subdomains:
        findings.append(f"Discovered subdomains: {', '.join(subdomains)}")

    if tech:
        findings.append(f"Detected technologies: {', '.join(tech)}")

    if headers_result["status_code"] and headers_result["status_code"] >= 400:
        findings.append(f"Application returned HTTP status {headers_result['status_code']}")

    if not findings:
        findings.append("No major issues detected during this scan")

    return findings


def calculate_risk(headers_result, open_ports, tls_details):
    score = 100

    score -= len(headers_result["missing"]) * 8

    port_penalties = {
        "21": 8,
        "25": 6,
        "3306": 10,
        "8080": 4,
        "22": 3,
    }

    for port_entry in open_ports:
        for port_number, penalty in port_penalties.items():
            if port_number in port_entry:
                score -= penalty

    tls_version = tls_details["tls_version"]
    cert_expiry_days = tls_details["cert_expiry_days"]

    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
        score -= 15
    elif tls_version == "Unavailable":
        score -= 10

    if cert_expiry_days is not None:
        if cert_expiry_days < 0:
            score -= 20
        elif cert_expiry_days <= 30:
            score -= 8

    score = max(score, 0)

    if score >= 85:
        level = "Low"
    elif score >= 60:
        level = "Medium"
    else:
        level = "High"

    return score, level


def run_scan(domain: str):
    normalized_url, hostname = normalize_domain(domain)

    headers_result = scan_headers(normalized_url)
    tls_details = check_tls_details(hostname)
    open_ports = scan_ports(hostname)
    technologies = detect_technology(normalized_url)
    subdomains = find_subdomains(hostname)

    risk_score, risk_level = calculate_risk(
        headers_result=headers_result,
        open_ports=open_ports,
        tls_details=tls_details,
    )

    findings = build_findings(
        headers_result=headers_result,
        open_ports=open_ports,
        tech=technologies,
        subdomains=subdomains,
        tls_details=tls_details,
    )

    return {
        "headers_score": 100 - (len(headers_result["missing"]) * 8),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "tls": tls_details["tls_version"],
        "findings": findings,
        "ports": open_ports,
        "tech": technologies,
        "subdomains": subdomains,
        "present_headers": headers_result["present"],
        "missing_headers": headers_result["missing"],
    }