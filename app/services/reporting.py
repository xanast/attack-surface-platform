import json
from datetime import datetime


def build_scan_payload(target, scan):
    return {
        "target": {
            "id": target.id,
            "domain": target.domain,
            "description": target.description,
        },
        "scan": {
            "id": scan.id,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "headers_score": scan.headers_score,
            "tls_version": scan.tls_version,
            "findings": scan.findings,
            "ports": scan.ports,
            "technologies": scan.tech,
            "subdomains": scan.subdomains,
            "created_at": str(scan.created_at),
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def build_scan_json(target, scan):
    payload = build_scan_payload(target, scan)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_scan_html(target, scan):
    created_at = str(scan.created_at) if scan.created_at else "Unknown"

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Report - {target.domain}</title>
    <style>
        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #05070d, #0b1120);
            color: #f5f7fa;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .card {{
            background: rgba(20, 25, 36, 0.95);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 18px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 12px 30px rgba(0,0,0,0.28);
        }}
        h1, h2 {{
            margin-top: 0;
        }}
        .row {{
            display: grid;
            grid-template-columns: 180px 1fr;
            gap: 14px;
            padding: 10px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .row:last-child {{
            border-bottom: none;
        }}
        .label {{
            color: #93a0b5;
            font-weight: 700;
        }}
        .value {{
            word-break: break-word;
        }}
        .pill {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 999px;
            font-weight: 800;
        }}
        .low {{
            background: rgba(34, 197, 94, 0.18);
            color: #86efac;
        }}
        .medium {{
            background: rgba(250, 204, 21, 0.16);
            color: #fde68a;
        }}
        .high {{
            background: rgba(239, 68, 68, 0.16);
            color: #fca5a5;
        }}
        @media (max-width: 700px) {{
            .row {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Attack Surface Scan Report</h1>
            <p>Generated report for authorized target analysis.</p>
        </div>

        <div class="card">
            <h2>Target Information</h2>
            <div class="row">
                <div class="label">Domain</div>
                <div class="value">{target.domain}</div>
            </div>
            <div class="row">
                <div class="label">Description</div>
                <div class="value">{target.description or "No description"}</div>
            </div>
            <div class="row">
                <div class="label">Target ID</div>
                <div class="value">{target.id}</div>
            </div>
        </div>

        <div class="card">
            <h2>Latest Scan Summary</h2>
            <div class="row">
                <div class="label">Risk Score</div>
                <div class="value">{scan.risk_score}/100</div>
            </div>
            <div class="row">
                <div class="label">Risk Level</div>
                <div class="value">
                    <span class="pill {scan.risk_level.lower()}">{scan.risk_level}</span>
                </div>
            </div>
            <div class="row">
                <div class="label">Headers Score</div>
                <div class="value">{scan.headers_score}</div>
            </div>
            <div class="row">
                <div class="label">TLS Version</div>
                <div class="value">{scan.tls_version}</div>
            </div>
            <div class="row">
                <div class="label">Findings</div>
                <div class="value">{scan.findings or "None"}</div>
            </div>
            <div class="row">
                <div class="label">Open Ports</div>
                <div class="value">{scan.ports or "None"}</div>
            </div>
            <div class="row">
                <div class="label">Technologies</div>
                <div class="value">{scan.tech or "Unknown"}</div>
            </div>
            <div class="row">
                <div class="label">Subdomains</div>
                <div class="value">{scan.subdomains or "None found"}</div>
            </div>
            <div class="row">
                <div class="label">Created At</div>
                <div class="value">{created_at}</div>
            </div>
        </div>
    </div>
</body>
</html>
""".strip()