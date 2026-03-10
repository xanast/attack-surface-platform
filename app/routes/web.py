from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.db.database import SessionLocal
from app.models.target import Target
from app.models.scan import Scan
from app.services.scanner import run_scan
from app.services.reporting import build_scan_json, build_scan_html


router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def split_findings(findings_text: str):
    if not findings_text:
        return []
    return [item.strip() for item in findings_text.split("|") if item.strip()]


def classify_finding(finding: str):
    text = (finding or "").strip()
    lower = text.lower()

    severity = "Low"
    category = "General"
    title = "Security Finding"
    detail = text

    if "missing security header:" in lower:
        severity = "Medium"
        category = "Headers"
        header_name = text.split(":", 1)[1].strip() if ":" in text else text
        title = "Missing Security Header"
        detail = header_name

    elif "potentially sensitive open ports:" in lower:
        severity = "High"
        category = "Ports"
        ports = text.split(":", 1)[1].strip() if ":" in text else text
        title = "Sensitive Open Ports Exposed"
        detail = ports

    elif "outdated tls version detected:" in lower:
        severity = "High"
        category = "TLS"
        tls_value = text.split(":", 1)[1].strip() if ":" in text else text
        title = "Outdated TLS Version"
        detail = tls_value

    elif "tls handshake unavailable or failed" in lower:
        severity = "High"
        category = "TLS"
        title = "TLS Handshake Failed"
        detail = "The platform could not complete a secure TLS handshake."

    elif "tls certificate appears expired" in lower:
        severity = "High"
        category = "TLS"
        title = "Expired TLS Certificate"
        detail = "The certificate appears to be expired."

    elif "tls certificate expires soon" in lower:
        severity = "Medium"
        category = "TLS"
        title = "TLS Certificate Expiring Soon"
        detail = text

    elif "discovered subdomains:" in lower:
        severity = "Info"
        category = "Recon"
        title = "Subdomains Discovered"
        detail = text.split(":", 1)[1].strip() if ":" in text else text

    elif "detected technologies:" in lower:
        severity = "Info"
        category = "Recon"
        title = "Technologies Detected"
        detail = text.split(":", 1)[1].strip() if ":" in text else text

    elif "application returned http status" in lower:
        severity = "Medium"
        category = "Application"
        title = "Application Returned Error Status"
        detail = text

    elif "no major issues detected during this scan" in lower:
        severity = "Low"
        category = "Summary"
        title = "No Major Issues Detected"
        detail = "The scan did not identify any major issues."

    return {
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "raw": text,
    }


def build_structured_findings(findings_list):
    return [classify_finding(item) for item in findings_list if item.strip()]


def build_scan_comparison(scans):
    if len(scans) < 2:
        return None

    latest_scan = scans[0]
    previous_scan = scans[1]

    latest_findings = split_findings(latest_scan.findings)
    previous_findings = split_findings(previous_scan.findings)

    latest_set = set(latest_findings)
    previous_set = set(previous_findings)

    new_findings = sorted(list(latest_set - previous_set))
    resolved_findings = sorted(list(previous_set - latest_set))
    persistent_findings = sorted(list(latest_set & previous_set))

    latest_score = latest_scan.risk_score if latest_scan.risk_score is not None else 0
    previous_score = previous_scan.risk_score if previous_scan.risk_score is not None else 0
    score_delta = latest_score - previous_score

    if score_delta < 0:
        score_direction = "improved"
    elif score_delta > 0:
        score_direction = "worsened"
    else:
        score_direction = "unchanged"

    return {
        "latest_scan": latest_scan,
        "previous_scan": previous_scan,
        "latest_score": latest_score,
        "previous_score": previous_score,
        "score_delta": score_delta,
        "score_direction": score_direction,
        "new_findings": build_structured_findings(new_findings),
        "resolved_findings": build_structured_findings(resolved_findings),
        "persistent_findings": build_structured_findings(persistent_findings),
    }


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def calculate_next_run(scan_frequency: str):
    now = utc_now()

    if scan_frequency == "daily":
        return now + timedelta(days=1)
    if scan_frequency == "weekly":
        return now + timedelta(weeks=1)
    if scan_frequency == "monthly":
        return now + timedelta(days=30)

    return None


def create_scan_for_target(db, target: Target):
    result = run_scan(target.domain)

    scan = Scan(
        target_id=target.id,
        headers_score=result["headers_score"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        tls_version=result["tls"],
        findings=" | ".join(result["findings"]),
        ports=",".join(map(str, result["ports"])),
        tech=",".join(result["tech"]),
        subdomains=",".join(result["subdomains"]),
    )

    target.last_run_at = utc_now()
    target.next_run_at = calculate_next_run(target.scan_frequency)

    db.add(scan)
    return scan


def build_dashboard_data(db, search: str = "", risk: str = "all"):
    targets = db.query(Target).all()
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()

    total_targets = len(targets)
    total_scans = len(scans)
    high_risk_scans = len([s for s in scans if s.risk_level == "High"])
    medium_risk_scans = len([s for s in scans if s.risk_level == "Medium"])
    low_risk_scans = len([s for s in scans if s.risk_level == "Low"])

    avg_risk_score = 0
    scored_scans = [s.risk_score for s in scans if s.risk_score is not None]
    if scored_scans:
        avg_risk_score = round(sum(scored_scans) / len(scored_scans))

    highest_risk_scan = None
    if scans:
        highest_risk_scan = sorted(
            scans,
            key=lambda s: (s.risk_score if s.risk_score is not None else 999)
        )[0]

    now = utc_now()
    scheduled_targets = len([t for t in targets if t.scan_frequency != "manual"])
    due_targets = len(
        [
            t for t in targets
            if t.scan_frequency != "manual"
            and t.next_run_at is not None
            and t.next_run_at <= now
        ]
    )

    search_lower = search.strip().lower()

    target_cards = []
    risk_trends = []
    avg_score_per_target = []

    for target in targets:
        target_scans = (
            db.query(Scan)
            .filter(Scan.target_id == target.id)
            .order_by(Scan.created_at.desc())
            .all()
        )

        latest = target_scans[0] if target_scans else None
        recent_scores = [scan.risk_score for scan in target_scans[:5] if scan.risk_score is not None]

        trend_direction = "No Data"
        if len(recent_scores) >= 2:
            if recent_scores[0] < recent_scores[-1]:
                trend_direction = "Improving"
            elif recent_scores[0] > recent_scores[-1]:
                trend_direction = "Worsening"
            else:
                trend_direction = "Stable"
        elif len(recent_scores) == 1:
            trend_direction = "Single Scan"

        matches_search = True
        if search_lower:
            matches_search = (
                search_lower in target.domain.lower()
                or search_lower in (target.description or "").lower()
            )

        matches_risk = True
        if risk != "all":
            if latest:
                matches_risk = latest.risk_level.lower() == risk.lower()
            else:
                matches_risk = False

        is_due = (
            target.scan_frequency != "manual"
            and target.next_run_at is not None
            and target.next_run_at <= now
        )

        if matches_search and matches_risk:
            target_cards.append(
                {
                    "id": target.id,
                    "domain": target.domain,
                    "description": target.description,
                    "latest_scan": latest,
                    "scan_frequency": target.scan_frequency,
                    "last_run_at": target.last_run_at,
                    "next_run_at": target.next_run_at,
                    "is_due": is_due,
                }
            )

            risk_trends.append(
                {
                    "id": target.id,
                    "domain": target.domain,
                    "latest_scan": latest,
                    "recent_scores": recent_scores,
                    "trend_direction": trend_direction,
                }
            )

        target_scored = [scan.risk_score for scan in target_scans if scan.risk_score is not None]
        if target_scored:
            avg_score_per_target.append(
                {
                    "domain": target.domain,
                    "avg_score": round(sum(target_scored) / len(target_scored)),
                }
            )

    recent_scans = []
    for scan in scans:
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        target_domain = target.domain if target else "Unknown"

        matches_search = True
        if search_lower:
            matches_search = search_lower in target_domain.lower()

        matches_risk = True
        if risk != "all":
            matches_risk = (scan.risk_level or "").lower() == risk.lower()

        if matches_search and matches_risk:
            findings_list = split_findings(scan.findings)

            recent_scans.append(
                {
                    "scan": scan,
                    "target_domain": target_domain,
                    "findings_list": findings_list,
                    "structured_findings": build_structured_findings(findings_list),
                }
            )

    highest_risk_target_domain = None
    if highest_risk_scan:
        target = db.query(Target).filter(Target.id == highest_risk_scan.target_id).first()
        highest_risk_target_domain = target.domain if target else "Unknown"

    chart_data = {
        "risk_distribution": {
            "low": low_risk_scans,
            "medium": medium_risk_scans,
            "high": high_risk_scans,
        },
        "avg_score_per_target": avg_score_per_target,
    }

    return {
        "targets": targets,
        "target_cards": target_cards,
        "recent_scans": recent_scans[:8],
        "risk_trends": risk_trends,
        "chart_data": chart_data,
        "stats": {
            "total_targets": total_targets,
            "total_scans": total_scans,
            "high_risk_scans": high_risk_scans,
            "medium_risk_scans": medium_risk_scans,
            "low_risk_scans": low_risk_scans,
            "avg_risk_score": avg_risk_score,
            "highest_risk_target_domain": highest_risk_target_domain,
            "highest_risk_score": highest_risk_scan.risk_score if highest_risk_scan else None,
            "scheduled_targets": scheduled_targets,
            "due_targets": due_targets,
        },
    }


@router.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    search: str = Query(default=""),
    risk: str = Query(default="all"),
):
    db = SessionLocal()
    dashboard = build_dashboard_data(db, search=search, risk=risk)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "targets": dashboard["targets"],
            "target_cards": dashboard["target_cards"],
            "recent_scans": dashboard["recent_scans"],
            "risk_trends": dashboard["risk_trends"],
            "chart_data": dashboard["chart_data"],
            "stats": dashboard["stats"],
            "search": search,
            "risk": risk,
        },
    )


@router.get("/targets/{target_id}", response_class=HTMLResponse)
def target_details(request: Request, target_id: int):
    db = SessionLocal()

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return RedirectResponse("/", status_code=303)

    scans = (
        db.query(Scan)
        .filter(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
        .all()
    )

    latest_scan = scans[0] if scans else None
    latest_findings = split_findings(latest_scan.findings) if latest_scan else []
    structured_latest_findings = build_structured_findings(latest_findings)
    scan_comparison = build_scan_comparison(scans)

    history_items = []
    for scan in scans:
        scan_findings = split_findings(scan.findings)

        history_items.append(
            {
                "scan": scan,
                "findings_list": scan_findings,
                "structured_findings": build_structured_findings(scan_findings),
            }
        )

    risk_scores = []
    risk_dates = []

    for scan in reversed(scans):
        if scan.risk_score is not None:
            risk_scores.append(scan.risk_score)
            risk_dates.append(scan.created_at.strftime("%m-%d"))

    return templates.TemplateResponse(
        "target_detail.html",
        {
            "request": request,
            "target": target,
            "latest_scan": latest_scan,
            "latest_findings": latest_findings,
            "structured_latest_findings": structured_latest_findings,
            "history_items": history_items,
            "risk_scores": risk_scores,
            "risk_dates": risk_dates,
            "scan_comparison": scan_comparison,
        },
    )


@router.get("/targets/{target_id}/export/json")
def export_latest_scan_json(target_id: int):
    db = SessionLocal()

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return RedirectResponse("/", status_code=303)

    latest_scan = (
        db.query(Scan)
        .filter(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
        .first()
    )

    if not latest_scan:
        return RedirectResponse(f"/targets/{target_id}", status_code=303)

    content = build_scan_json(target, latest_scan)

    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{target.domain}_latest_scan.json"'
        },
    )


@router.get("/targets/{target_id}/export/html")
def export_latest_scan_html(target_id: int):
    db = SessionLocal()

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return RedirectResponse("/", status_code=303)

    latest_scan = (
        db.query(Scan)
        .filter(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
        .first()
    )

    if not latest_scan:
        return RedirectResponse(f"/targets/{target_id}", status_code=303)

    content = build_scan_html(target, latest_scan)

    return Response(
        content=content,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{target.domain}_latest_scan.html"'
        },
    )


@router.post("/targets/add")
def add_target(
    domain: str = Form(...),
    description: str = Form(""),
    scan_frequency: str = Form("manual"),
):
    db = SessionLocal()

    clean_domain = domain.strip()
    existing = db.query(Target).filter(Target.domain == clean_domain).first()

    if not existing:
        target = Target(
            domain=clean_domain,
            description=description.strip(),
            scan_frequency=scan_frequency,
            next_run_at=calculate_next_run(scan_frequency),
        )
        db.add(target)
        db.commit()

    return RedirectResponse("/", status_code=303)


@router.post("/targets/run-due")
def run_due_scans():
    db = SessionLocal()
    now = utc_now()

    due_targets = (
        db.query(Target)
        .filter(Target.scan_frequency != "manual")
        .filter(Target.next_run_at.isnot(None))
        .all()
    )

    for target in due_targets:
        if target.next_run_at and target.next_run_at <= now:
            create_scan_for_target(db, target)

    db.commit()
    return RedirectResponse("/", status_code=303)


@router.post("/targets/{target_id}/delete")
def delete_target(target_id: int):
    db = SessionLocal()

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return RedirectResponse("/", status_code=303)

    db.query(Scan).filter(Scan.target_id == target_id).delete()
    db.delete(target)
    db.commit()

    return RedirectResponse("/", status_code=303)


@router.post("/scan/{target_id}")
def run_target_scan(target_id: int):
    db = SessionLocal()

    target = db.query(Target).get(target_id)
    if not target:
        return RedirectResponse("/", status_code=303)

    create_scan_for_target(db, target)
    db.commit()

    return RedirectResponse(f"/targets/{target_id}", status_code=303)