from fastapi import APIRouter, Request, Form
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


def build_dashboard_data(db):
    targets = db.query(Target).all()
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()

    latest_scan_by_target = {}
    for scan in scans:
        if scan.target_id not in latest_scan_by_target:
            latest_scan_by_target[scan.target_id] = scan

    total_targets = len(targets)
    total_scans = len(scans)
    high_risk_scans = len([s for s in scans if s.risk_level == "High"])
    medium_risk_scans = len([s for s in scans if s.risk_level == "Medium"])
    low_risk_scans = len([s for s in scans if s.risk_level == "Low"])

    avg_risk_score = 0
    scored_scans = [s.risk_score for s in scans if s.risk_score is not None]
    if scored_scans:
        avg_risk_score = round(sum(scored_scans) / len(scored_scans))

    target_cards = []
    for target in targets:
        latest = latest_scan_by_target.get(target.id)

        target_cards.append(
            {
                "id": target.id,
                "domain": target.domain,
                "description": target.description,
                "latest_scan": latest,
            }
        )

    recent_scans = []
    for scan in scans[:8]:
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        recent_scans.append(
            {
                "scan": scan,
                "target_domain": target.domain if target else "Unknown",
                "findings_list": split_findings(scan.findings),
            }
        )

    return {
        "targets": targets,
        "target_cards": target_cards,
        "recent_scans": recent_scans,
        "stats": {
            "total_targets": total_targets,
            "total_scans": total_scans,
            "high_risk_scans": high_risk_scans,
            "medium_risk_scans": medium_risk_scans,
            "low_risk_scans": low_risk_scans,
            "avg_risk_score": avg_risk_score,
        },
    }


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    db = SessionLocal()
    dashboard = build_dashboard_data(db)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "targets": dashboard["targets"],
            "target_cards": dashboard["target_cards"],
            "recent_scans": dashboard["recent_scans"],
            "stats": dashboard["stats"],
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

    history_items = []
    for scan in scans:
        history_items.append(
            {
                "scan": scan,
                "findings_list": split_findings(scan.findings),
            }
        )

    return templates.TemplateResponse(
        "target_detail.html",
        {
            "request": request,
            "target": target,
            "latest_scan": latest_scan,
            "latest_findings": latest_findings,
            "history_items": history_items,
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
def add_target(domain: str = Form(...), description: str = Form("")):
    db = SessionLocal()

    clean_domain = domain.strip()
    existing = db.query(Target).filter(Target.domain == clean_domain).first()

    if not existing:
        target = Target(domain=clean_domain, description=description.strip())
        db.add(target)
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

    result = run_scan(target.domain)

    scan = Scan(
        target_id=target_id,
        headers_score=result["headers_score"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        tls_version=result["tls"],
        findings=" | ".join(result["findings"]),
        ports=",".join(map(str, result["ports"])),
        tech=",".join(result["tech"]),
        subdomains=",".join(result["subdomains"]),
    )

    db.add(scan)
    db.commit()

    return RedirectResponse(f"/targets/{target_id}", status_code=303)