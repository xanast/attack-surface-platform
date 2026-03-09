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


def build_dashboard_data(db, search: str = "", risk: str = "all"):
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

    highest_risk_scan = None
    if scans:
        highest_risk_scan = sorted(
            scans,
            key=lambda s: (s.risk_score if s.risk_score is not None else 999)
        )[0]

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

        if matches_search and matches_risk:
            target_cards.append(
                {
                    "id": target.id,
                    "domain": target.domain,
                    "description": target.description,
                    "latest_scan": latest,
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
                    "avg_score": round(sum(target_scored) / len(target_scored))
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
            recent_scans.append(
                {
                    "scan": scan,
                    "target_domain": target_domain,
                    "findings_list": split_findings(scan.findings),
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