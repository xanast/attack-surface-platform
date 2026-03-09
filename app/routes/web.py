from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.db.database import SessionLocal
from app.models.target import Target
from app.models.scan import Scan
from app.services.scanner import run_scan


router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    db = SessionLocal()

    targets = db.query(Target).all()
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "targets": targets,
            "scans": scans
        }
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

    return templates.TemplateResponse(
        "target_detail.html",
        {
            "request": request,
            "target": target,
            "latest_scan": latest_scan,
            "scans": scans
        }
    )


@router.post("/targets/add")
def add_target(domain: str = Form(...), description: str = Form("")):
    db = SessionLocal()

    existing = db.query(Target).filter(Target.domain == domain).first()
    if not existing:
        target = Target(domain=domain, description=description)
        db.add(target)
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
        subdomains=",".join(result["subdomains"])
    )

    db.add(scan)
    db.commit()

    return RedirectResponse(f"/targets/{target_id}", status_code=303)