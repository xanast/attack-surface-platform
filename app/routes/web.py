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
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "targets": targets,
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

    return RedirectResponse("/", status_code=303)