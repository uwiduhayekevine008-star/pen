"""Authenticated API for scoped, low-impact security assessments."""
import asyncio
import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
import uvicorn

from vulnscanner.security import (
    ScopeError,
    api_token_is_valid,
    require_feature_enabled,
    validate_ports,
    validate_targets,
)

_docs_enabled = os.getenv("PEN_ENABLE_API_DOCS", "").strip().lower() in {"1", "true", "yes"}
app = FastAPI(
    title="Vulnerability Scanner API",
    description="Authenticated security assessment API",
    version="1.1.0",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

_origins = [origin.strip() for origin in os.getenv("PEN_CORS_ORIGINS", "").split(",") if origin.strip()]
for _origin in _origins:
    _parsed_origin = urlsplit(_origin)
    if (
        _origin == "*"
        or _parsed_origin.scheme not in {"http", "https"}
        or not _parsed_origin.netloc
        or _parsed_origin.username is not None
        or _parsed_origin.password is not None
        or _parsed_origin.path not in {"", "/"}
        or _parsed_origin.query
        or _parsed_origin.fragment
    ):
        raise RuntimeError("PEN_CORS_ORIGINS must contain exact HTTP(S) origins; wildcard and path entries are not allowed")
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

active_scans: Dict[str, Dict] = {}
scan_results: Dict[str, Dict] = {}
scan_tasks: Dict[str, asyncio.Task] = {}


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: List[str] = Field(min_length=1, max_length=25)
    ports: Optional[List[int]] = Field(default=None, max_length=100)
    scan_type: Literal["safe", "active"] = "safe"
    run_exploits: bool = False


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    targets_completed: int
    total_targets: int
    vulnerabilities_found: int
    start_time: str
    eta: Optional[str] = None


async def require_api_token(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    if not os.getenv("PEN_API_TOKEN"):
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    if not api_token_is_valid(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_scan_summary(scan_id: str, data: Dict) -> Dict:
    return {
        "scan_id": scan_id,
        "status": data.get("status", "unknown"),
        "progress": data.get("progress", 0),
        "targets_completed": data.get("targets_completed", 0),
        "total_targets": data.get("total_targets", 0),
        "vulnerabilities_found": data.get("vulnerabilities_found", 0),
        "start_time": data.get("start_time"),
        "targets": data.get("targets", []),
    }

def _prune_completed_scans(max_finished: int = 100) -> None:
    """Keep recent finished scans only; prevent unbounded in-memory growth."""
    finished = [
        scan_id for scan_id, data in active_scans.items()
        if data.get("status") in {"completed", "failed", "cancelled"}
    ]
    for scan_id in finished[:-max_finished]:
        active_scans.pop(scan_id, None)
        scan_results.pop(scan_id, None)
        scan_tasks.pop(scan_id, None)


@app.get("/")
async def root():
    return {
        "name": "Vulnerability Scanner API",
        "version": "1.1.0",
        "status": "operational",
        "authentication": "X-API-Key required for scan and assessment endpoints",
        "default_scan_mode": "safe (passive web checks; no exploit execution)",
    }


@app.post("/scan", dependencies=[Depends(require_api_token)])
async def create_scan(request: ScanRequest):
    try:
        targets = validate_targets(request.targets, maximum=25)
        if any('://' in target or '/' in target for target in targets):
            raise ScopeError("API scans require individual hostnames or IP addresses, not URLs or CIDR ranges")
        ports = validate_ports(request.ports, maximum=100)
        if request.scan_type == "active":
            require_feature_enabled("PEN_ENABLE_ACTIVE_TESTS", "Active web checks")
        if request.run_exploits:
            require_feature_enabled("PEN_ENABLE_EXPLOIT_CHECKS", "Exploit checks")
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        max_running = min(max(int(os.getenv("PEN_MAX_RUNNING_SCANS", "2")), 1), 10)
    except ValueError:
        max_running = 2
    running = sum(1 for item in active_scans.values() if item.get("status") in {
        "initializing", "running", "cancelling"
    })
    if running >= max_running:
        raise HTTPException(status_code=429, detail="Maximum concurrent scan count reached")

    scan_id = uuid.uuid4().hex
    active_scans[scan_id] = {
        "status": "initializing",
        "progress": 0.0,
        "targets": targets,
        "targets_completed": 0,
        "total_targets": len(targets),
        "vulnerabilities_found": 0,
        "start_time": _utc_now(),
        "scan_type": request.scan_type,
    }
    scan_tasks[scan_id] = asyncio.create_task(
        run_scan_task(scan_id, targets, ports, request.scan_type, request.run_exploits)
    )
    return {
        "scan_id": scan_id,
        "message": "Scan initiated",
        "status_url": f"/scan/{scan_id}",
        "scan_type": request.scan_type,
    }


async def run_scan_task(
    scan_id: str,
    targets: List[str],
    ports: Optional[List[int]],
    scan_type: str = "safe",
    run_exploits: bool = False,
):
    from vulnscanner.core.engine import ScannerEngine

    all_vulns = []
    all_exploits = []
    try:
        active_scans[scan_id]["status"] = "running"
        for index, target in enumerate(targets):
            state = active_scans.get(scan_id)
            if state is None:
                return
            state["progress"] = (index / len(targets)) * 100
            state["current_target"] = target

            engine = ScannerEngine(config={"enable_active_tests": scan_type == "active"})
            try:
                engine.add_target(target, ports)
                results = await engine.run_full_scan()
                for host_vulns in results.values():
                    all_vulns.extend(host_vulns)
            finally:
                await engine.close()

            if run_exploits:
                # This branch is reachable only after explicit request + env opt-in.
                from vulnscanner.core.exploits import ExploitModule
                exploit_module = ExploitModule()
                all_exploits.extend(await exploit_module.scan_target(target, ports))

            state["targets_completed"] = index + 1
            state["vulnerabilities_found"] = len(all_vulns)

        scan_results[scan_id] = {
            "scan_id": scan_id,
            "targets": targets,
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "name": v.name,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "affected_component": v.affected_component,
                    "remediation": v.remediation,
                    "cwe_id": v.cwe_id,
                    "cve_id": v.cve_id,
                    "exploit_available": v.exploit_available,
                    "timestamp": v.timestamp,
                }
                for v in all_vulns
            ],
            "exploits": [
                {
                    "exploit_name": getattr(e, "exploit_name", "unknown"),
                    "success": bool(getattr(e, "success", False)),
                    "target": getattr(e, "target", ""),
                    "output": str(getattr(e, "output", ""))[:500],
                }
                for e in all_exploits
            ],
            "statistics": {
                "total": len(all_vulns),
                "critical": sum(1 for v in all_vulns if v.severity == "CRITICAL"),
                "high": sum(1 for v in all_vulns if v.severity == "HIGH"),
                "medium": sum(1 for v in all_vulns if v.severity == "MEDIUM"),
                "low": sum(1 for v in all_vulns if v.severity == "LOW"),
            },
            "completed_at": _utc_now(),
        }
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100.0
    except asyncio.CancelledError:
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "cancelled"
        raise
    except Exception:
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = "Scan failed. Check server logs for details."
    finally:
        scan_tasks.pop(scan_id, None)
        _prune_completed_scans()


@app.get("/scan/{scan_id}", dependencies=[Depends(require_api_token)])
async def get_scan_status(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus(**_safe_scan_summary(scan_id, active_scans[scan_id]))


@app.get("/scan/{scan_id}/results", dependencies=[Depends(require_api_token)])
async def get_scan_results(scan_id: str):
    if scan_id not in scan_results:
        if scan_id in active_scans:
            return {"status": active_scans[scan_id]["status"], "message": "Results are not ready"}
        raise HTTPException(status_code=404, detail="Scan results not found")
    return scan_results[scan_id]


@app.get("/scans", dependencies=[Depends(require_api_token)])
async def list_scans():
    return {
        "scans": [
            _safe_scan_summary(scan_id, data)
            for scan_id, data in list(active_scans.items())[-100:]
        ]
    }


@app.delete("/scan/{scan_id}", dependencies=[Depends(require_api_token)])
async def cancel_scan(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    task = scan_tasks.get(scan_id)
    if not task or task.done():
        raise HTTPException(status_code=409, detail="Scan is no longer running")
    active_scans[scan_id]["status"] = "cancelling"
    task.cancel()
    return {"message": "Cancellation requested", "scan_id": scan_id, "status": "cancelling"}


@app.get("/exploits", dependencies=[Depends(require_api_token)])
async def list_exploits():
    from vulnscanner.core.exploits import ExploitModule
    return {"exploits": ExploitModule().get_exploit_list()}


@app.get("/payloads", dependencies=[Depends(require_api_token)])
async def list_payloads():
    from vulnscanner.core.payloads import PayloadManager
    payloads = PayloadManager().get_all_payloads()
    return {"categories": list(payloads.keys()), "counts": {key: len(value) for key, value in payloads.items()}}


@app.get("/payloads/{category}", dependencies=[Depends(require_api_token)])
async def get_payloads(category: str):
    from vulnscanner.core.payloads import PayloadManager
    payloads = PayloadManager().get_payloads(category)
    if not payloads:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"category": category, "count": len(payloads), "payloads": payloads[:50]}


def run_server(host: str = "127.0.0.1", port: int = 8000):
    ssl_options = {}
    if host not in {"127.0.0.1", "localhost", "::1"}:
        if os.getenv("PEN_ALLOW_REMOTE_API", "").strip().lower() not in {"1", "true", "yes"}:
            raise RuntimeError(
                "Remote API binding is disabled by default; configure PEN_ALLOW_REMOTE_API=1 only for a secured deployment."
            )
        certfile = os.getenv("PEN_API_TLS_CERTFILE", "")
        keyfile = os.getenv("PEN_API_TLS_KEYFILE", "")
        if not certfile or not keyfile or not Path(certfile).is_file() or not Path(keyfile).is_file():
            raise RuntimeError(
                "Remote API binding requires existing PEN_API_TLS_CERTFILE and PEN_API_TLS_KEYFILE files; "
                "otherwise bind to loopback behind a TLS-terminating proxy."
            )
        ssl_options = {"ssl_certfile": certfile, "ssl_keyfile": keyfile}
    if not 1 <= int(port) <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    print(f"[*] Starting Vulnerability Scanner API on {host}:{port}")
    uvicorn.run(app, host=host, port=port, **ssl_options)


if __name__ == "__main__":
    run_server()
