import sys
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn


app = FastAPI(
    title="Vulnerability Scanner API",
    description="Enterprise Security Scanning Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_scans: Dict[str, Dict] = {}
scan_results: Dict[str, Dict] = {}


class ScanRequest(BaseModel):
    targets: List[str]
    ports: Optional[List[int]] = None
    scan_type: str = "full"
    run_exploits: bool = False
    config: Optional[Dict] = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    targets_completed: int
    total_targets: int
    vulnerabilities_found: int
    start_time: str
    eta: Optional[str] = None


@app.get("/")
async def root():
    return {
        "name": "Vulnerability Scanner API",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "/scan": "POST - Start new scan",
            "/scan/{scan_id}": "GET - Get scan status",
            "/scan/{scan_id}/results": "GET - Get scan results",
            "/scans": "GET - List all scans",
            "/exploits": "GET - List available exploits",
            "/payloads": "GET - List payload categories"
        }
    }


@app.post("/scan")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    from vulnscanner.core.engine import ScannerEngine
    from vulnscanner.core.exploits import ExploitModule
    import uuid
    
    scan_id = str(uuid.uuid4())[:8].upper()
    
    active_scans[scan_id] = {
        "status": "initializing",
        "progress": 0,
        "targets": request.targets,
        "targets_completed": 0,
        "total_targets": len(request.targets),
        "vulnerabilities_found": 0,
        "start_time": datetime.now().isoformat(),
        "config": request.config or {}
    }
    
    background_tasks.add_task(
        run_scan_task,
        scan_id,
        request.targets,
        request.ports,
        request.run_exploits
    )
    
    return {"scan_id": scan_id, "message": "Scan initiated", "status_url": f"/scan/{scan_id}"}


async def run_scan_task(scan_id: str, targets: List[str], ports: List[int], run_exploits: bool):
    from vulnscanner.core.engine import ScannerEngine
    from vulnscanner.core.exploits import ExploitModule
    
    try:
        active_scans[scan_id]["status"] = "running"
        
        engine = ScannerEngine()
        exploit_module = ExploitModule() if run_exploits else None
        
        all_vulns = []
        all_exploits = []
        
        for i, target in enumerate(targets):
            active_scans[scan_id]["progress"] = (i / len(targets)) * 100
            active_scans[scan_id]["current_target"] = target
            
            engine.add_target(target, ports)
            
            results = await engine.run_full_scan()
            for host, vulns in results.items():
                all_vulns.extend(vulns)
            
            active_scans[scan_id]["targets_completed"] = i + 1
            active_scans[scan_id]["vulnerabilities_found"] = len(all_vulns)
        
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "targets": targets,
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id, "name": v.name, "severity": v.severity,
                    "cvss_score": v.cvss_score, "description": v.description,
                    "affected_component": v.affected_component, "remediation": v.remediation,
                    "cwe_id": v.cwe_id, "cve_id": v.cve_id, "exploit_available": v.exploit_available,
                    "timestamp": v.timestamp
                } for v in all_vulns
            ],
            "statistics": {
                "total": len(all_vulns),
                "critical": sum(1 for v in all_vulns if v.severity == "CRITICAL"),
                "high": sum(1 for v in all_vulns if v.severity == "HIGH"),
                "medium": sum(1 for v in all_vulns if v.severity == "MEDIUM"),
                "low": sum(1 for v in all_vulns if v.severity == "LOW")
            },
            "completed_at": datetime.now().isoformat()
        }
        
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100
        
        await engine.close()
        
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)


@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanStatus(
        scan_id=scan_id,
        status=active_scans[scan_id]["status"],
        progress=active_scans[scan_id]["progress"],
        targets_completed=active_scans[scan_id]["targets_completed"],
        total_targets=active_scans[scan_id]["total_targets"],
        vulnerabilities_found=active_scans[scan_id]["vulnerabilities_found"],
        start_time=active_scans[scan_id]["start_time"]
    )


@app.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    if scan_id not in scan_results:
        if scan_id in active_scans:
            return {"status": "in_progress", "message": "Scan still running"}
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    return scan_results[scan_id]


@app.get("/scans")
async def list_scans():
    return {
        "active_scans": [
            {"scan_id": sid, **data} 
            for sid, data in active_scans.items() 
            if data["status"] not in ["completed", "failed"]
        ],
        "completed_scans": [
            {"scan_id": sid, "completed_at": scan_results.get(sid, {}).get("completed_at")} 
            for sid, data in active_scans.items() 
            if data["status"] == "completed"
        ]
    }


@app.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    active_scans[scan_id]["status"] = "cancelled"
    return {"message": "Scan cancelled", "scan_id": scan_id}


@app.get("/exploits")
async def list_exploits():
    from vulnscanner.core.exploits import ExploitModule
    exploit_module = ExploitModule()
    return {"exploits": exploit_module.get_exploit_list()}


@app.get("/payloads")
async def list_payloads():
    from vulnscanner.core.payloads import PayloadManager
    pm = PayloadManager()
    return {
        "categories": list(pm.get_all_payloads().keys()),
        "counts": {k: len(v) for k, v in pm.get_all_payloads().items()}
    }


@app.get("/payloads/{category}")
async def get_payloads(category: str):
    from vulnscanner.core.payloads import PayloadManager
    pm = PayloadManager()
    payloads = pm.get_payloads(category)
    if not payloads:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"category": category, "count": len(payloads), "payloads": payloads[:50]}


def run_server(host: str = "0.0.0.0", port: int = 8000):
    print(f"[*] Starting Vulnerability Scanner API on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == '__main__':
    run_server()
