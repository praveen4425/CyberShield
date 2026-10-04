"""
CyberShield - Explainable Security Log Analysis & Intrusion Detection Backend
FastAPI server serving analysis APIs and static frontend dashboard.
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .models import AnalysisResponse, AnalysisSummary, CorrelatedIncident, SecurityEvent
from .parser import parse_logs
from .detector import run_all_detections
from .correlator import correlate_incidents, generate_analysis_summary

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "data"
SAMPLE_CSV_PATH = DATA_DIR / "sample_security_logs.csv"

app = FastAPI(
    title="CyberShield Intrusion Detection Platform",
    description="Explainable Security Log Analysis & Intrusion Detection Platform for ALG-CYBER-01",
    version="1.0.0"
)

# Enable CORS for local development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for current session's analysis
current_analysis_cache = {
    "events": [],
    "incidents": [],
    "summary": None
}


def process_raw_logs(content: str, filename: str = "") -> AnalysisResponse:
    """Core pipeline: Ingest -> Normalize -> Detect -> Correlate -> Score -> Respond."""
    events = parse_logs(content, filename=filename)
    if not events:
        # Empty or unparseable input
        empty_summary = AnalysisSummary(
            total_events=0,
            total_suspicious_events=0,
            total_incidents=0,
            critical_incidents=0,
            high_incidents=0,
            medium_incidents=0,
            low_incidents=0,
            unique_ips=0,
            unique_users=0,
            suspicious_ips=[],
            suspicious_users=[]
        )
        return AnalysisResponse(
            success=True,
            message="No events parsed from the provided input.",
            summary=empty_summary,
            incidents=[],
            events=[]
        )

    # Run Detection Engine
    detections = run_all_detections(events)
    
    # Run Correlation & Incident Engine
    incidents = correlate_incidents(events, detections)
    
    # Generate Summary Metrics
    summary = generate_analysis_summary(events, incidents)

    # Update session cache
    current_analysis_cache["events"] = events
    current_analysis_cache["incidents"] = incidents
    current_analysis_cache["summary"] = summary

    return AnalysisResponse(
        success=True,
        message=f"Analyzed {len(events)} events; identified {len(incidents)} correlated incident(s).",
        summary=summary,
        incidents=incidents,
        events=events
    )


@app.post("/api/analyze/upload", response_model=AnalysisResponse)
async def upload_log_file(file: UploadFile = File(...)):
    """Upload a CSV or JSON log file for instant analysis."""
    try:
        content_bytes = await file.read()
        content_str = content_bytes.decode("utf-8", errors="replace")
        return process_raw_logs(content_str, filename=file.filename or "")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process uploaded file: {str(e)}")


@app.get("/api/analyze/sample", response_model=AnalysisResponse)
async def analyze_sample_logs():
    """Load and analyze pre-configured synthetic sample logs for instant judge demonstration."""
    if not SAMPLE_CSV_PATH.exists():
        raise HTTPException(status_code=404, detail="Sample logs not found.")
    try:
        with open(SAMPLE_CSV_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        return process_raw_logs(content, filename="sample_security_logs.csv")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading sample logs: {str(e)}")


@app.get("/api/incidents", response_model=List[CorrelatedIncident])
async def get_incidents(risk_level: Optional[str] = None):
    """Retrieve all correlated incidents, optionally filtered by risk level."""
    incidents = current_analysis_cache.get("incidents", [])
    if risk_level:
        incidents = [i for i in incidents if i.risk_level.upper() == risk_level.upper()]
    return incidents


@app.get("/api/incidents/{incident_id}", response_model=CorrelatedIncident)
async def get_incident_detail(incident_id: str):
    """Retrieve deep forensic detail for a specific incident."""
    incidents = current_analysis_cache.get("incidents", [])
    for inc in incidents:
        if inc.incident_id.upper() == incident_id.upper():
            return inc
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")


@app.patch("/api/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, status: str = Query(..., pattern="^(New|Investigating|Resolved)$")):
    """Update status of an incident (New, Investigating, Resolved)."""
    incidents = current_analysis_cache.get("incidents", [])
    for inc in incidents:
        if inc.incident_id.upper() == incident_id.upper():
            inc.status = status
            return {"success": True, "incident_id": incident_id, "status": status}
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")


@app.get("/api/health")
async def health_check():
    """Simple health endpoint."""
    return {"status": "ok", "app": "CyberShield", "version": "1.0.0"}


# Serve static frontend files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    if (FRONTEND_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
    if (FRONTEND_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")

    @app.get("/")
    async def serve_index():
        return FileResponse(FRONTEND_DIR / "index.html")
