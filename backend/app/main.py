from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import os
from typing import Dict, Any, Optional

from app.services.recon_engine import LiveReconRunner
from app.services.ai_analyzer import GeminiAnalyzer

app = FastAPI(title="KavachRecon API Engine", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_STORE: Dict[str, Dict[str, Any]] = {}

class StartScanRequest(BaseModel):
    target: str
    scan_mode: str = "PASSIVE_ONLY"
    authorization_confirmed: bool

class AISummaryRequest(BaseModel):
    api_key: Optional[str] = None

class AIChatRequest(BaseModel):
    message: str
    api_key: Optional[str] = None

@app.get("/api/v1/health")
async def health_check():
    return {"status": "HEALTHY", "product": "KavachRecon", "engine": "ACTIVE"}

@app.post("/api/v1/scans/start")
async def start_scan(payload: StartScanRequest, background_tasks: BackgroundTasks):
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=403, 
            detail="Scope authorization confirmation is required before initiating reconnaissance."
        )

    scan_id = str(uuid.uuid4())
    runner = LiveReconRunner(payload.target, scan_id, payload.scan_mode)
    SCAN_STORE[scan_id] = runner.state

    background_tasks.add_task(runner.execute_all)

    return {
        "scan_id": scan_id,
        "target": runner.target_domain,
        "scan_mode": payload.scan_mode,
        "status": "QUEUED"
    }

@app.get("/api/v1/scans/{scan_id}/status")
async def get_scan_status(scan_id: str):
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return SCAN_STORE[scan_id]

@app.post("/api/v1/scans/{scan_id}/ai/summary")
async def generate_ai_summary(scan_id: str, payload: AISummaryRequest):
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    
    summary = await GeminiAnalyzer.generate_summary(SCAN_STORE[scan_id], payload.api_key)
    return {"scan_id": scan_id, "summary": summary}

@app.post("/api/v1/scans/{scan_id}/ai/chat")
async def ai_chat(scan_id: str, payload: AIChatRequest):
    if scan_id not in SCAN_STORE:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    
    response = await GeminiAnalyzer.chat_query(SCAN_STORE[scan_id], payload.message, payload.api_key)
    return {"scan_id": scan_id, "response": response}