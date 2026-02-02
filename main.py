import os
import logging
import uvicorn
import requests
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Union
from dotenv import load_dotenv

from agent_engine import AgentEngine

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_SECRET = os.getenv("API_SECRET")
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

app = FastAPI()

agent_engine = AgentEngine()

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    body = await request.body()
    logger.error(f"❌ VALIDATION ERROR from {request.client.host}")
    logger.error(f"📦 Raw body: {body.decode('utf-8', errors='replace')}")
    logger.error(f"🔍 Validation errors: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()}
    )

class MessageData(BaseModel):
    sender: Optional[str] = "unknown"
    text: str
    timestamp: Optional[Union[str, int]] = ""

class IncomingRequest(BaseModel):
    sessionId: Optional[str] = "default-session"
    message: Optional[MessageData] = None
    text: Optional[str] = None
    conversationHistory: Optional[List[MessageData]] = []
    metadata: Optional[dict] = None

class APIResponse(BaseModel):
    status: str
    scamDetected: bool
    engagementMetrics: Dict[str, Any]
    extractedIntelligence: Dict[str, Any]
    agentNotes: str

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Invalid API Key")

async def send_callback(session_id, decision, total_msgs):
    logger.info(f"🚀 INITIATING CALLBACK for session: {session_id}")

    payload = {
        "sessionId": session_id,
        "scamDetected": decision["scamDetected"],
        "totalMessagesExchanged": total_msgs,
        "extractedIntelligence": {
            "bankAccounts": decision["extractedIntelligence"].get("bankAccounts", []),
            "upiIds": decision["extractedIntelligence"].get("upiIds", []),
            "phishingLinks": decision["extractedIntelligence"].get("phishingLinks", []),
            "phoneNumbers": decision["extractedIntelligence"].get("phoneNumbers", []),
            "suspiciousKeywords": decision["extractedIntelligence"].get("suspiciousKeywords", [])
        },
        "agentNotes": decision["agentNotes"]
    }

    logger.info(f"📦 Callback payload: {payload}")

    for attempt in range(3):
        try:
            r = requests.post(
                CALLBACK_URL,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": API_SECRET
                },
                timeout=5
            )
            logger.info(f"📡 Callback attempt {attempt + 1} → Status: {r.status_code} | Response: {r.text}")
            if r.status_code in (200, 201):
                logger.info(f"✅ CALLBACK SUCCESS for session: {session_id}")
                return
        except Exception as e:
            logger.error(f"❌ Callback attempt {attempt + 1} failed: {e}")

    logger.error(f"⚠️ CALLBACK FAILED after 3 retries for session: {session_id}")

@app.post("/api/v1/detect", response_model=APIResponse)
async def detect(
    request: Request,
    bg: BackgroundTasks,
    _: str = Depends(verify_api_key)
):
    # Get JSON body
    try:
        json_body = await request.json()
        logger.info(f"📥 Request from {request.client.host}: {str(json_body)[:500]}")
    except Exception as e:
        logger.error(f"❌ Failed to parse JSON: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # Parse into Pydantic model
    try:
        payload = IncomingRequest.parse_obj(json_body)
    except Exception as e:
        logger.error(f"❌ Validation error: {e}")
        raise HTTPException(status_code=422, detail=f"Validation failed: {str(e)}")
    
    # Normalize: GUVI might send { "text": "..." } flat OR { "message": { "text": "..." } }
    if payload.message is None:
        if payload.text:
            payload.message = MessageData(text=payload.text)
        else:
            raise HTTPException(status_code=400, detail="No message text provided")

    # Handle None conversationHistory
    history = [m.model_dump() for m in (payload.conversationHistory or [])]
    total_msgs = len(history) + 1

    decision = agent_engine.process_message(
        payload.message.text,
        history,
        payload.message.sender
    )

    decision_dict = decision.model_dump()

    logger.info(f"💬 Agent replyText: {decision.replyText}")
    logger.info(f"📊 conversationStatus: {decision.conversationStatus} | scamDetected: {decision.scamDetected}")

    if decision.conversationStatus == "FINISHED":
        logger.info(f"🔚 FINISHED detected — triggering callback for session: {payload.sessionId}")
        bg.add_task(
            send_callback,
            payload.sessionId,
            decision_dict,
            total_msgs
        )

    return {
        "status": "success",
        "scamDetected": decision.scamDetected,
        "engagementMetrics": {
            "engagementDurationSeconds": total_msgs * 15,
            "totalMessagesExchanged": total_msgs
        },
        "extractedIntelligence": decision.extractedIntelligence.model_dump(),
        "agentNotes": decision.agentNotes
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))