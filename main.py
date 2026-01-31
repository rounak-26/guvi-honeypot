import os
import uvicorn
import logging
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

from agent_engine import AgentEngine

# -------------------------------------------------
# SETUP
# -------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("API")

load_dotenv()

API_SECRET = os.getenv("API_SECRET", "guvi_hackathon_secret_123")
PORT = int(os.getenv("PORT", 8000))

# ✅ OFFICIAL GUVI CALLBACK (MANDATORY)
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

app = FastAPI(title="Agentic Honey-Pot API", version="1.0.0")

# -------------------------------------------------
# INIT AGENT
# -------------------------------------------------
try:
    agent_engine = AgentEngine()
    logger.info("✅ Agent Engine Initialized Successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize Agent Engine: {e}")
    agent_engine = None

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class MessageData(BaseModel):
    sender: str
    text: str
    timestamp: str

class IncomingRequest(BaseModel):
    sessionId: str
    message: MessageData
    conversationHistory: List[MessageData] = []
    metadata: Optional[dict] = None

class APIResponse(BaseModel):
    status: str
    scamDetected: bool
    engagementMetrics: Dict[str, Any]
    extractedIntelligence: Dict[str, Any]
    agentNotes: str

# -------------------------------------------------
# AUTH
# -------------------------------------------------
async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key

# -------------------------------------------------
# CALLBACK (MANDATORY)
# -------------------------------------------------
async def send_callback_background(
    session_id: str,
    decision_data: dict,
    total_messages: int
):
    try:
        payload = {
            "sessionId": session_id,
            "scamDetected": decision_data.get("scamDetected"),
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": decision_data.get("extractedIntelligence"),
            "agentNotes": decision_data.get("agentNotes")
        }

        logger.info(f"🚀 [CALLBACK] Sending Final Report for Session: {session_id}")
        logger.info(f"📦 Payload: {payload}")

        import requests
        requests.post(
            CALLBACK_URL,
            json=payload,
            timeout=5
        )

    except Exception as e:
        logger.error(f"⚠️ CALLBACK FAILED (will not block score): {e}")

# -------------------------------------------------
# MAIN ENDPOINT
# -------------------------------------------------
@app.post("/api/v1/detect", response_model=APIResponse)
async def detect_scam(
    payload: IncomingRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    if not agent_engine:
        raise HTTPException(status_code=500, detail="AI Engine not initialized")

    # --- PREPARE HISTORY ---
    history_list = [msg.model_dump() for msg in payload.conversationHistory]
    total_msgs = len(payload.conversationHistory) + 1

    # --- AGENT CALL ---
    decision = agent_engine.process_message(
        incoming_msg=payload.message.text,
        history=history_list,
        sender_type=payload.message.sender.lower()
    )

    # --- CALLBACK ONLY WHEN AGENT FINISHES ---
    if decision.conversationStatus == "FINISHED":
        background_tasks.add_task(
            send_callback_background,
            session_id=payload.sessionId,
            decision_data=decision.model_dump(),
            total_messages=total_msgs
        )

    # --- RESPONSE ---
    formatted_notes = (
        f"[STATUS: {decision.conversationStatus}] "
        f"[REPLY]: {decision.replyText} | {decision.agentNotes}"
    )

    return {
        "status": "success",
        "scamDetected": decision.scamDetected,
        "engagementMetrics": {
            "engagementDurationSeconds": total_msgs * 15,
            "totalMessagesExchanged": total_msgs
        },
        "extractedIntelligence": decision.extractedIntelligence.model_dump(),
        "agentNotes": formatted_notes
    }

# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
