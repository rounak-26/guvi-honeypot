import requests
import logging
import json

logger = logging.getLogger(__name__)

# Source: Problem Statement Section 12 [cite: 135]
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_final_callback(session_id: str, decision_data: dict, total_messages: int):
    """
    Sends the final extracted intelligence to the GUVI evaluation endpoint.
    This is executed as a Background Task to ensure the API responds fast.
    """
    logger.info(f"🚀 INITIATING CALLBACK for Session: {session_id}")
    
    # Construct the strict payload [cite: 139-151]
    payload = {
        "sessionId": session_id,
        "scamDetected": decision_data.get("scamDetected", False),
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": decision_data.get("extractedIntelligence", {}),
        "agentNotes": decision_data.get("agentNotes", "Automated report")
    }

    try:
        # We set a timeout because we don't want to hang forever
        response = requests.post(CALLBACK_URL, json=payload, headers={"Content-Type": "application/json", "x-api-key": "guvi_hackathon_secret_123"}, timeout=10)
        
        if response.status_code == 200 or response.status_code == 201:
            logger.info(f"✅ CALLBACK SUCCESS: {response.status_code} | {response.text}")
        else:
            logger.error(f"⚠️ CALLBACK FAILED: {response.status_code} | {response.text}")
            
    except Exception as e:
        logger.error(f"❌ CALLBACK EXCEPTION: {str(e)}")