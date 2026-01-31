import requests
import json
import time

# Configuration
API_URL = "http://localhost:8000/api/v1/detect"
API_KEY = "guvi_hackathon_secret_123"
SESSION_ID = f"sim-test-{int(time.time())}"

headers = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

def send_message(text, sender, history):
    payload = {
        "sessionId": SESSION_ID,
        "message": {
            "sender": sender,
            "text": text,
            "timestamp": "2026-01-31T10:00:00Z"
        },
        "conversationHistory": history,
        "metadata": {"channel": "SMS", "language": "en", "locale": "IN"}
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def run_simulation():
    history = []
    
    print(f"🚀 STARTING MULTI-TURN SIMULATION (Session: {SESSION_ID})\n")

    # TURN 1: Scammer starts (Subtle, no immediate demand)
    msg1 = "Hello, this is SBI Support. We noticed unusual activity on your card."
    print(f"1️⃣  Scammer: {msg1}")
    
    resp1 = send_message(msg1, "scammer", history)
    print(f"    🤖 Agent: {resp1.get('agentNotes', 'No notes')}")
    print(f"    detect: {resp1.get('scamDetected')}")
    
    # Add to history (Judge requires strict history format)
    history.append({"sender": "scammer", "text": msg1, "timestamp": "2026-01-31T10:00:00Z"})
    
    # Simulating User Reply (The Agent's previous reply would technically go here, 
    # but for this test we simulate the user playing along)
    user_reply = "Oh no! What happened? Is my money safe?"
    history.append({"sender": "user", "text": user_reply, "timestamp": "2026-01-31T10:01:00Z"})
    
    print("-" * 40)
    time.sleep(1)

    # TURN 2: Scammer escalates (Still no link, just urgency)
    msg2 = "Your card is blocked. You must verify your KYC immediately or police action will be taken."
    print(f"2️⃣  Scammer: {msg2}")
    
    resp2 = send_message(msg2, "scammer", history)
    print(f"    🤖 Agent: {resp2.get('agentNotes', 'No notes')}")
    
    history.append({"sender": "scammer", "text": msg2, "timestamp": "2026-01-31T10:02:00Z"})
    user_reply2 = "I am scared. Please tell me what to do."
    history.append({"sender": "user", "text": user_reply2, "timestamp": "2026-01-31T10:03:00Z"})
    
    print("-" * 40)
    time.sleep(1)

    # TURN 3: The Trap (Payment Info)
    msg3 = "Download QuickSupport or send 10rs to verify@okaxis to unlock."
    print(f"3️⃣  Scammer: {msg3}")
    
    resp3 = send_message(msg3, "scammer", history)
    
    # ANALYZE RESULT
    intel = resp3.get("extractedIntelligence", {})
    print(f"\n📊 FINAL INTELLIGENCE EXTRACTED:")
    print(f"   UPI: {intel.get('upiIds')}")
    print(f"   Links: {intel.get('phishingLinks')}")
    print(f"   Keywords: {intel.get('suspiciousKeywords')}")
    
    if "verify@okaxis" in intel.get("upiIds", []):
        print("\n✅ SUCCESS: Agent remembered context and extracted the UPI.")
    else:
        print("\n❌ FAILED: UPI not found.")

if __name__ == "__main__":
    run_simulation()