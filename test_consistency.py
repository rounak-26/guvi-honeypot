import requests
import json
import time

API_URL = "http://localhost:8000/api/v1/detect"
HEADERS = {"x-api-key": "guvi_hackathon_secret_123", "Content-Type": "application/json"}
SESSION_ID = f"consistency-test-{int(time.time())}"

def get_reply(turn_num, text, history):
    payload = {
        "sessionId": SESSION_ID,
        "message": {"sender": "scammer", "text": text, "timestamp": "2026-02-01"},
        "conversationHistory": history
    }
    response = requests.post(API_URL, json=payload, headers=HEADERS).json()
    
    # Extract the reply text cleanly from the notes
    raw_notes = response.get("agentNotes", "")
    if "[REPLY]:" in raw_notes:
        reply = raw_notes.split("[REPLY]:")[1].split("|")[0].strip()
    else:
        reply = raw_notes
        
    print(f"\n🔹 TURN {turn_num} (Scammer): \"{text}\"")
    print(f"   🤖 AGENT: \"{reply}\"")
    return response

print(f"🧪 TESTING PERSONA CONSISTENCY (Session: {SESSION_ID})")
print("Goal: The Agent must pick ONE persona and stick to it.\n")

history = []

# --- TURN 1: The Trigger (Agent picks a random persona here) ---
resp1 = get_reply(1, "Hello sir, your electricity bill is overdue. Pay immediately or we cut power.", history)
history.append({"sender": "scammer", "text": "Hello sir, your electricity bill is overdue. Pay immediately or we cut power.", "timestamp": "2026-02-01"})
# We simulate the agent's reply in history so the LLM knows what it said previously
# (In real life, the platform sends this back, but here we must append it manually for the test)
agent_reply_1 = resp1.get("agentNotes", "").split("[REPLY]:")[1].split("|")[0].strip()
history.append({"sender": "user", "text": agent_reply_1, "timestamp": "2026-02-01"})

# --- TURN 2: The Follow-up (Agent must maintain persona) ---
resp2 = get_reply(2, "Do not argue. Send 500rs to power@upi immediately.", history)
history.append({"sender": "scammer", "text": "Do not argue. Send 500rs to power@upi immediately.", "timestamp": "2026-02-01"})
agent_reply_2 = resp2.get("agentNotes", "").split("[REPLY]:")[1].split("|")[0].strip()
history.append({"sender": "user", "text": agent_reply_2, "timestamp": "2026-02-01"})

# --- TURN 3: The Pressure (Agent must still be the same person) ---
resp3 = get_reply(3, "Sir if you don't pay now, police will come.", history)

print("\n" + "="*50)
print("🧐 ANALYSIS:")
print("Read the 3 Agent replies above. Do they sound like the SAME person?")