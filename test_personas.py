import requests
import json
import time

API_URL = "http://localhost:8000/api/v1/detect"
HEADERS = {"x-api-key": "guvi_hackathon_secret_123", "Content-Type": "application/json"}

def send(text, history):
    payload = {
        "sessionId": f"test-{int(time.time())}",
        "message": {"sender": "scammer", "text": text, "timestamp": "2026-02-01"},
        "conversationHistory": history
    }
    return requests.post(API_URL, json=payload, headers=HEADERS).json()

print("⚔️ STARTING PERSONA & SAFETY TEST ⚔️\n")

# TEST 1: LEGIT MESSAGE
print("🔹 TEST 1: Legit Bank Alert")
resp1 = send("HDFC Bank: Rs 5000 debited for Amazon. Ref: 12345. Call 1800-HDFC if unauthorized.", [])
print(f"   Scam Detected: {resp1['scamDetected']}")
print(f"   Notes: {resp1['agentNotes']}")

if resp1['scamDetected'] == False:
    print("   ✅ PASSED: Legit message ignored.\n")
else:
    print("   ❌ FAILED: Legit message flagged!\n")

# TEST 2: CONTEXTUAL PERSONA ("Hi Dad")
print("🔹 TEST 2: Contextual Persona ('Hi Dad')")
resp2 = send("Hi Dad, I lost my phone and wallet. Please send 5000rs to this friend's UPI urgently.", [])
print(f"   Reply: {resp2['agentNotes']}")

if "Dad" in resp2['agentNotes'] or "son" in resp2['agentNotes'] or "daughter" in resp2['agentNotes'] or "honey" in resp2['agentNotes'].lower():
    print("   ✅ PASSED: Agent adopted Parent persona.\n")
else:
    print("   ⚠️ CHECK: Did it sound like a parent?\n")

# TEST 3: DIFFERENT PERSONA (Generic)
print("🔹 TEST 3: Random/Generic Persona")
resp3 = send("Sir, your electricity will be cut tonight unless you pay bill.", [])
print(f"   Reply: {resp3['agentNotes']}")
print("   ✅ CHECK: Does this sound like a Lawyer, Student, or Senior? (Variety check)\n")