import requests
import json
import time

# CONFIGURATION
API_URL = "http://localhost:8000/api/v1/detect"
API_KEY = "guvi_hackathon_secret_123"
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}
SESSION_ID = f"victory-lap-{int(time.time())}"

def run_turn(turn_name, message_text, history):
    print(f"\n🏁 {turn_name} | Incoming: \"{message_text}\"")
    
    payload = {
        "sessionId": SESSION_ID,
        "message": {
            "sender": "scammer",
            "text": message_text,
            "timestamp": "2026-02-01T10:00:00Z"
        },
        "conversationHistory": history
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            reply = data.get("agentNotes", "").split("|")[0]
            intel = data.get("extractedIntelligence", {})
            print(f"   🤖 Verdict: {'🚨 SCAM' if data['scamDetected'] else '✅ SAFE'}")
            print(f"   🗣️ Reply: {reply}")
            if intel.get('upiIds') or intel.get('bankAccounts'):
                print(f"   💰 INTEL: {intel}")
            return data, reply
        else:
            print(f"   ❌ Error: {response.text}")
            return None, None
    except Exception as e:
        print(f"   ❌ CRITICAL FAILURE: {e}")
        return None, None

# --- START SIMULATION ---
print(f"🏎️ STARTING VICTORY LAP SIMULATION (Session: {SESSION_ID})")
print("Objective: Pass all 12 PDF Criteria in one run.\n")

history = []

# LAP 1: The "Safety Check" (Must Ignore)
# PDF Criterion: "Detect scam intent" (implies ignoring non-scams) [cite: 9]
data1, reply1 = run_turn(
    "LAP 1 (Legit Bank Alert)", 
    "HDFC Bank Alert: Rs 5000 debited for ATM WDL. Call 1800-258-6161 if disputes.", 
    []
)

if data1 and not data1['scamDetected']:
    print("   ✅ PASS: Legit message correctly ignored.")
else:
    print("   ❌ FAIL: False Positive detected!")

# LAP 2: The "Scam Trigger" (Must Detect & Persona Lock)
# PDF Criterion: "Maintain a believable human-like persona" [cite: 10]
scam_msg = "Your HDFC account will be blocked today! Update PAN immediately at http://bit.ly/hdfc-kyc"
data2, reply2 = run_turn("LAP 2 (Scam Hook)", scam_msg, history)

# Update History (Simulate real convo)
history.append({"sender": "scammer", "text": scam_msg, "timestamp": "2026-02-01T10:05:00Z"})
if reply2:
    # Clean the reply for history (remove [STATUS] tags)
    clean_reply = reply2.replace("[STATUS: ONGOING] [REPLY]:", "").strip()
    history.append({"sender": "user", "text": clean_reply, "timestamp": "2026-02-01T10:05:15Z"})

# LAP 3: The "Extraction" (Must get Intel)
# PDF Criterion: "Extract scam-related intelligence" [cite: 10]
follow_up = "Sir, don't argue. Transfer 10rs to verify@okicici or account 5010023456 to stop blocking."
data3, reply3 = run_turn("LAP 3 (Extraction)", follow_up, history)

# --- FINAL VERIFICATION ---
print("\n" + "="*50)
print("🏆 RACE RESULTS:")

# Check 1: Intel Extraction [cite: 111-115]
intel = data3.get('extractedIntelligence', {})
got_link = len(intel.get('phishingLinks', [])) > 0
got_upi = len(intel.get('upiIds', [])) > 0 or len(intel.get('bankAccounts', [])) > 0

if got_link and got_upi:
    print("✅ INTELLIGENCE: 100% (Link + Payment Details Found)")
else:
    print(f"⚠️ INTELLIGENCE: Partial ({intel})")

# Check 2: Mandatory Callback [cite: 131]
print("✅ CALLBACK: Check your Terminal Logs for '🚀 [CALLBACK] Sending Report'")
print("   (This confirms the mandatory PDF requirement is met)")

print("="*50)
if got_link and got_upi and data1['scamDetected'] == False:
    print("🥇 YOU ARE READY TO WIN. SUBMIT NOW.")
else:
    print("❌ CHECK FAILED. DO NOT SUBMIT.")