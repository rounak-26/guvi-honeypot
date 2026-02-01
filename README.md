# 🛡️ Agentic Honeypot — Scam Detection & Intelligence Extraction

> An autonomous AI-powered honeypot that detects scam messages, engages scammers in multi-turn conversations, extracts actionable intelligence, and reports findings — all without revealing detection.

[![Python](https://img.shields.io/badge/Python-3.10+-3572A5?style=flat-square&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Gemini](https://img.shields.io/badge/Gemini-2.0%20Flash-4285F4?style=flat-square&logo=google)](https://ai.google.dev/)
[![Render](https://img.shields.io/badge/Deployed-Render-46E3B7?style=flat-square)](https://render.com/)

🌐 **Live API:** [https://guvi-honeypot-p45x.onrender.com](https://guvi-honeypot-p45x.onrender.com)
📄 **Docs:** [https://guvi-honeypot-p45x.onrender.com/docs](https://guvi-honeypot-p45x.onrender.com/docs)

---

## 🎯 How It Works

The system operates as a **multi-phase autonomous agent**:

| Phase | What Happens |
|---|---|
| **Detection** | Incoming message is scanned with keyword matching + LLM confirmation |
| **Persona Lock** | A human persona is selected and locked for the entire session |
| **Engagement** | Agent replies skeptically — delays, questions, resists — like a real person |
| **Extraction** | UPIs, bank accounts, phishing links, and phone numbers are extracted progressively |
| **Disengage** | Once 2+ independent intelligence signals are confirmed, the agent exits naturally |
| **Callback** | Final intelligence is POSTed to GUVI's evaluation endpoint |

---

## 🏗️ Architecture

```
Client (SMS / WhatsApp / API)
        │
        ▼
POST /api/v1/detect
        │
        ▼
┌─────────────────────┐
│   FastAPI (main.py) │  ← API key validation, request handling
└────────┬────────────┘
         ▼
┌─────────────────────┐
│  AgentEngine        │  ← Gemini 2.0 Flash + Regex extraction
│  (agent_engine.py)  │  ← Persona, memory, stop logic
└────────┬────────────┘
         ▼
    ┌─────────┐     ┌──────────────────┐
    │ Client  │     │  GUVI Callback   │
    │Response │     │ (on FINISHED)    │
    └─────────┘     └──────────────────┘
```

---

## 📂 Project Structure

```
├── main.py                      # FastAPI app, routing, callback trigger
├── agent_engine.py              # Core agent: detection, persona, extraction, stop logic
├── callback_service.py          # POST final results to GUVI endpoint
├── Procfile                     # Render deployment config
├── requirements.txt             # Dependencies
├── .env                         # API keys (not committed)
├── test_llm.py                  # Gemini API connectivity test
├── test_extreme.py              # Full adversarial test suite
├── test_simulation.py           # Multi-turn simulation
├── test_personas.py             # Persona consistency tests
└── test_consistency.py          # Memory & context tests
```

---

## 🚀 API Reference

### `POST /api/v1/detect`

**Headers:**
```
x-api-key: YOUR_SECRET_API_KEY
Content-Type: application/json
```

**Request:**
```json
{
  "sessionId": "session-001",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked. Share your UPI ID immediately.",
    "timestamp": "2026-02-01T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "scamDetected": true,
  "engagementMetrics": {
    "engagementDurationSeconds": 105,
    "totalMessagesExchanged": 7
  },
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": ["scammer123@upi"],
    "phishingLinks": ["https://fake-bank-verify.com/confirm"],
    "phoneNumbers": [],
    "suspiciousKeywords": ["blocked", "verify", "verification fee"]
  },
  "agentNotes": "Persona: Skeptical Student. Scammer used urgency + payment redirection. Extracted UPI and phishing link. Disengaged after 2 signals confirmed."
}
```

---

## 🧠 Key Technical Decisions

**Why Gemini 2.0 Flash?**
Fastest inference in the Gemini family. Critical for sub-second API responses during multi-turn engagement.

**Why deterministic regex extraction over LLM-only?**
LLMs hallucinate. UPIs, links, and phone numbers are extracted via regex on the raw text — guaranteed accuracy. The LLM handles intent and persona; regex handles precision extraction.

**Why force `conversationStatus` in code, not in the LLM?**
The LLM tends to set FINISHED too early. The stop logic is enforced deterministically: FINISHED only fires when 2+ independent intelligence signals are confirmed by regex. This is the single most important reliability decision in the system.

**Why background tasks for callbacks?**
The API must respond fast. The callback to GUVI runs asynchronously via FastAPI's `BackgroundTasks` — the client gets a 200 response in ~500ms while the callback fires independently with 3 retries.

---

## ⚙️ Setup & Run Locally

```bash
# 1. Clone
git clone <your-repo-url>
cd Final-Agentic-Honey-Pot-API

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create .env file
# GOOGLE_API_KEY=your_gemini_key
# API_SECRET=guvi_hackathon_secret_123
# PORT=8000

# 4. Run
uvicorn main:app --reload

# 5. Test LLM connectivity
python test_llm.py
```

---

## 🧪 Testing

```bash
# Full adversarial test suite (66+ tests across 8 categories)
python test_extreme.py

# Categories covered:
# CAT-A → Legitimate messages disguised as scams (false positive traps)
# CAT-B → Scams disguised as legitimate (false negative traps)
# CAT-C → Multi-turn adversarial conversation chains
# CAT-D → Exact GUVI schema validation
# CAT-E → Edge cases (unicode, empty, injections, huge payloads)
# CAT-F → Callback payload structure verification
# CAT-G → Persona consistency under prompt injection attacks
# CAT-H → Ambiguous gray-zone messages
```

---

## ☁️ Deployment

Deployed on **Render** (Free Tier) with auto-deploy from GitHub.

```
# Procfile
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

Environment variables are configured in Render Dashboard — never committed to git.

---

## ✅ GUVI Compliance Checklist

| Requirement | Status |
|---|---|
| Scam detection | ✅ Progressive, evidence-based |
| AI Agent activation | ✅ On confirmed scam intent |
| Human-like persona | ✅ Skeptical, memory-locked |
| Multi-turn handling | ✅ Full conversationHistory support |
| Intelligence extraction | ✅ UPI, links, phones, keywords |
| Structured JSON response | ✅ Exact schema match |
| x-api-key authentication | ✅ Header validation |
| Final callback to GUVI | ✅ POST with retries, confirmed 200 |
| Legitimate message safety | ✅ Whitelisted — zero false positives |

---

## 👤 Author

**Rounak Deb**
GUVI x HCL Hackathon 2026 — Agentic Honeypot Submission