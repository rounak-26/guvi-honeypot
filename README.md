\# 🛡️ Agentic Honeypot for Scam Detection \& Intelligence Extraction



This project implements a \*\*production-grade Agentic Honeypot API\*\* designed to \*\*detect scams, engage malicious actors autonomously, extract actionable intelligence, and disengage safely\*\* — without revealing detection.



The system is built to align \*\*strictly with the GUVI Hackathon problem statement\*\*, including:

\- Progressive scam detection  

\- Human-like engagement  

\- Memory-aware conversation handling  

\- Structured intelligence extraction  

\- Mandatory callback support  



---



\## 🚀 What This System Does



\- Detects scam intent progressively (not binary)

\- Engages scammers like a real human (skeptical, confused, busy personas)

\- Extracts intelligence such as:

&nbsp; - UPI IDs

&nbsp; - Bank account numbers

&nbsp; - Phishing links

&nbsp; - Phone numbers

&nbsp; - Scam keywords

\- Maintains conversation memory across messages

\- Disengages cleanly after sufficient intelligence is gathered

\- Never alerts the scammer that detection has occurred



---



\## 🧠 Core Design Philosophy



\- Accuracy > Cleverness  

\- Consistency > Creativity  

\- False positives are heavily penalized  

\- Legitimate bank alerts must NEVER be flagged  

\- Scam detection is progressive and evidence-based  



This is \*\*not a chatbot\*\* and \*\*not a simple classifier\*\*.  

It is an \*\*autonomous agent\*\* designed to waste scammer time while gathering evidence.



---



\## 🏗️ Architecture Overview



```

Client (SMS / API)

&nbsp;       |

&nbsp;       v

FastAPI (/api/v1/detect)

&nbsp;       |

&nbsp;       v

AgentEngine (Gemini 2.0 Flash)

&nbsp;       |

&nbsp;       v

Structured Decision (JSON)

&nbsp;       |

&nbsp;       +--> Client Response

&nbsp;       |

&nbsp;       +--> GUVI Callback (on FINISHED)

```



---



\## 🧩 Key Components



\### `main.py`

\- FastAPI application

\- API key validation

\- Request / response formatting

\- Background callback execution



\### `agent\_engine.py`

\- Core agent logic

\- Persona selection \& locking

\- Progressive scam detection

\- Intelligence extraction

\- Stop / disengage logic

\- LLM-failure safe fallback



\### `callback\_service.py`

\- Sends final results to GUVI’s evaluation endpoint

\- Runs asynchronously to avoid blocking API responses



\### `Procfile`

\- Production startup command for Render deployment



---



\## 📡 API Endpoint



\### `POST /api/v1/detect`



\#### Request Body (Example)



```json

{

&nbsp; "sessionId": "example-session-001",

&nbsp; "message": {

&nbsp;   "sender": "scammer",

&nbsp;   "text": "Your account is blocked. Pay ₹1 to verify.pay@okaxis immediately.",

&nbsp;   "timestamp": "2026-02-01T18:30:00Z"

&nbsp; },

&nbsp; "conversationHistory": \[],

&nbsp; "metadata": {

&nbsp;   "channel": "SMS",

&nbsp;   "language": "English",

&nbsp;   "locale": "IN"

&nbsp; }

}

```



---



\#### Response Body (Example)



```json

{

&nbsp; "status": "success",

&nbsp; "scamDetected": true,

&nbsp; "engagementMetrics": {

&nbsp;   "engagementDurationSeconds": 15,

&nbsp;   "totalMessagesExchanged": 1

&nbsp; },

&nbsp; "extractedIntelligence": {

&nbsp;   "upiIds": \["verify.pay@okaxis"],

&nbsp;   "bankAccounts": \[],

&nbsp;   "phishingLinks": \[],

&nbsp;   "phoneNumbers": \[],

&nbsp;   "suspiciousKeywords": \["blocked", "verify"]

&nbsp; },

&nbsp; "agentNotes": "Persona: Confused Senior. Scam tactic: Urgency and UPI payment request. Delaying to extract intelligence."

}

```



---



\## ✅ Legit Message Handling (False-Positive Safe)



The agent explicitly whitelists legitimate messages such as:

\- Bank debit / credit alerts

\- Informational OTP messages

\- Non-interactive transactional alerts



Example that must NOT be flagged:



```

HDFC Bank Alert: Rs 4,850 debited at Amazon. If not you, contact customer care.

```



---



\## 🔐 Environment Variables



These are \*\*NOT committed to GitHub\*\*.



```

GOOGLE\_API\_KEY=your\_gemini\_api\_key

API\_SECRET=guvi\_hackathon\_secret\_123

PORT=8000

```



Environment variables are configured directly in \*\*Render Dashboard\*\*.



---



\## ☁️ Deployment



\- Platform: Render

\- Server: Uvicorn

\- Model: Gemini 2.0 Flash



\*\*Procfile\*\*

```

web: uvicorn main:app --host 0.0.0.0 --port $PORT

```



---



\## 🧪 Testing



The repository includes test scripts covering:

\- Scam vs legit detection

\- Persona consistency

\- Memory handling

\- Multi-turn extraction

\- LLM availability fallback



---



\## 🏁 Final Notes



\- Designed to match real-world scam behavior

\- Outputs are strictly structured for judge evaluation

\- Conservative behavior when uncertain

\- All GUVI hackathon requirements are explicitly addressed



---



\### 👤 Author

\*\*Rounak Deb\*\*  

Agentic Honeypot – GUVI Hackathon Submission



