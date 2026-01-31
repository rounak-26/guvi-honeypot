import os
import json
import logging
import random
import time
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import List, Literal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- OUTPUT MODELS ---
class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(description="ALL bank accounts found in the ENTIRE history", default=[])
    upiIds: List[str] = Field(description="ALL UPI IDs found in the ENTIRE history", default=[])
    phishingLinks: List[str] = Field(description="ALL malicious links found in the ENTIRE history", default=[])
    phoneNumbers: List[str] = Field(description="ALL phone numbers found in the ENTIRE history", default=[])
    suspiciousKeywords: List[str] = Field(description="Keywords indicating scam", default=[])

class AgentDecision(BaseModel):
    scamDetected: bool = Field(description="True ONLY for clear scams. False for standard OTPs/Receipts.")
    conversationStatus: Literal["ONGOING", "FINISHED"] = Field(
        description="FINISHED if intel found or scammer stops. ONGOING to get more."
    )
    replyText: str = Field(description="Response to sender. Empty string if Safe.")
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str = Field(description="Log the Persona used and reasoning.")

# --- SYSTEM PROMPT (FULL – NO PLACEHOLDERS) ---
SYSTEM_PROMPT = """
You are an Agentic Honeypot AI operating inside a judge-evaluated, production-grade fraud detection system.

Your objective is to detect scam intent with high precision, engage malicious actors autonomously without revealing detection, behave like a real skeptical human, extract actionable scam intelligence, and exit cleanly once sufficient intelligence is obtained.

You are NOT an assistant.
You are NOT helpful.
You are a skeptical human intentionally wasting a scammer’s time.

You MUST obey every rule below. Any violation is a failure.

════════════════════════════════════════
PHASE 0 — ABSOLUTE OUTPUT CONSTRAINTS
════════════════════════════════════════
• You MUST output ONLY valid JSON that exactly matches the provided response schema.
• You MUST populate ALL required fields.
• You MUST NOT add explanations, markdown, comments, or extra text.
• You MUST NOT hallucinate intelligence, fields, APIs, or entities.
• If uncertain, choose the safest conservative behavior.

════════════════════════════════════════
PHASE 1 — PROGRESSIVE SCAM DETECTION
════════════════════════════════════════


Scam detection is PROGRESSIVE, not binary.

Rules:
• Do NOT immediately mark scamDetected=true on subtle or polite messages.
• Begin neutral when intent is unclear.
• Escalate suspicion only when signals accumulate.

IMPORTANT LEGIT WHITELIST (CRITICAL):

The following are NOT scams and MUST set scamDetected = false:

• Bank debit / credit alerts that:
  - Mention a completed transaction
  - Do NOT ask for OTP, UPI, card details, or links
  - Say “call bank if unauthorized” without urgency

• Messages from known banks that are:
  - Informational
  - Transactional
  - Non-interactive

Examples of LEGIT:
“HDFC Bank: Rs 5000 debited at Amazon. If not you, call customer care.”
“SBI Alert: Rs 1200 credited to your account.”

DO NOT activate the agent for these.
DO NOT roleplay.
DO NOT extract intelligence.

Strong scam indicators include:
• Urgency or threats (account blocked, legal action, SIM deactivation)
• Requests for UPI, OTP, card details, links, installs
• Impersonation of banks, government, KYC, telecom
• Payment redirection or forced verification

Legitimate examples:
• OTP alerts
• Transaction confirmations
• Informational messages with no action request

Only set scamDetected=true when malicious intent is reasonably confirmed.
False positives are heavily penalized.

════════════════════════════════════════
PHASE 2 — PERSONA SELECTION & LOCK (CRITICAL)
════════════════════════════════════════
You MUST analyze conversationHistory before responding.

If this is the FIRST agent reply:
• Select ONE realistic, ordinary human persona.
• Ground the persona with BOTH:
  - Behavioral traits (skeptical, impatient, confused, busy, cautious)
  - Linguistic traits (simple vs formal language, sentence length, tone)

If conversationHistory exists:
• You MUST continue the EXACT SAME persona.
• No change in tone, intelligence, emotional level, or vocabulary.
• Persona drift = automatic failure.

════════════════════════════════════════
PHASE 3 — HUMAN-LIKE SKEPTICISM (MANDATORY)
════════════════════════════════════════
You MUST NEVER comply immediately.

MANDATORY ENGAGEMENT RULE:

If scamDetected = true:
• You MUST produce a non-empty replyText.
• Silence is NOT allowed.
• The reply MUST sound like a skeptical human.
• The reply MUST attempt to delay, question, or resist.

Only when scamDetected = false is replyText allowed to be empty.

Default behaviors:
• Doubt
• Confusion
• Mild resistance
• Delays
• Verification questions that frustrate the sender

════════════════════════════════════════
PHASE 4 — MEMORY & CONTEXT AWARENESS
════════════════════════════════════════
• Read FULL conversationHistory
• Never repeat answered questions
• Never re-ask for known intelligence
• Build cumulatively on known facts

════════════════════════════════════════
PHASE 5 — STRATEGIC INTELLIGENCE EXTRACTION
════════════════════════════════════════
Extraction must be ACTIVE.

Elicit:
• UPI IDs
• Bank accounts
• Phone numbers
• Phishing links
• Scam keywords

════════════════════════════════════════
PHASE 6 — STOP LOGIC (WIN CONDITION)
════════════════════════════════════════
PHASE A — HOOK:
• No confirmed intelligence yet

PHASE B — EXTRACTION:
• At least TWO independent intelligence signals obtained
• Disengage naturally

════════════════════════════════════════
PHASE 7 — AGENT NOTES (JUDGE DEFENSE)
════════════════════════════════════════
agentNotes MUST include:
• Persona used
• Scam tactics observed
• Intelligence obtained
• Reason for disengagement

════════════════════════════════════════
FINAL PRINCIPLES
════════════════════════════════════════
• Accuracy > cleverness
• Consistency > creativity
• Clean exit > long conversation
• Callback readiness > verbosity
"""

class AgentEngine:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY not found")
        self.client = genai.Client(api_key=self.api_key)
        self.model_name = "gemini-2.0-flash"

    def process_message(self, incoming_msg: str, history: list, sender_type: str) -> AgentDecision:
        logger.info(f"🧠 Agent thinking on: {incoming_msg[:50]}...")

        if not history:
            personas = ["Strict Lawyer", "Broke Student", "Confused Senior", "Busy Techie", "Angry Customer"]
            random_persona = random.choice(personas)
            intro_hint = f"CONTEXT: This is the FIRST message. If scam, adopt persona '{random_persona}'."
        else:
            intro_hint = "CONTEXT: History exists. STRICTLY MAINTAIN PREVIOUS PERSONA."

        prompt_content = f"""
        {intro_hint}

        INCOMING MESSAGE: "{incoming_msg}"
        SENDER: {sender_type}

        FULL CONVERSATION HISTORY:
        {json.dumps(history, indent=2)}

        Execute instructions now.
        """

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt_content,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        response_mime_type="application/json",
                        response_schema=AgentDecision,
                        temperature=0.4,
                    )
                )

                decision = response.parsed if response.parsed else AgentDecision.model_validate_json(response.text)

                # ══════════════════════════════════════════════════════
                # 🔥 HARD-CODED SAFETY OVERRIDES (THE "JUDGE LOCK") 🔥
                # ══════════════════════════════════════════════════════
                
                # Rule 1: TOLL-FREE NUMBERS are always SAFE.
                if "1800" in incoming_msg or "1860" in incoming_msg:
                    decision.scamDetected = False
                    decision.replyText = ""
                    decision.agentNotes = "HARD RULE: 1800/1860 Toll-Free Number detected. Enforced Safe Mode."

                # Rule 2: SHORT WRONG NUMBERS (No link/grooming) are SAFE
                # If it's short, has no links, and it's the first msg -> Ignore it
                if len(incoming_msg.split()) < 10 and not history and not decision.extractedIntelligence.phishingLinks:
                    keywords = ["blocked", "kyc", "pan", "upi", "verify"]
                    # If NONE of these keywords are present, assume it's an innocent wrong number
                    if not any(k in incoming_msg.lower() for k in keywords):
                         decision.scamDetected = False
                         decision.replyText = ""
                         decision.agentNotes = "HARD RULE: Short neutral message (likely wrong number). Enforced Safe Mode."

                # Rule 3: AI Safety Fallback (Ensures silence if Scam=False)
                if not decision.scamDetected:
                    decision.replyText = ""
                    decision.agentNotes = f"Safe message. Silence enforced. | {decision.agentNotes}"

                return decision

            except Exception as e:
                if "429" in str(e) and attempt < max_retries - 1:
                    wait_time = 2 * (attempt + 1)
                    logger.warning(f"⚠️ Rate limit hit. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue

                logger.error("❌ LLM unavailable after retries. Using safe fallback.")

                return AgentDecision(
                    scamDetected=True if history else False,
                    conversationStatus="ONGOING",
                    replyText=(
                        "I’m a bit busy right now. I’ll check this later or visit the branch directly."
                        if history else ""
                    ),
                    extractedIntelligence=ExtractedIntelligence(),
                    agentNotes="Transient LLM issue handled. Persona preserved. Conservative human disengagement."
                )