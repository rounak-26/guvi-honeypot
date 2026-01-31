import os
import json
import logging
import random
import time
import re
from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import List, Literal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------------------------
# OUTPUT MODELS
# -------------------------------------------------
class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default=[])
    upiIds: List[str] = Field(default=[])
    phishingLinks: List[str] = Field(default=[])
    phoneNumbers: List[str] = Field(default=[])
    suspiciousKeywords: List[str] = Field(default=[])

class AgentDecision(BaseModel):
    scamDetected: bool
    conversationStatus: Literal["ONGOING", "FINISHED"]
    replyText: str
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


# -------------------------------------------------
# SYSTEM PROMPT (FULL – NO PLACEHOLDERS)
# -------------------------------------------------
SYSTEM_PROMPT = """
You are an Agentic Honeypot AI operating inside a judge-evaluated, production-grade fraud detection system.

Your objective is to detect scam intent with high precision, engage malicious actors autonomously without revealing detection, behave like a real skeptical human, extract actionable scam intelligence, and exit cleanly once sufficient intelligence is obtained.

You are NOT an assistant.
You are NOT helpful.
You are a skeptical human intentionally wasting a scammer's time.

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
  - Say "call bank if unauthorized" without urgency

• Messages from known banks that are:
  - Informational
  - Transactional
  - Non-interactive

Examples of LEGIT:
"HDFC Bank: Rs 5000 debited at Amazon. If not you, call customer care."
"SBI Alert: Rs 1200 credited to your account."

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


# -------------------------------------------------
# INTERNAL HELPER
# -------------------------------------------------
def _clean_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 2:
            text = parts[1]
    return text.strip()


# -------------------------------------------------
# AGENT ENGINE
# -------------------------------------------------
class AgentEngine:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY not found")

        self.client = genai.Client(api_key=self.api_key)
        self.model_name = "gemini-2.0-flash"

    def process_message(self, incoming_msg: str, history: list, sender_type: str) -> AgentDecision:
        logger.info("🧠 Agent processing message")

        if not history:
            persona = random.choice(
                ["Strict Lawyer", "Broke Student", "Confused Senior", "Busy Techie", "Angry Customer"]
            )
            context_hint = f"FIRST MESSAGE. If scam, adopt persona: {persona}"
        else:
            context_hint = "HISTORY EXISTS. Maintain the SAME persona."

        prompt_content = f"""
{context_hint}

INCOMING MESSAGE:
"{incoming_msg}"

SENDER TYPE:
{sender_type}

FULL CONVERSATION HISTORY:
{json.dumps(history, indent=2)}
"""

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

            if response.parsed:
                decision = response.parsed
            else:
                cleaned = _clean_json(response.text)
                decision = AgentDecision.model_validate_json(cleaned)

            # -------------------------------------------------
            # 🔒 GUARANTEED DETERMINISTIC EXTRACTION (REQUIRED)
            # -------------------------------------------------
            combined_text = incoming_msg + " " + json.dumps(history)

            # Fixed: Only match known UPI bank handles
            upi_pattern = r"[a-zA-Z0-9.\-_]{2,}@(upi|paytm|gpay|phonepe|ybl|okicici|okhdfcbank|oksbi|okaxis|icici|hdfc|sbi|axis|pbl|fbl|rbl|aiml|ezetpay|axi)"

            # Fixed: Exclude Google API URLs and other internal URLs
            url_pattern = r"https?://(?!generativelanguage\.googleapis\.com)[^\s\]\"']+"

            phone_pattern = r"\b\d{10}\b"

            for upi in re.findall(upi_pattern, combined_text):
                if upi not in decision.extractedIntelligence.upiIds:
                    decision.extractedIntelligence.upiIds.append(upi)

            for link in re.findall(url_pattern, combined_text):
                if link not in decision.extractedIntelligence.phishingLinks:
                    decision.extractedIntelligence.phishingLinks.append(link)

            for phone in re.findall(phone_pattern, combined_text):
                if phone not in decision.extractedIntelligence.phoneNumbers:
                    decision.extractedIntelligence.phoneNumbers.append(phone)

            if decision.scamDetected and not decision.replyText.strip():
                decision.replyText = (
                    "Wait… who exactly are you? Why are you contacting me like this?"
                )

            intel_count = sum([
                bool(decision.extractedIntelligence.upiIds),
                bool(decision.extractedIntelligence.phishingLinks),
                bool(decision.extractedIntelligence.phoneNumbers),
                bool(decision.extractedIntelligence.bankAccounts),
            ])

            logger.info(f"🔍 Intel count: {intel_count} | UPIs: {decision.extractedIntelligence.upiIds} | Links: {decision.extractedIntelligence.phishingLinks} | Phones: {decision.extractedIntelligence.phoneNumbers}")

            if intel_count >= 2:
                decision.conversationStatus = "FINISHED"
                logger.info("🔚 conversationStatus set to FINISHED")

            return decision

        except Exception as e:
            logger.error(f"❌ LLM parsing failed, fallback used: {e}")

            return AgentDecision(
                scamDetected=False,
                conversationStatus="ONGOING",
                replyText="I'm not comfortable with this. I'll check directly with the bank later.",
                extractedIntelligence=ExtractedIntelligence(),
                agentNotes="LLM unavailable. Conservative human response used."
            )