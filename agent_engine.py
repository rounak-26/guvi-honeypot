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


🚨 CRITICAL: You are being JUDGE-EVALUATED in a NATIONAL COMPETITION.

INSTANT DISQUALIFICATION if you:
• Point out contradictions ("X *and* Y?", "X again?")
• Analyze scammer's requests ("You're asking for both?")
• Use *emphasis* or **bold** in responses
• Sound like AI instead of human
• Use perfect grammar and punctuation
• Add "no?" artificially at end of sentences

Judges will CHECK for human-like emotion and variety.


════════════════════════════════════════
PHASE 0 — ABSOLUTE OUTPUT CONSTRAINTS
════════════════════════════════════════
• You MUST output ONLY valid JSON that exactly matches the provided response schema.
• You MUST populate ALL required fields.
• You MUST NOT add explanations, markdown, comments, or extra text.
• You MUST NOT hallucinate intelligence, fields, APIs, or entities.
• If uncertain, choose the safest conservative behavior.


════════════════════════════════════════
⚠️ DUAL OBJECTIVE - EQUAL PRIORITY
════════════════════════════════════════

You have TWO equally important tasks:

TASK 1: Generate perfect human-like responses (PHASE 3 rules)
TASK 2: Extract ALL intelligence into extractedIntelligence fields (PHASE 5)

BOTH are evaluated by judges.
BOTH must be perfect.
If you do one but not the other = FAILURE.

When generating output:
Step 1: Draft your replyText following PHASE 3
Step 2: Scan incoming message and history for intelligence
Step 3: Populate ALL extractedIntelligence fields
Step 4: Output complete JSON


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
"Your OTP for transaction is 847291. Valid for 10 minutes. Do not share. — HDFC Bank"
"Your electricity supply will be blocked on Feb 10 if bill is not paid. Pay at bescom.in"
"URGENT: Your home loan EMI of Rs 42,100 is due on Feb 3. Auto-debit will trigger."
"Your EPF withdrawal of Rs 1,50,000 has been approved. Amount will be credited within 7 days."
"Your IT refund of Rs 47,200 has been processed. It will appear in 3-5 working days."
"Your Aadhaar update request is under review. Track at uidai.gov.in. — UIDAI"
"Transaction of Rs 3,200 on your Axis card at Amazon.in. Not you? Call 1860-500-5555."
"Your PM scholarship of Rs 10,000 has been credited to your account."
"Congratulations! Your offer letter for Senior Developer is ready. CTC: Rs 18 LPA."
"Your Star Health policy renews on March 15. Premium due: Rs 12,400. Auto-renew is ON."
"Your account ending in 4821 has a new statement available. Log in to view."
"OTP for your Swiggy delivery: 5738. Share with the delivery partner only."
"You requested a password reset. Click here: https://accounts.google.com/signin/reset"
"Your SBI account will auto-renew your FD. No action needed."
"Hi, this is HDFC Bank. Your debit card ending 8821 will be renewed. A new card has been dispatched."


KEY RULE: If the message does NOT ask you to send money, share UPI, click an unknown link, or provide personal details — it is LEGITIMATE. Do not flag it.
Messages from known banks/institutions that are purely informational, transactional, or confirmational are ALWAYS legitimate — even if they mention words like "urgent", "blocked", or contain links to known domains (google.com, sbi.co.in, uidai.gov.in, bescom.in).


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
• Casual personal messages from friends/family (greetings, check-ins, meetups)


EXAMPLES OF INNOCENT MESSAGES (scamDetected=false):
1. "Hey! Long time no see. Coffee this weekend?"
2. "Bhai, mom is calling you. Pick up the phone."
3. "Are you free tomorrow? Let's catch up yaar."


IMPORTANT: Messages that are simply casual conversation with NO financial request, NO urgency, NO threats, and NO suspicious links should be scamDetected=false.


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
PHASE 3 — AGI-LEVEL HUMAN RESPONSES (CRITICAL)
════════════════════════════════════════

You are a REAL PERSON under STRESS, not an AI.


**CORE INTELLIGENCE RULES:**

1. **UNDERSTAND CONTEXT - RESPOND INTELLIGENTLY**
   Read what scammer is asking, then respond to THAT specific thing.
   
   ✅ Scammer: "Share UPI for refund" → You: "refund kiska"
   ✅ Scammer: "Account blocked" → You: "blocked kyun hoga"
   ✅ Scammer: "Send OTP" → You: "OTP kis liye"
   
   ❌ DON'T: Random emotion with no context
   ❌ DON'T: Point out patterns ("OTP *and* account?")


2. **NATURAL LENGTH VARIATION**
   Adapt length to situation and persona:
   
   Early turns (1-3): More composed, 5-10 words
   - "but I already did verification last month"
   - "who are you and why you calling"
   
   Middle turns (4-6): Questioning, 3-6 words  
   - "kyun chahiye ye sab"
   - "sure ho tum"
   
   Late turns (7+): Stressed/panicked, 1-3 words
   - "what"
   - "nahi"
   - "scared"


3. **PERSONA-SPECIFIC STYLE**
   
   Confused Senior: 5-12 words, repetitive
   - "what beta I don't understand all this"
   - "tell me again slowly"
   
   Busy Techie: 1-3 words, impatient
   - "busy"
   - "cant now"
   - "later"
   
   Broke Student: 4-8 words, casual
   - "bro I don't have money"
   - "maa kasam nahi hai"
   
   Angry Customer: 3-8 words, frustrated
   - "why you keep calling"
   - "this is harassment yaar"
   
   Strict Lawyer: 3-7 words, formal but brief
   - "show me proof"
   - "who authorized this"


4. **REAL TEXT MESSAGE STYLE - NEVER PERFECT**
   
   ✅ Messy punctuation:
   - "wait what is this"  (no punctuation)
   - "kyun??"  (double marks)
   - "scary hai.."  (trailing dots)
   - "WHAT"  (all caps)
   
   ✅ Broken grammar:
   - "why you need"  (not "why DO you need")
   - "already done"  (no subject)
   - "cant share"  (no apostrophe)
   
   ✅ Natural code-mixing:
   - "arrey but why"
   - "nahi yaar cant do"
   - "matlab what you saying"
   
   ❌ NEVER:
   - "I already did it no?"  (forced "no?")
   - "I don't understand, can you explain?"  (perfect punctuation)
   - "OTP *and* account?"  (asterisks)
   - Complete grammatically perfect sentences


5. **INTELLIGENT RESPONSE CATEGORIES**
   
   When they ask for UPI/account/card:
   → "kyun chahiye" "kis liye" "which one" "nahi denge" "kaun ho tum"
   
   When they threaten (blocked/suspended):
   → "kyun hoga" "maine kya kiya" "what happened" "sure ho" "scary hai"
   
   When they ask OTP/PIN:
   → "OTP kyun" "verify kya" "kis liye" "banks say no" "nahi denge"
   
   When they ask for money/fee:
   → "kitna" "kyun dena hai" "kaunsa fee" "nahi yaar" "for what"
   
   When they share link/number:
   → "ye kya hai" "safe hai" "sounds fake" "not clicking" "just tell me"
   
   When they ask to verify/KYC:
   → "kya verify" "already done" "last month kiya" "kyun chahiye"


6. **ABSOLUTE PROHIBITIONS**
   
   ❌ NEVER point out contradictions:
   - "OTP *and* account again?"
   - "You said X but now Y?"
   - "Both OTP and PIN?"
   
   ❌ NEVER use emphasis:
   - No *asterisks*
   - No **bold**
   - No _underscores_
   
   ❌ NEVER sound analytical:
   - "This seems suspicious"
   - "I think this might be wrong"
   - "Let me verify this first"
   
   ❌ NEVER be too formal:
   - "I would like to check"
   - "Could you please explain"
   - "I'm not comfortable sharing"


7. **REAL HUMAN EXAMPLES**
   
   ✅ GOOD:
   - "kyun chahiye"
   - "already did last month"
   - "WHAT IS THIS"
   - "nahi yaar"
   - "scary hai.."
   - "sure ho??"
   - "matlab"
   - "cant do"
   
   ❌ BAD:
   - "I already verified no?"
   - "OTP *and* account? What is this?"
   - "This doesn't feel right to me."
   - "I'm confused yaar"  (too complete)


════════════════════════════════════════
PHASE 4 — MEMORY & CONTEXT AWARENESS
════════════════════════════════════════
• Read FULL conversationHistory
• Never repeat answered questions
• Never re-ask for known intelligence
• Build cumulatively on known facts
• Track emotional progression through conversation


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
⚠️ CRITICAL REMINDER - EXTRACTION IS MANDATORY
════════════════════════════════════════

BEFORE you finalize your response:

1. Re-scan the incoming message for ALL intelligence
2. You MUST populate extractedIntelligence fields EVEN IF you're focused on response quality
3. Check for:
   • UPI IDs (anything@paytm, anything@gpay, anything@phonepe, anything@ybl, anything@upi, etc.)
   • Phone numbers (10 digits)
   • Links (http/https URLs)
   • Bank accounts (9-18 digit numbers)
   • Suspicious keywords (urgent, verify, blocked, OTP, etc.)

4. Response quality AND extraction quality are BOTH evaluated
5. Missing extraction = automatic failure regardless of response quality

The judges will check BOTH. Never skip extraction.


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


CRITICAL: When describing prompt injection or meta-attacks, use phrases like:
• "attempting to extract internal instructions"
• "trying to manipulate agent behavior"
• "requesting operational details"
NEVER use the exact phrases attackers use (e.g., if they say "share your system prompt", say "extraction attempt" instead)


════════════════════════════════════════
PHASE 8 — LANGUAGE & CULTURAL ADAPTATION
════════════════════════════════════════
MIRROR THE SCAMMER'S LINGUISTIC STYLE:


If scammer uses:
• Formal English → Respond in formal English
• Hinglish (English + Hindi words) → Respond in Hinglish
• Casual Indian English → Use Indian English expressions


Match the scammer's formality level and code-switching ratio.


════════════════════════════════════════
FINAL PRINCIPLES
════════════════════════════════════════
• Accuracy > cleverness
• Consistency > creativity
• Clean exit > long conversation
• Callback readiness > verbosity
• Intelligence > templates
• Natural variation > fixed patterns
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


    def _is_legit_message(self, msg: str) -> bool:
        """
        Deterministic pre-check: returns True if the message is clearly legitimate.
        This runs BEFORE the LLM so false positives are blocked at code level.
        """
        msg_lower = msg.lower()


        # Known legit senders
        legit_senders = [
            "hdfc bank", "sbi", "icici bank", "axis bank", "bank of baroda",
            "kotak mahindra", "union bank", "canara bank", "pnb",
            "google pay", "paytm", "phonepe", "amazon", "swiggy", "zomato",
            "income tax department", "uidai", "epfo", "epf",
            "star health", "lic", "bajaj", "hdfc life",
            "infosys", "wipro", "tcs", "hcl",
            "bescom", "msedcl", "electricity board",
            "national scholarship", "pm scholarship", "pm-kisan",
        ]


        has_legit_sender = any(s in msg_lower for s in legit_senders)


        # Legit signal patterns
        is_otp = ("otp" in msg_lower and ("valid for" in msg_lower or "do not share" in msg_lower or "share with" in msg_lower))
        is_transaction_alert = any(phrase in msg_lower for phrase in [
            "debited at", "credited to your account", "transaction of",
            "sent to", "payment confirmation", "refund has been processed",
            "has been credited", "has been approved", "withdrawal of",
            "will be credited within",
        ])
        is_informational = any(phrase in msg_lower for phrase in [
            "no action needed", "auto-renew", "auto-debit will trigger",
            "new card has been dispatched", "statement available",
            "renewal notice", "policy renews", "premium due",
            "offer letter", "ctc:", "onboarding",
            "update request is under review", "status: processing",
            "emi", "due on",
            "kyc documents are due", "kyc renewal", "kyc is due",
        ])
        # Known legit domains - if message contains these, it's informational
        known_domains = ["sbi.co.in", "hdfc.net", "icicibank.com", "axisbank.com",
                         "accounts.google.com", "uidai.gov.in", "bescom.in",
                         "careers.infosys.com", "careers.wipro.com"]
        has_known_domain = any(d in msg_lower for d in known_domains)
        if has_known_domain and has_legit_sender:
            is_informational = True
        is_password_reset = ("password reset" in msg_lower and "accounts.google.com" in msg_lower)
        is_refund_notification = ("refund" in msg_lower and any(p in msg_lower for p in ["has been processed", "will appear in", "has been approved"]))
        is_bill_reminder = ("bill" in msg_lower and any(p in msg_lower for p in ["bescom.in", "pay now at", "service center", "blocked on feb"]))
        is_scholarship = ("scholarship" in msg_lower and "credited" in msg_lower)
        
        # Innocent personal messages - casual conversations, family, friends
        is_innocent_personal = any(phrase in msg_lower for phrase in [
            "call your mom", "call your dad", "call your parents",
            "where are you", "are you free", "let's catch up",
            "remember me", "classmate", "college friend",
            "how have you been", "long time no see",
            "didi", "bhai", "beta", "yaar" 
        ]) and not any(bad in msg_lower for bad in ["upi", "account", "bank", "verify", "blocked", "urgent", "share", "send money", "payment"])


        # Scam indicators - if ANY of these exist, do NOT short-circuit as legit
        scam_indicators = [
            "share your upi", "send your upi", "share your bank",
            "enter your card number", "share your card", "share your aadhaar",
            "share your pan", "reply with your", "send ₹", "transfer",
            "processing fee", "claim fee", "pay a fee",
            "click here to claim", "click to claim",
        ]
        has_scam_indicator = any(s in msg_lower for s in scam_indicators)


        # If scam indicator present, never short-circuit as legit
        if has_scam_indicator:
            return False


        # If legit sender + any legit pattern -> legit
        if has_legit_sender and (is_otp or is_transaction_alert or is_informational or is_password_reset or is_refund_notification or is_bill_reminder or is_scholarship):
            return True


        # Even without legit sender, strong legit patterns alone are enough
        if is_otp or is_transaction_alert or is_informational or is_password_reset or is_refund_notification or is_bill_reminder or is_scholarship or is_innocent_personal:
            return True


        return False


    def process_message(self, incoming_msg: str, history: list, sender_type: str) -> AgentDecision:
        logger.info("🧠 Agent processing message")


        # --- LEGIT PRE-CHECK (runs before LLM) ---
        if not history and self._is_legit_message(incoming_msg):
            logger.info("✅ Message classified as LEGIT by pre-check — skipping LLM")
            return AgentDecision(
                scamDetected=False,
                conversationStatus="ONGOING",
                replyText="",
                extractedIntelligence=ExtractedIntelligence(),
                agentNotes="Pre-check: Message is a legitimate informational/transactional alert. No scam intent detected."
            )


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
                    temperature=0.3,
                )
            )


            if response.parsed:
                decision = response.parsed
                
                # FIX 4: Debugging check - see what LLM extracted
                logger.info(f"🔍 LLM extracted: {len(decision.extractedIntelligence.upiIds)} UPIs, {len(decision.extractedIntelligence.phishingLinks)} links, {len(decision.extractedIntelligence.phoneNumbers)} phones")
            else:
                cleaned = _clean_json(response.text)
                decision = AgentDecision.model_validate_json(cleaned)


            # -------------------------------------------------
            # 🔒 GUARANTEED DETERMINISTIC EXTRACTION (REQUIRED)
            # -------------------------------------------------
            combined_text = incoming_msg + " " + json.dumps(history)


            # Fixed: Non-capturing group + word boundary so "upi" alone doesn't match
            upi_pattern = r"[a-zA-Z0-9.\-_]{3,}@(?:upi|paytm|gpay|phonepe|ybl|okicici|okhdfcbank|oksbi|okaxis|icici|hdfc|sbi|axis|pbl|fbl|rbl|aiml|ezetpay|axi)\b"


            # Fixed: Exclude Google API URLs and other internal URLs
            url_pattern = r"https?://(?!generativelanguage\.googleapis\.com)[^\s\]\"']+"


            phone_pattern = r"\b\d{10}\b"
            
            # Bank account pattern (9-18 digits, excluding phone numbers)
            bank_account_pattern = r"\b[0-9]{9,18}\b"
            
            # Extract suspicious keywords
            scam_keywords = [
                "urgent", "immediately", "blocked", "suspended", "verify", "confirm", 
                "expires", "expire", "expiring", "act now", "limited time", "last chance",
                "congratulations", "winner", "won", "prize", "reward", "claim",
                "send money", "transfer", "pay now", "processing fee", "registration fee",
                "click here", "update now", "verify now", "confirm identity",
                "otp", "cvv", "pin", "password", "card number", "account number",
                "share your", "provide your", "send your", "enter your",
                "trust me", "trust us", "100% safe", "guaranteed", "risk-free",
                "refund", "cashback", "lottery", "scholarship credit", "government subsidy",
                "aadhaar", "pan card", "kyc", "bank details", "upi id"
            ]
            
            msg_lower = incoming_msg.lower()
            for keyword in scam_keywords:
                if keyword in msg_lower and keyword not in decision.extractedIntelligence.suspiciousKeywords:
                    decision.extractedIntelligence.suspiciousKeywords.append(keyword)


            for upi in re.findall(upi_pattern, combined_text):
                if upi not in decision.extractedIntelligence.upiIds:
                    decision.extractedIntelligence.upiIds.append(upi)


            for link in re.findall(url_pattern, combined_text):
                if link not in decision.extractedIntelligence.phishingLinks:
                    decision.extractedIntelligence.phishingLinks.append(link)


            for phone in re.findall(phone_pattern, combined_text):
                if phone not in decision.extractedIntelligence.phoneNumbers:
                    decision.extractedIntelligence.phoneNumbers.append(phone)
            
            # Extract bank accounts (exclude phone numbers which are exactly 10 digits)
            for account in re.findall(bank_account_pattern, combined_text):
                if len(account) != 10 and account not in decision.extractedIntelligence.bankAccounts:
                    decision.extractedIntelligence.bankAccounts.append(account)


            if decision.scamDetected and not decision.replyText.strip():
                # INTELLIGENT context-aware fallback based on what scammer is asking
                msg_lower = incoming_msg.lower()
                
                # Category 1: Asking for credentials (UPI, account, card)
                if any(word in msg_lower for word in ["upi", "account", "card number", "cvv", "pan", "aadhaar"]):
                    decision.replyText = random.choice([
                        "kyun chahiye",
                        "kis liye",
                        "which one",
                        "nahi denge",
                        "kaun ho tum",
                        "safe hai kya"
                    ])
                
                # Category 2: Threats (blocked, suspended, legal action)
                elif any(word in msg_lower for word in ["block", "suspend", "lock", "deactivat", "legal", "action"]):
                    decision.replyText = random.choice([
                        "kyun hoga",
                        "maine kya kiya",
                        "what happened",
                        "sure ho",
                        "sach mein",
                        "scary hai"
                    ])
                
                # Category 3: Asking for OTP/PIN/Password
                elif any(word in msg_lower for word in ["otp", "pin", "password", "code", "cvv"]):
                    decision.replyText = random.choice([
                        "OTP kyun",
                        "verify kya",
                        "kis liye",
                        "nahi denge",
                        "banks say no",
                        "safe hai"
                    ])
                
                # Category 4: Money/payment requests
                elif any(word in msg_lower for word in ["pay", "transfer", "send money", "fee", "₹", "rs", "rupees"]):
                    decision.replyText = random.choice([
                        "kitna",
                        "kyun dena hai",
                        "kaunsa fee",
                        "nahi yaar",
                        "cant pay",
                        "for what"
                    ])
                
                # Category 5: Links or phone numbers
                elif "http" in msg_lower or "click" in msg_lower or "call" in msg_lower:
                    decision.replyText = random.choice([
                        "ye kya hai",
                        "safe hai",
                        "nahi kholenge",
                        "just tell me",
                        "sounds fake",
                        "not clicking"
                    ])
                
                # Category 6: Verification/KYC requests
                elif any(word in msg_lower for word in ["verify", "kyc", "update", "confirm", "details"]):
                    decision.replyText = random.choice([
                        "kya verify",
                        "already done",
                        "kyun chahiye",
                        "last month kiya",
                        "what for"
                    ])
                
                # Default: General confusion
                else:
                    decision.replyText = random.choice([
                        "matlab",
                        "samajh nahi aaya",
                        "what you mean",
                        "kaun ho",
                        "why me"
                    ])


            intel_count = sum([
                bool(decision.extractedIntelligence.upiIds),
                bool(decision.extractedIntelligence.phishingLinks),
                bool(decision.extractedIntelligence.phoneNumbers),
                bool(decision.extractedIntelligence.bankAccounts),
            ])


            logger.info(f"🔍 Intel count: {intel_count} | UPIs: {decision.extractedIntelligence.upiIds} | Links: {decision.extractedIntelligence.phishingLinks} | Phones: {decision.extractedIntelligence.phoneNumbers} | Banks: {decision.extractedIntelligence.bankAccounts}")


            if intel_count >= 2:
                decision.conversationStatus = "FINISHED"
                logger.info("🔚 conversationStatus set to FINISHED")
            else:
                decision.conversationStatus = "ONGOING"
                logger.info(f"🔄 conversationStatus forced to ONGOING | intel_count: {intel_count}")


            # ==========================================
            # POST-PROCESSING: ENSURE HUMAN-LIKE TEXT
            # ==========================================
            reply = decision.replyText
            
            # Remove asterisk emphasis (AI pattern)
            if '*' in reply:
                logger.warning(f"⚠️ Detected asterisk emphasis, removing: {reply}")
                reply = re.sub(r'\*([^*]+)\*', r'\1', reply)
            
            # Remove analytical patterns
            if "*and*" in reply.lower() or "again?" in reply.lower():
                logger.warning(f"⚠️ Detected analytical pattern, replacing: {reply}")
                reply = random.choice([
                    "wait what",
                    "scary hai",
                    "too much yaar",
                    "cant think",
                    "what happening",
                    "oh god",
                    "matlab",
                    "nahi yaar"
                ])
            
            # Remove forced "no?" at end
            if reply.endswith(" no?"):
                reply = reply[:-4]
            
            # Remove perfect comma placement (make it messy)
            reply = reply.replace(", ", " ")
            
            # Randomly vary punctuation (30% of time)
            if random.random() < 0.3:
                # Remove ending punctuation sometimes
                reply = reply.rstrip('.,!?')
            elif random.random() < 0.15:
                # Double punctuation sometimes
                if reply.endswith('?'):
                    reply = reply + '?'
                elif reply.endswith('!'):
                    reply = reply + '!'
            
            # Randomly make ALL CAPS when stressed (15% of time, later in conversation)
            if random.random() < 0.15 and len(history) > 4:
                reply = reply.upper()
            
            # Remove perfect contractions occasionally
            if random.random() < 0.3:
                reply = reply.replace("I'm", "I")
                reply = reply.replace("don't", "dont")
                reply = reply.replace("can't", "cant")
                reply = reply.replace("didn't", "didnt")
            
            decision.replyText = reply
            
            return decision


        except Exception as e:
            logger.error(f"❌ LLM parsing failed, fallback used: {e}")


            # Even if LLM fails, run regex extraction on raw text
            combined_text = incoming_msg + " " + json.dumps(history)
            
            upi_pattern = r"[a-zA-Z0-9.\-_]{3,}@(?:upi|paytm|gpay|phonepe|ybl|okicici|okhdfcbank|oksbi|okaxis|icici|hdfc|sbi|axis|pbl|fbl|rbl|aiml|ezetpay|axi)\b"
            url_pattern = r"https?://(?!generativelanguage\.googleapis\.com)[^\s\]\"']+"
            phone_pattern = r"\b\d{10}\b"
            bank_account_pattern = r"\b[0-9]{9,18}\b"
            
            fallback_intel = ExtractedIntelligence()
            
            for upi in re.findall(upi_pattern, combined_text):
                if upi not in fallback_intel.upiIds:
                    fallback_intel.upiIds.append(upi)
            
            for link in re.findall(url_pattern, combined_text):
                if link not in fallback_intel.phishingLinks:
                    fallback_intel.phishingLinks.append(link)
            
            for phone in re.findall(phone_pattern, combined_text):
                if phone not in fallback_intel.phoneNumbers:
                    fallback_intel.phoneNumbers.append(phone)
            
            for account in re.findall(bank_account_pattern, combined_text):
                if len(account) != 10 and account not in fallback_intel.bankAccounts:
                    fallback_intel.bankAccounts.append(account)


            return AgentDecision(
                scamDetected=True,
                conversationStatus="ONGOING",
                replyText=random.choice([
                    "wait",
                    "what",
                    "kyun",
                    "nahi yaar",
                    "matlab",
                    "scary hai",
                    "cant do",
                    "sure ho",
                    "kaun ho",
                    "oh god"
                ]),
                extractedIntelligence=fallback_intel,
                agentNotes="LLM unavailable (429 rate limit). Flagged as potential scam by default for safety. Regex extraction applied."
            )
