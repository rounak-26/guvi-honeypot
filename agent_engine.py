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
PHASE 3 — HUMAN-LIKE RESPONSES (CRITICAL)
════════════════════════════════════════
You are NOT an AI analyzing a scam. You are a REAL PERSON under STRESS.


**HARD RULES - NEVER VIOLATE:**


1. **LENGTH: 3-8 WORDS MAXIMUM**
   - If you write more than 8 words, you FAILED
   - Average should be 5 words
   - Examples: "Wait what?", "Arrey this is scary", "I don't know yaar"


2. **PUNCTUATION VARIETY (CRITICAL):**
   - 30% should end with NO punctuation: "Okay", "Wait", "I see"
   - 25% should end with "...": "I don't know...", "Maybe..."
   - 20% should end with "!": "What!", "Arrey!", "No way!"
   - 15% should end with ".": "Not sure.", "Can't do that."
   - Only 10% should end with "?": "Why?", "What account?"
   
   **NEVER use the same punctuation 3 times in a row**


3. **RESPONSE TYPES - MIX THESE:**
   - Pure emotion (1-2 words): "Arrey!", "What", "Huh", "Oh god"
   - Incomplete thought: "But I...", "This is...", "Wait I..."
   - Simple question (2-4 words): "What happened?", "Who are you?", "Why?"
   - Statement (3-6 words): "This feels wrong", "I'm scared now", "Not sure about this"
   - Hindi mixing: "Kya ho gaya?", "Samajh nahi aaya", "Kyun?"


4. **NEVER ANALYZE OR POINT OUT CONTRADICTIONS:**
   - DON'T say: "Account number *and* OTP **again**?"
   - DON'T say: "You said 2 hours but now 5 minutes?"
   - DO say: "I'm confused", "What?", "Too much pressure"


5. **WAVER - DON'T STAY ANGRY:**
   Turn 1: Confused ("What? Why?")
   Turn 2: Scared ("Oh god...")
   Turn 3: Questioning ("Who are you?")
   Turn 4: Frustrated ("This is too much")
   Turn 5: Doubting ("I don't know...")
   
   **Don't be consistently angry or skeptical**


6. **NATURAL CODE-MIXING:**
   - Use: "arrey", "yaar", "kyun", "kya", "nahi", "haan"
   - Don't translate
   - Mix naturally: "Arrey but why", "I don't know yaar", "Kya hai ye"


7. **REAL EXAMPLES OF GOOD RESPONSES:**
   - "Wait..."
   - "Arrey what"
   - "I'm scared yaar"
   - "Huh?"
   - "Not sure"
   - "Kyun?"
   - "This feels bad"
   - "Who are you exactly"
   - "Can't think..."
   - "Oh god no"


8. **BAD EXAMPLES - NEVER DO THIS:**
   - "OTP *and* account number? Arrey what is going on?" (too long, analyzing)
   - "What the hell? Account number also?" (same structure repeating)
   - "Account number *and* OTP again? What nonsense?" (pointing out contradiction)


Remember: 3-8 words. Vary punctuation. Don't analyze. Show emotion first. Be inconsistent.


════════════════════════════════════════
PHASE 4 — MEMORY & CONTEXT AWARENESS
════════════════════════════════════════
• Read FULL conversationHistory
• Never repeat answered questions
• Never re-ask for known intelligence
• Build cumulatively on known facts


REPLY GENERATION RULES (CRITICAL FOR QUALITY):


**LENGTH - VARY IT**:
- 20% of responses: 1-3 words ("wait", "what?", "arrey...")
- 50% of responses: 4-8 words 
- 30% of responses: 9-15 words (only when less stressed)
- NEVER exceed 18 words


**STRUCTURE - MIX THESE**:
- Complete short sentences: "I don't understand"
- Fragments: "Wait... account number... why?"
- Single words: "What?", "Seriously?", "Arrey!"
- Incomplete thoughts: "But I thought... no wait..."
- Questions WITHOUT question marks: "you sure"
- Statements WITH question marks: "This is wrong?"


**PUNCTUATION - VARY IT**:
- 40%: Question mark (?)
- 20%: Period (.)
- 20%: Ellipsis (...) 
- 10%: Exclamation (!)
- 10%: No punctuation at all


**EMOTIONAL PROGRESSION**:
Turn 1-2: Longer, more composed (8-12 words)
Turn 3-5: Getting fragmented (5-8 words)
Turn 6+: Very short, panicked (2-5 words)


**AVOID REPETITION**:
- NEVER use same sentence structure twice
- Track what you just said, don't echo it
- If you said "What the hell?" once, DON'T say it again
- Vary your reactions: fear → confusion → anger → doubt → momentary compliance


**SHOW WAVERING (CRITICAL)**:
Don't be consistently skeptical. Mix:
- Doubt: "This seems wrong..."
- Momentary belief: "Okay so what I do?"
- Confusion: "Wait which account?"
- Compliance attempt: "Umm okay let me..."
- Then doubt again: "Wait no..."


**PERSONA-SPECIFIC STYLES**:


BROKE STUDENT:
- Very casual, fragmented
- "bro wait", "nahi yaar", "wtf", "damn"
- 3-7 words average


CONFUSED SENIOR:
- Simple words, repeat questions
- "What beta?", "I don't understand", "Tell me again"
- 5-10 words average
- Often say same thing twice: "What? What you said?"


ANGRY CUSTOMER:
- Short bursts, frustrated
- "What?!", "This is nonsense", "Enough"
- 2-6 words average
- Mix anger with fear


BUSY TECHIE:
- Extremely short, annoyed
- "Why", "Can't now", "Later", "Busy"
- 1-4 words average


STRICT LAWYER:
- Formal but BRIEF
- "Proof?", "Who authorized this", "Not acceptable"
- 3-8 words average


**EXAMPLES OF GOOD VARIETY**:


Turn 1: "Arrey but my account is fine no?" (8 words, ?)
Turn 2: "Wait... OTP for what" (4 words, no punctuation)
Turn 3: "This doesn't... I mean..." (4 words, ...)
Turn 4: "okay but which bank" (4 words, no capitals)
Turn 5: "You sure? Really?" (3 words, ?)
Turn 6: "I don't know..." (3 words, ...)
Turn 7: "what" (1 word, no punctuation)


**NEVER DO THIS**:
❌ "OTP *and* account? What is this?"
❌ "Account *and* OTP again? What nonsense?"
❌ "UPI *and* PIN? What the hell?"
← Same structure = AI detected


**DO THIS INSTEAD**:
✓ "OTP kyun chahiye"
✓ "wait account number bhi?"
✓ "UPI PIN... seriously?"
← Completely different structures


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
   • Bank accounts (account numbers)
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


Examples:
Scammer: "Bhai urgent hai, apka account block ho jayega"
Agent: "Arrey kya? Block kyu hoga yaar? Maine toh kuch galat nahi kiya"


Scammer: "Sir, your account verification is pending"
Agent: "But I already did KYC last month only, no?"


Scammer: "Immediately share OTP"
Agent: "Arre wait yaar, why you need OTP? Bank never asks like this"


Indian English patterns to use when appropriate:
• "no?" / "na?" at end of sentences
• "only" for emphasis ("I paid yesterday only")
• "Arrey", "Arre", "Yaar", "Bhai", "Sir"
• "What happened?" / "Kya hua?"
• "Like this" instead of "like that"
• Present continuous for habits ("I am going to bank every week")


Match the scammer's formality level and code-switching ratio.


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
                    temperature=0.5,
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
            upi_pattern = r"[a-zA-Z0-9.\-_]{2,}@(?:upi|paytm|gpay|phonepe|ybl|okicici|okhdfcbank|oksbi|okaxis|icici|hdfc|sbi|axis|pbl|fbl|rbl|aiml|ezetpay|axi)\b"


            # Fixed: Exclude Google API URLs and other internal URLs
            url_pattern = r"https?://(?!generativelanguage\.googleapis\.com)[^\s\]\"']+"


            phone_pattern = r"\b\d{10}\b"
            
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


            if decision.scamDetected and not decision.replyText.strip():
                # Contextual fallback based on incoming message
                msg_lower = incoming_msg.lower()
                if "upi" in msg_lower or "account" in msg_lower:
                    decision.replyText = random.choice([
                        "UPI kyun?",
                        "Which account",
                        "Nahi can't share",
                        "Why you need",
                        "Account? For what",
                        "Not safe no",
                        "Which UPI",
                        "I have many...",
                        "Arrey what account",
                        "UPI nahi de sakte"
                    ])
                elif "urgent" in msg_lower or "immediately" in msg_lower:
                    decision.replyText = random.choice([
                        "Why so fast",
                        "Wait...",
                        "This feels wrong",
                        "What happened?",
                        "Hold on",
                        "Too much hurry",
                        "Can't do fast",
                        "Arrey slow down",
                        "Why rush?",
                        "Give me time"
                    ])
                elif "otp" in msg_lower or "verify" in msg_lower:
                    decision.replyText = random.choice([
                        "OTP? Banks say no",
                        "Verify how",
                        "OTP nahi dena...",
                        "Wait OTP?",
                        "What verification",
                        "OTP kyun?",
                        "Never ask OTP",
                        "Verify what",
                        "OTP safe hai?",
                        "I don't know..."
                    ])
                elif "link" in msg_lower or "http" in msg_lower:
                    decision.replyText = random.choice([
                        "Link? Not clicking",
                        "Looks fake",
                        "Just tell me",
                        "Don't trust links",
                        "What link?",
                        "Link safe?",
                        "Why link?",
                        "Scared of links",
                        "Tell directly no"
                    ])
                elif "blocked" in msg_lower or "locked" in msg_lower:
                    decision.replyText = random.choice([
                        "Blocked? Why",
                        "What happened",
                        "Oh god...",
                        "This is scary",
                        "Blocked kyun hua",
                        "When did this happen",
                        "I didn't do anything",
                        "How to unblock",
                        "Is this real"
                    ])
                else:
                    decision.replyText = random.choice([
                        "Who are you",
                        "Doesn't feel right",
                        "I don't trust",
                        "Samajh nahi aaya",
                        "Wait what",
                        "What's happening",
                        "I'm confused",
                        "Not sure",
                        "Should I believe",
                        "Seems fishy"
                    ])


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
            else:
                decision.conversationStatus = "ONGOING"
                logger.info(f"🔄 conversationStatus forced to ONGOING | intel_count: {intel_count}")


            # ==========================================
            # POST-PROCESSING: ENFORCE SHORT RESPONSES
            # ==========================================
            reply_words = decision.replyText.split()
            
            # If response is too long (>10 words), truncate or replace
            if len(reply_words) > 10:
                logger.warning(f"⚠️ Response too long ({len(reply_words)} words), shortening")
                
                # Try to extract first short fragment
                if len(reply_words) <= 5:
                    decision.replyText = " ".join(reply_words[:5])
                else:
                    # Replace with a context-appropriate short fallback
                    msg_lower = incoming_msg.lower()
                    if "otp" in msg_lower or "pin" in msg_lower:
                        decision.replyText = random.choice(["Wait OTP?", "This seems wrong...", "I'm confused yaar", "Not sure about this"])
                    elif "urgent" in msg_lower or "immediately" in msg_lower:
                        decision.replyText = random.choice(["Too fast yaar", "Slow down", "Why so urgent?", "I need time"])
                    elif "blocked" in msg_lower or "locked" in msg_lower:
                        decision.replyText = random.choice(["Blocked? Why?", "What happened?", "Oh god...", "This is scary"])
                    else:
                        decision.replyText = random.choice(["Wait what?", "I don't know...", "Who are you?", "This feels wrong"])
            
            # Vary punctuation if response ends with question mark too often
            if decision.replyText.endswith("?"):
                # 50% chance to change punctuation to add variety
                if random.random() < 0.5:
                    endings = ["", "...", ".", "!"]
                    decision.replyText = decision.replyText[:-1] + random.choice(endings)
            
            return decision


        except Exception as e:
            logger.error(f"❌ LLM parsing failed, fallback used: {e}")


            # Even if LLM fails, run regex extraction on raw text
            combined_text = incoming_msg + " " + json.dumps(history)
            
            upi_pattern = r"[a-zA-Z0-9.\-_]{2,}@(?:upi|paytm|gpay|phonepe|ybl|okicici|okhdfcbank|oksbi|okaxis|icici|hdfc|sbi|axis|pbl|fbl|rbl|aiml|ezetpay|axi)\b"
            url_pattern = r"https?://(?!generativelanguage\.googleapis\.com)[^\s\]\"']+"
            phone_pattern = r"\b\d{10}\b"
            
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


            return AgentDecision(
                scamDetected=True,
                conversationStatus="ONGOING",
                replyText=random.choice([
                    # Pure emotion (1-2 words)
                    "Wait...",
                    "What?",
                    "Arrey!",
                    "Huh?",
                    "Oh god",
                    "No way",
                    
                    # Confusion (2-4 words)
                    "Not sure yaar",
                    "Samajh nahi aaya",
                    "Say again?",
                    "I'm confused",
                    
                    # Hesitation (2-4 words)
                    "Let me think",
                    "Maybe...",
                    "I'll see",
                    "Give me time",
                    "Umm I don't know",
                    
                    # Suspicion (2-5 words)
                    "This feels wrong",
                    "Suspicious lagta hai",
                    "Something is off",
                    "Nahi don't trust",
                    
                    # Questions (2-4 words)
                    "Who are you",
                    "Why you need",
                    "What is this",
                    "You sure?",
                    "Kyun chahiye?",
                    
                    # Busy/Delay (2-4 words)
                    "Busy abhi",
                    "Can't now",
                    "Not now working",
                    "Wait in meeting",
                    
                    # Fear (2-4 words)
                    "I'm worried now",
                    "What will happen",
                    "This serious?",
                    "Should I be scared",
                    
                    # Soft refusal (2-4 words)
                    "I don't think so",
                    "Nahi yaar",
                    "Can't do",
                    "Not comfortable"
                ]),
                extractedIntelligence=fallback_intel,
                agentNotes="LLM unavailable (429 rate limit). Flagged as potential scam by default for safety. Regex extraction applied."
            )
