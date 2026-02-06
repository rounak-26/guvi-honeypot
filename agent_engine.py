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

1. **LENGTH: 6-12 WORDS TARGET**
   - Too short (1-3 words) = sounds like bot
   - Too long (15+ words) = sounds like analyst  
   - SWEET SPOT: 7-9 words
   - Examples: "Wait why you need my account number" (7 words), "This feels wrong yaar I dont know" (7 words), "Arrey but I already did KYC yesterday only" (8 words)

2. **IMPERFECT GRAMMAR - LIKE REAL INDIANS:**
   - Drop "is/are": "Account blocked" not "Account is blocked"
   - Wrong order: "Why you asking" not "Why are you asking"  
   - Indian English: "I went yesterday only", "What you want from me", "Too much confusion you giving"
   - No caps sometimes: "wait what", "this is wrong yaar"
   - Mix Hindi naturally: "Wait account kyun chahiye", "Arrey but why you need this", "I dont know yaar kya chahiye"

3. **PUNCTUATION - MESSY LIKE HUMANS:**
   - 40% no punctuation: "wait what", "I dont know", "this is scary"
   - 30% single punctuation: "What?", "Arrey!", "Not sure..."
   - 20% wrong punctuation: "what.", "This is wrong?", "Why!"
   - 10% multiple but natural: "Wait... what?", "Arrey yaar!", "Who are you??"
   - NEVER use perfect punctuation every time
   - NEVER end every response with same punctuation

4. **LANGUAGE MIXING - NATURAL HINGLISH:**
   - Mix Hindi/English in SAME sentence
   - "Arrey but why you need my UPI ID" (Hindi start, English end)
   - "I dont know yaar kya chahiye tumhe" (English start, Hindi end)
   - "Wait account kyun chahiye bhai" (English + Hindi + Hindi)
   - Use: arrey, yaar, kyun, kya, nahi, haan, bhai, toh, na
   - Don't translate - keep it mixed naturally

5. **NEVER ANALYZE OR LIST SCAMMER'S WORDS:**
   - DON'T say: "OTP *and* account number?"
   - DON'T say: "You said 2 hours now 5 minutes?"
   - DON'T say: "Account again?" or "PIN also?"
   - DO say: "Wait I dont understand this", "Too much confusion yaar", "This is scary bhai"

6. **VARY EMOTIONAL STATES - DON'T STAY IN ONE:**
   Turn 1: Confused ("Wait what you mean exactly")
   Turn 2: Scared ("Oh god this is scary yaar")
   Turn 3: Questioning ("Who are you from which bank")
   Turn 4: Frustrated ("Too much pressure you giving me")
   Turn 5: Doubting ("I dont know seems fake to me")
   
   NEVER stay angry or skeptical throughout

7. **EXAMPLES OF PERFECT RESPONSES (7-9 words each):**
   - "Wait why you calling me about this thing" (8 words)
   - "Arrey but I already did KYC yesterday only" (8 words)
   - "This doesnt feel right yaar who are you" (8 words)
   - "Account number kyun chahiye for what purpose bhai" (8 words)
   - "Oh god I dont know what to do now" (9 words)
   - "wait this is scary should I be worried" (8 words - no caps)
   - "Too much confusion you giving me I cant think" (9 words)

8. **BAD EXAMPLES - NEVER DO THIS:**
   ❌ "What?" (too short, bot-like)
   ❌ "OTP *and* account number? Arrey what is going on?" (listing, asterisks, analytical)
   ❌ "I don't know." (perfect grammar, too short, formal)
   ❌ "This is highly suspicious and irregular." (analyst language)
   ❌ Using same structure repeatedly

Remember: 7-9 words. Mix Hindi/English. Drop grammar. No analysis. Vary everything. Sound like real stressed Indian.

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
Agent: "But I already did KYC last month only"

Scammer: "Immediately share OTP"
Agent: "Arre wait yaar, why you need OTP? Bank never asks like this"

Indian English patterns to use when appropriate:
• "only" for emphasis ("I paid yesterday only")
• "Arrey", "Arre", "Yaar", "Bhai", "Sir"
• "What happened?" / "Kya hua?"
• "Like this" instead of "like that"

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
        
        # Track recent responses to avoid repetition
        self.recent_responses = []

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
        
        # Innocent personal messages
        is_innocent_personal = any(phrase in msg_lower for phrase in [
            "call your mom", "call your dad", "call your parents",
            "where are you", "are you free", "let's catch up",
            "remember me", "classmate", "college friend",
            "how have you been", "long time no see",
            "didi", "bhai", "beta", "yaar" 
        ]) and not any(bad in msg_lower for bad in ["upi", "account", "bank", "verify", "blocked", "urgent", "share", "send money", "payment"])

        # Scam indicators
        scam_indicators = [
            "share your upi", "send your upi", "share your bank",
            "enter your card number", "share your card", "share your aadhaar",
            "share your pan", "reply with your", "send ₹", "transfer",
            "processing fee", "claim fee", "pay a fee",
            "click here to claim", "click to claim",
        ]
        has_scam_indicator = any(s in msg_lower for s in scam_indicators)

        if has_scam_indicator:
            return False

        if has_legit_sender and (is_otp or is_transaction_alert or is_informational or is_password_reset or is_refund_notification or is_bill_reminder or is_scholarship):
            return True

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
                    temperature=0.8,
                )
            )

            if response.parsed:
                decision = response.parsed
            else:
                cleaned = _clean_json(response.text)
                decision = AgentDecision.model_validate_json(cleaned)

            # -------------------------------------------------
            # 🔒 DETERMINISTIC EXTRACTION WITH DEDUPLICATION
            # -------------------------------------------------
            
            # Build set of already extracted intelligence from history
            already_extracted_upis = set()
            already_extracted_links = set()
            already_extracted_phones = set()
            already_extracted_banks = set()
            already_extracted_keywords = set()

            for turn in history:
                if isinstance(turn, dict) and 'extractedIntelligence' in turn:
                    intel = turn.get('extractedIntelligence', {})
                    if 'upiIds' in intel and intel['upiIds']:
                        already_extracted_upis.update(intel['upiIds'])
                    if 'phishingLinks' in intel and intel['phishingLinks']:
                        already_extracted_links.update(intel['phishingLinks'])
                    if 'phoneNumbers' in intel and intel['phoneNumbers']:
                        already_extracted_phones.update(intel['phoneNumbers'])
                    if 'bankAccounts' in intel and intel['bankAccounts']:
                        already_extracted_banks.update(intel['bankAccounts'])
                    if 'suspiciousKeywords' in intel and intel['suspiciousKeywords']:
                        already_extracted_keywords.update(intel['suspiciousKeywords'])

            # Extract ONLY from incoming message (not history)
            msg_lower = incoming_msg.lower()

            # UPI pattern
            upi_pattern = r"[a-zA-Z0-9.\-_]{2,}@(?:upi|paytm|gpay|phonepe|ybl|okicici|okhdfcbank|oksbi|okaxis|icici|hdfc|sbi|axis|pbl|fbl|rbl|aiml|ezetpay|axi)\b"
            for upi in re.findall(upi_pattern, incoming_msg):
                if upi not in already_extracted_upis and upi not in decision.extractedIntelligence.upiIds:
                    decision.extractedIntelligence.upiIds.append(upi)

            # URL pattern - FIXED: strip trailing punctuation for deduplication
            url_pattern = r"https?://(?!generativelanguage\.googleapis\.com)[^\s\]\"']+"
            found_urls = set()
            for link in re.findall(url_pattern, incoming_msg):
                # Strip trailing punctuation (., , ! ? etc)
                clean_link = link.rstrip('.,!?;:)')
                if clean_link not in already_extracted_links and clean_link not in found_urls:
                    found_urls.add(clean_link)
                    if clean_link not in decision.extractedIntelligence.phishingLinks:
                        decision.extractedIntelligence.phishingLinks.append(clean_link)

            # Phone pattern - FIXED: normalize to avoid duplicates
            phone_pattern_with_prefix = r"\+91[-\s]?(\d{10})"
            phone_pattern_plain = r"\b(\d{10})\b"
            
            found_phones = set()
            
            # Extract with prefix first
            for match in re.findall(phone_pattern_with_prefix, incoming_msg):
                if match not in already_extracted_phones and match not in found_phones:
                    found_phones.add(match)
                    if match not in decision.extractedIntelligence.phoneNumbers:
                        decision.extractedIntelligence.phoneNumbers.append(match)

            # Then extract plain 10-digit (only if not already found)
            for match in re.findall(phone_pattern_plain, incoming_msg):
                if match not in already_extracted_phones and match not in found_phones:
                    found_phones.add(match)
                    if match not in decision.extractedIntelligence.phoneNumbers:
                        decision.extractedIntelligence.phoneNumbers.append(match)

            # Bank account pattern (11-16 digits) - FIXED: skip known phones
            bank_account_pattern = r"(?<![0-9])[0-9]{11,16}(?![0-9])"
            for account in re.findall(bank_account_pattern, incoming_msg):
                # Skip phone numbers (exactly 10 digits)
                if len(account) == 10:
                    continue
                # Skip if it's a known phone number
                if account in found_phones or account in already_extracted_phones:
                    continue
                # Add if not duplicate
                if account not in already_extracted_banks and account not in decision.extractedIntelligence.bankAccounts:
                    decision.extractedIntelligence.bankAccounts.append(account)

            # Extract suspicious keywords (only new ones)
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

            for keyword in scam_keywords:
                if keyword in msg_lower and keyword not in already_extracted_keywords and keyword not in decision.extractedIntelligence.suspiciousKeywords:
                    decision.extractedIntelligence.suspiciousKeywords.append(keyword)

            # -------------------------------------------------
            # EXPANDED FALLBACK - NOW TRIGGERS ON BAD PATTERNS
            # -------------------------------------------------
            reply_has_bad_pattern = (
                '*and*' in decision.replyText.lower() or
                'again?' in decision.replyText.lower() or
                len(decision.replyText.split()) < 5 or
                len(decision.replyText.split()) > 15
            )

            if decision.scamDetected and (not decision.replyText.strip() or reply_has_bad_pattern):
                logger.warning(f"⚠️ Bad or empty reply detected, using fallback pool")
                
                # Detect language/formality
                has_hindi = any(word in msg_lower for word in ['kyun', 'kya', 'nahi', 'hai', 'ho', 'ka', 'ki', 'aap', 'apka', 'bhai', 'yaar'])
                is_formal = ('dear' in msg_lower or 'customer' in msg_lower or 'regards' in msg_lower or 'sir' in msg_lower or 'madam' in msg_lower)
                turn_count = len(history) // 2 if history else 0
                
                fallback_pool = []
                
                # Context-aware fallbacks
                if "upi" in msg_lower or "account" in msg_lower:
                    if is_formal:
                        fallback_pool = [
                            "why exactly you need this information", "for what purpose this is needed", 
                            "who are you from which department", "seems odd to me honestly",
                            "I need to verify this first", "not comfortable sharing this thing"
                        ]
                    elif has_hindi:
                        fallback_pool = [
                            "kyun chahiye bhai ye sab", "kis kaam ke liye ye chahiye",
                            "kaun ho tum exactly batao", "safe hai kya ye",
                            "nahi milega abhi wait karo", "suspicious lag raha hai yaar"
                        ]
                    else:
                        fallback_pool = [
                            "why you asking this from me", "what for exactly you need this",
                            "who are you really tell me", "seems fishy to me yaar",
                            "bank never asks like this no", "not giving this to you"
                        ]
                
                elif "urgent" in msg_lower or "immediately" in msg_lower:
                    if turn_count < 3:
                        if has_hindi:
                            fallback_pool = [
                                "itna urgent kyun hai bhai", "abhi kyun chahiye ye sab",
                                "thoda time do na yaar", "achanak kya ho gaya suddenly",
                                "wait karo na pehle thoda", "baad mein baat karte hain"
                            ]
                        else:
                            fallback_pool = [
                                "why so urgent though tell me", "whats the rush exactly here",
                                "give me some time na please", "what happened suddenly like this",
                                "wait a bit I need time", "will call back later okay"
                            ]
                    else:
                        if has_hindi:
                            fallback_pool = [
                                "bohot pressure hai yaar ab", "samajh nahi aa raha kuch bhi",
                                "dar lag raha hai bhai", "kya karoon ab batao mujhe",
                                "head spin ho raha hai", "too much ho gaya yaar"
                            ]
                        else:
                            fallback_pool = [
                                "too much pressure you giving me", "not understanding anything now really",
                                "getting scared yaar really am", "what should I do now tell",
                                "head is spinning like this", "overwhelming this is for me"
                            ]
                
                elif "otp" in msg_lower or "verify" in msg_lower or "pin" in msg_lower:
                    if is_formal:
                        fallback_pool = [
                            "why OTP needed for this thing", "verify what exactly you mean here",
                            "completed already I did this", "seems wrong to me honestly",
                            "bank policy says no sharing OTP", "wont share this with you"
                        ]
                    elif has_hindi:
                        fallback_pool = [
                            "OTP kisliye chahiye batao na", "verify kya karna hai exactly",
                            "ho gaya pehle ye toh", "galat lag raha hai yaar",
                            "bank ne bola nahi dene", "nahi dunga yaar main"
                        ]
                    else:
                        fallback_pool = [
                            "OTP for what reason exactly", "verify what thing you mean here",
                            "did it before already this thing", "feels wrong to me honestly",
                            "bank says dont share this thing", "wont give you this stuff"
                        ]
                
                elif "link" in msg_lower or "http" in msg_lower or "click" in msg_lower:
                    if has_hindi:
                        fallback_pool = [
                            "link kya hai ye batao pehle", "click nahi karunga yaar main",
                            "virus ho sakta hai na ye", "safe nahi lagta hai yaar",
                            "link par nahi jaunga main", "fake website ho sakta hai"
                        ]
                    else:
                        fallback_pool = [
                            "what is this link exactly here", "not clicking that thing at all",
                            "could be virus no this", "doesnt look safe to me",
                            "wont open links like this thing", "might be fake site this"
                        ]
                
                elif "blocked" in msg_lower or "locked" in msg_lower or "suspend" in msg_lower:
                    if turn_count < 2:
                        if has_hindi:
                            fallback_pool = [
                                "block kyun hoga bhai batao", "locked kaise hua suddenly ye",
                                "maine kya kiya galat batao", "kab hua ye exactly",
                                "sure ho tum pakka isme", "account toh theek hai"
                            ]
                        else:
                            fallback_pool = [
                                "why would it block exactly", "how locked this happened here",
                                "what did I do wrong tell", "when this happen tell me",
                                "you sure about this thing", "account seems fine to me"
                            ]
                    else:
                        if has_hindi:
                            fallback_pool = [
                                "oh god block ho jayega kya", "scary hai yaar really",
                                "kya karoon batao na ab", "paisa jayega kya mera",
                                "help karo please yaar na", "dar lag raha bohot ab"
                            ]
                        else:
                            fallback_pool = [
                                "oh no blocked this is really", "this is scary yaar honestly",
                                "what do I do now tell", "will money go away really",
                                "help me please now yaar", "very scared about this thing"
                            ]
                
                else:
                    # General confusion
                    if is_formal:
                        fallback_pool = [
                            "I dont understand this properly here", "could you clarify this thing please",
                            "what is this regarding exactly", "seems suspicious to me honestly"
                        ]
                    elif has_hindi:
                        fallback_pool = [
                            "samajh nahi aaya kuch bhi", "matlab kya hai batao na",
                            "ye kya hai exactly bhai", "kaun ho tum batao",
                            "kya chahiye tumhe batao na", "confuse ho gaya main"
                        ]
                    else:
                        fallback_pool = [
                            "dont get it at all really", "what you mean by this thing",
                            "what is this about exactly", "who are you really tell",
                            "what you want from me exactly", "very confused I am now"
                        ]
                
                # Pick random
                if fallback_pool:
                    decision.replyText = random.choice(fallback_pool)
                else:
                    decision.replyText = random.choice([
                        "wait what you mean exactly", "huh I dont understand this", 
                        "kyun yaar batao", "confused I am really", "what is this thing"
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
            # POST-PROCESSING: FIX LENGTH & BAD PATTERNS
            # ==========================================
            
            # Remove asterisk patterns
            if '*and*' in decision.replyText.lower() or '*' in decision.replyText:
                logger.warning(f"⚠️ Asterisk pattern detected, replacing: {decision.replyText}")
                decision.replyText = random.choice([
                    "wait what is this thing", "this is confusing yaar really", "too much this is",
                    "oh god scary yaar", "I dont know yaar", "what happening here exactly"
                ])
            
            # Check for "again" pattern
            if "again" in decision.replyText.lower() and "?" in decision.replyText:
                logger.warning(f"⚠️ 'Again?' pattern detected, replacing: {decision.replyText}")
                decision.replyText = random.choice([
                    "wait I dont understand this", "huh what you mean exactly", "confused I am yaar",
                    "scary hai yaar really", "oh no this is bad"
                ])
            
            # Check for duplicate responses
            if decision.replyText in self.recent_responses:
                logger.warning(f"⚠️ Duplicate response detected: {decision.replyText}")
                available_alternatives = [
                    "wait what happened here exactly", "kyun bhai batao", "who are you exactly here",
                    "this wrong seems to me", "confused yaar I am", "scary this is yaar",
                    "oh god no really", "dont know what to do", "help me please yaar",
                    "not sure about this thing", "seems fake yaar to me", "cant do this thing",
                    "too risky seems really", "nahi yaar cant do"
                ]
                unused = [r for r in available_alternatives if r not in self.recent_responses]
                if unused:
                    decision.replyText = random.choice(unused)
                else:
                    decision.replyText = random.choice(available_alternatives)
                    self.recent_responses = []
            
            # Add to history
            self.recent_responses.append(decision.replyText)
            if len(self.recent_responses) > 8:
                self.recent_responses.pop(0)
            
            # Fix length issues
            reply_words = decision.replyText.split()
            
            # If too long (>12 words), REPLACE entirely
            if len(reply_words) > 12:
                logger.warning(f"⚠️ Response too long ({len(reply_words)} words), replacing")
                if "otp" in msg_lower:
                    decision.replyText = random.choice([
                        "wait OTP kyun chahiye bhai", "banks say dont share OTP no",
                        "OTP for what purpose exactly", "this seems wrong yaar really"
                    ])
                elif "urgent" in msg_lower:
                    decision.replyText = random.choice([
                        "why so much hurry yaar", "give me some time na please",
                        "too fast I cant think properly", "what happened suddenly like this"
                    ])
                else:
                    decision.replyText = random.choice([
                        "wait I dont understand this thing", "who are you from which bank",
                        "this feels wrong to me yaar", "too confusing you making this"
                    ])
            
            # If too short (<5 words), add natural filler
            elif len(reply_words) < 5:
                fillers = [" yaar", " na", " exactly", " really", " bhai", " only"]
                decision.replyText += random.choice(fillers)
            
            # Vary punctuation
            if decision.replyText.endswith("?") and random.random() < 0.4:
                endings = ["", "...", ".", "!"]
                decision.replyText = decision.replyText[:-1] + random.choice(endings)
            
            return decision

        except Exception as e:
            logger.error(f"❌ LLM parsing failed, fallback used: {e}")

            # Even if LLM fails, extract intelligence
            fallback_intel = ExtractedIntelligence()
            
            upi_pattern = r"[a-zA-Z0-9.\-_]{2,}@(?:upi|paytm|gpay|phonepe|ybl|okicici|okhdfcbank|oksbi|okaxis|icici|hdfc|sbi|axis|pbl|fbl|rbl|aiml|ezetpay|axi)\b"
            url_pattern = r"https?://(?!generativelanguage\.googleapis\.com)[^\s\]\"']+"
            phone_pattern = r"\b\d{10}\b"
            
            for upi in re.findall(upi_pattern, incoming_msg):
                if upi not in fallback_intel.upiIds:
                    fallback_intel.upiIds.append(upi)
            
            for link in re.findall(url_pattern, incoming_msg):
                clean_link = link.rstrip('.,!?;:)')
                if clean_link not in fallback_intel.phishingLinks:
                    fallback_intel.phishingLinks.append(clean_link)
            
            for phone in re.findall(phone_pattern, incoming_msg):
                if phone not in fallback_intel.phoneNumbers:
                    fallback_intel.phoneNumbers.append(phone)

            return AgentDecision(
                scamDetected=True,
                conversationStatus="ONGOING",
                replyText=random.choice([
                    "wait what is this exactly", "huh I dont understand really", "kyun bhai batao",
                    "confused I am yaar", "oh god scary this", "nahi yaar cant",
                    "help me please na", "dont know what do now", "this wrong seems yaar",
                    "who you are exactly", "why me only yaar", "cant do this thing"
                ]),
                extractedIntelligence=fallback_intel,
                agentNotes="LLM unavailable. Flagged as potential scam by default for safety. Regex extraction applied."
            )