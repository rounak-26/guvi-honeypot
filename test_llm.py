import os
import sys
from dotenv import load_dotenv
from google import genai
from google.genai import types

# Load environment variables
load_dotenv()

def test_gemini_connection():
    """
    Validates Google Gemini API connectivity using the new 'google-genai' SDK.
    Targeting: Gemini 2.0 Flash (Next-Gen Speed/Reasoning)
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    
    if not api_key:
        print("❌ CRITICAL ERROR: GOOGLE_API_KEY not found in .env file.")
        sys.exit(1)

    print(f"🔄 Initializing Google GenAI Client with Key: {api_key[:4]}...{api_key[-4:]}")
    
    try:
        client = genai.Client(api_key=api_key)
        
        # SELECTED MODEL: Gemini 2.0 Flash
        # Excellent balance of latency and instruction following
        model_id = "gemini-2.0-flash"
        
        print(f"📡 Sending test probe to model: {model_id}...")
        
        generate_config = types.GenerateContentConfig(
            temperature=0,
            max_output_tokens=10,
            system_instruction="You are a low-latency system check. Reply with 'SYSTEM_ONLINE' only."
        )

        response = client.models.generate_content(
            model=model_id,
            contents="Ping.",
            config=generate_config
        )

        response_content = response.text.strip()

        if "SYSTEM_ONLINE" in response_content:
            print(f"\n✅ SUCCESS: Gemini API is Operational ({model_id}).")
            print(f"   Response: {response_content}")
            print(f"   Latency: Ultra-Low (Ready for Real-time Honeypot)")
            return True
        else:
            print(f"\n⚠️ WARNING: API connected but returned unexpected output: {response_content}")
            return False

    except Exception as e:
        print(f"\n❌ FATAL: Connection Failed.")
        print(f"   Error: {str(e)}")
        return False

if __name__ == "__main__":
    print("--- [ PHASE 0: INFRASTRUCTURE VALIDATION (FINAL) ] ---")
    if test_gemini_connection():
        print("----------------------------------------------")
        print("Ready for Phase 1: Environment & FastAPI Skeleton")
    else:
        print("----------------------------------------------")
        print("STOP: Fix API issues before proceeding.")
        sys.exit(1)