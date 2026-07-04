import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import os
import sys

# Add parent dir to path so we can import config and llm
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm.soc_assistant import soc_assistant

def test_assistant():
    print("--- Starting SOC Assistant Test ---")
    print(f"Is Live (using LLM)? {soc_assistant.is_live}")
    print(f"Total API Keys configured: {len(soc_assistant._api_keys)}")
    
    # Test a simple query
    question = "Can you explain how the BiLSTM detects zero-day threats?"
    print(f"\nQuestion: {question}")
    print("\nAsking assistant...")
    
    try:
        answer = soc_assistant.ask(question)
        print("\n--- Assistant Response ---")
        print(answer)
        print("--------------------------")
    except Exception as e:
        print(f"Error during ask(): {e}")

if __name__ == "__main__":
    test_assistant()
