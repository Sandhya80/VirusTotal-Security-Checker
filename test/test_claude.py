import os
import anthropic

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
print(f"\nUsing Anthropic API Key: {ANTHROPIC_API_KEY}\n------\n")
claude_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

def list_available_models():
    try:
        models_list = claude_client.models.list(limit=20)
        print("Available Claude Models using your API key:")
        for model in models_list.data:
            print(f"{model.id}, ({model.display_name})")
        print("------\n")
    except Exception as e:
        print(f"Error fetching models: {str(e)}")
        return []

def ask_claude(prompt: str, max_tokens: int = 300) -> str:
    if not ANTHROPIC_API_KEY:
        return "Claude API key not configured."
    try:
        message = f"{anthropic.HUMAN_PROMPT} {prompt}{anthropic.AI_PROMPT}"
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": message}
            ]
        )
        return response.content[0].text.strip()
    except Exception as e:
        return f"Claude API error: {str(e)}"
    
def test_ask_claude():
    response = ask_claude("What is the capital of France?")
    assert "Paris" in response, f"Expected 'Paris' in response, got: {response}"
    print("Claude API response:\n\n" + response + "\n------\n")
    print("Claude API test passed successfully.")
    
if __name__ == "__main__":
    list_available_models()
    test_ask_claude()