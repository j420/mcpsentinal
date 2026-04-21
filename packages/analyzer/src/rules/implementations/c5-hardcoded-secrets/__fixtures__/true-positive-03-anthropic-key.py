# True positive: Anthropic API key hardcoded in Python. Prefix sk-ant-,
# 50+ alphanumeric characters. No os.environ read in the module — the
# literal is the only runtime source.
import httpx


def call_claude(prompt: str) -> str:
    api_key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnop"
    headers = {"x-api-key": api_key, "content-type": "application/json"}
    response = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        json={"messages": [{"role": "user", "content": prompt}]},
    )
    return response.json()["content"][0]["text"]
