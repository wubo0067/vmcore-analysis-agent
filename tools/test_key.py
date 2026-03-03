import openai

client = openai.OpenAI(
    api_key="[REDACTED_API_KEY]",  # 换成你在 AiHubMix 生成的密钥
    base_url="https://aihubmix.com/v1",
)
response = client.chat.completions.create(
    model="gpt-4.1-free",
    messages=[{"role": "user", "content": "Hello, how are you?"}],
)

print(response.choices[0].message.content)
