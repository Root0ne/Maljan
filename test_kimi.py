"""Quick test for Kimi AI connectivity (kimi-k2.6 model)."""
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="kimi-k2.6",
    api_key="sk-kimi-vzaXsocP9zCEden9B89EKD0lilTg1aMOcZAxcGG1GdwSEC5F1Fz1scQ9aqaFuRqc",
    base_url="https://api.moonshot.cn/v1",
    temperature=0,
)
response = llm.invoke("Hello, are you Kimi AI? Reply in one sentence.")
print(response.content)
