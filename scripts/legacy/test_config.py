import sys
sys.path.insert(0, "src")

from maljan.core.config import Settings

s = Settings()
print("provider:", s.llm.provider)
print("openai api_key:", s.llm.openai.api_key[:25] + "..." if s.llm.openai.api_key else None)
print("openai base_url:", s.llm.openai.base_url)
print("openai expert_model:", s.llm.openai.expert_model)
print("openai judge_model:", s.llm.openai.judge_model)
