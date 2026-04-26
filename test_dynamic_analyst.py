import logging

from langchain_ollama import ChatOllama

from maljan.agents.dynamic_analyst import DynamicAnalyst

logging.basicConfig(level=logging.INFO)

llm = ChatOllama(model="llama3:latest")
agent = DynamicAnalyst(name="dynamic", llm=llm)
print("Agent created.")
try:
    agent._initialize_mcp_client()
    print("Tools initialized:", [t.name for t in getattr(agent, "tools", [])])
except Exception as e:
    print("Error:", e)
