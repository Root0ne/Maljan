import logging

from langchain_ollama import ChatOllama

from maljan.agents.static_analyst import StaticAnalyst

logging.basicConfig(level=logging.INFO)

llm = ChatOllama(model="llama3:latest")
agent = StaticAnalyst(name="Static", llm=llm)
print("Agent created.")
try:
    agent._initialize_mcp_client()
    print("Tools initialized:", [t.name for t in agent.tools])
except Exception as e:
    print("Error:", e)
