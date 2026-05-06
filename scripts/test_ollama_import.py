try:
    from langchain_ollama import ChatOllama
    print("OK")
except ImportError as e:
    print(f"MISSING: {e}")
