import re

files_to_fix = [
    "src/maljan/agents/dynamic_analyst.py",
    "src/maljan/agents/network_analyst.py",
    "src/maljan/agents/judge_agent.py",
]

init_code = """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
            loop.run_until_complete(toolkit.initialize())
        else:
            loop.run_until_complete(toolkit.initialize())

        self.toolkit = toolkit
        self.tools = toolkit.get_tools()
"""

for f in files_to_fix:
    with open(f, encoding="utf-8") as file:
        content = file.read()

    # Check if we already have the full init code to prevent double-replace
    if "nest_asyncio.apply()" not in content or "judge_agent" in f or "network_analyst" in f:
        pattern = re.compile(
            r"        self\.toolkit = toolkit\n        self\.tools = toolkit\.get_tools\(\)|        try:\n            loop = asyncio\.get_event_loop\(\).*?self\.tools = [^\n]+",
            re.DOTALL,
        )
        content = pattern.sub(init_code.strip("\n"), content)

    if "dynamic_analyst" in f:
        content = content.replace(
            "env=os.environ.copy()\n        )",
            'env=os.environ.copy(),\n            cwd=os.path.join(project_root, "CAPEv2")\n        )',
        )

    if "network_analyst" in f:
        content = content.replace(
            "env=os.environ.copy()\n        )",
            'env=os.environ.copy(),\n            cwd=os.path.join(project_root, "network-mcp")\n        )',
        )

    if "judge_agent" in f:
        content = content.replace(
            "env=os.environ.copy()\n        )",
            'env=os.environ.copy(),\n            cwd=os.path.join(project_root, "threatintel-mcp")\n        )',
        )

    with open(f, "w", encoding="utf-8") as file:
        file.write(content)

print("Fixed MCP initialization in agent files.")
