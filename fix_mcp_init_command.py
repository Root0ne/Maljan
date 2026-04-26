import glob


def fix_mcp_init(filepath):
    with open(filepath) as f:
        content = f.read()

    # Add import sys if not there
    if "import sys" not in content and "StdioServerParameters(" in content:
        content = content.replace("import os", "import os\n        import sys")

    if 'command="uv",' in content and 'args=["run", "python", server_script],' in content:
        content = content.replace('command="uv",', "command=sys.executable,")
        content = content.replace('args=["run", "python", server_script],', "args=[server_script],")
        with open(filepath, "w") as f:
            f.write(content)
        print(f"Fixed {filepath}")


for f in glob.glob("src/maljan/agents/*.py"):
    fix_mcp_init(f)
