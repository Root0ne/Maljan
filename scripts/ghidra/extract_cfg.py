# Ghidra Headless Analyzer Script to Extract Call Graph
# Usage:
# analyzeHeadless <project_dir> <project_name> -process <binary> -postScript extract_cfg.py <output_file.json>

import json


def extract_call_graph(program, output_path):
    func_manager = program.getFunctionManager()
    functions = func_manager.getFunctions(True)  # True = forward

    cfg = {"binary_name": program.getName(), "functions": {}}

    for func in functions:
        func_name = func.getName()
        entry_point = func.getEntryPoint()
        func_addr_str = "0x" + entry_point.toString()

        called_functions = []

        # Get all instructions in the function
        instructions = program.getListing().getInstructions(func.getBody(), True)
        for inst in instructions:
            flow_type = inst.getFlowType()
            if flow_type.isCall():
                refs = inst.getReferencesFrom()
                for ref in refs:
                    if ref.getReferenceType().isCall():
                        target_addr = ref.getToAddress()
                        called_func = func_manager.getFunctionAt(target_addr)
                        if called_func:
                            called_functions.append(called_func.getName())

        # Deduplicate called functions
        called_functions = list(set(called_functions))

        cfg["functions"][func_name] = {
            "address": func_addr_str,
            "calls": called_functions,
            "is_thunk": func.isThunk(),
        }

    with open(output_path, "w") as f:
        # Avoid using python3 specific json kwargs for jython 2.7 compat
        f.write(json.dumps(cfg, indent=4))

    print("CFG successfully exported to " + output_path)


if __name__ == "__main__":
    args = getScriptArgs()
    if len(args) < 1:
        print("Usage: extract_cfg.py <output_json_path>")
    else:
        output_file = args[0]
        # 'currentProgram' is automatically injected by Ghidra
        extract_call_graph(currentProgram, output_file)
