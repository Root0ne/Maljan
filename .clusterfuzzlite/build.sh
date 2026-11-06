#!/bin/bash -eu
# Builds each fuzz/fuzz_*.py harness into a libFuzzer target.
#
# The base image's interpreter is 3.11 and the package needs 3.13, so uv
# provides a 3.13 interpreter and installs the locked runtime dependencies and
# the package itself into an environment of its own. atheris and pyinstaller
# go into the same environment from hashed requirements. With that
# environment first on PATH, compile_python_fuzzer bundles every harness with
# the 3.13 interpreter.

export UV_PYTHON_INSTALL_DIR="$WORK/uv-python"
export UV_PROJECT_ENVIRONMENT="$WORK/fuzz-venv"
export UV_LINK_MODE=copy

# --extra tools: the format parsers archive_list reaches (py7zr, olefile).
uv sync --frozen --no-dev --no-editable --extra tools --python 3.13
uv pip install --python "$UV_PROJECT_ENVIRONMENT/bin/python" --require-hashes \
  -r .clusterfuzzlite/requirements.txt

export PATH="$UV_PROJECT_ENVIRONMENT/bin:$PATH"
for harness in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$harness"
done
