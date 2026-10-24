# cli-sidecar

The plumbing shared by the sidecars that serve one command-line analysis
program each over MCP (`die-mcp`, `ilspy-mcp`, `goresym-mcp`, `yarax-mcp`,
`oletools-mcp`, `webcrack-mcp`, `unblob-mcp`, `jadx-mcp`). One module, `cli_sidecar.py`, which imports
nothing of the platform: each image holds this module, its own `server.py`,
the program and the packages of `requirements.txt` (installed with
`--require-hashes`), and nothing else.

What every such server does the same way:

| | |
| --- | --- |
| Sample | A path argument must resolve (`realpath`) to a regular file under a directory `MALJAN_SAMPLE_ROOTS` lists; anything else is `path_outside_roots`, and the refusal names no path. Unset, the server reads nothing. |
| Run | The program reads the file it is given; nothing runs the sample. It is started in a process group of its own, with standard input closed, a scratch directory as its working directory, `HOME` and `TMPDIR` (one its server made for the call, where the program writes files the server reads back), and only `PATH`, `LANG` and the variables its server names. A server may hold the run to resource limits of its own (`limits`, such as the largest file it may write), a machine-safety bound, set by util-linux's `prlimit`, which the program is started under. |
| Time | `TOOL_TIMEOUT_SECONDS` bounds one run (unset: no bound); a run past it is killed with its whole group and answered as `timeout`. A cancelled call kills its run the same way. |
| Output | Read whole and parsed in one pass; no byte bound of its own. |
| Failure | `{"error": {"code", "message", "remediation"}, "tool"}` with the platform's codes. A program that is not installed is `missing_dependency`, with the install hint naming the pinned release. |
| `capabilities` | Each tool, whether this host can run its program, and how to install it when it cannot: the manifest the platform's registry reads. |

## Serving

`python3 server.py` serves streamable HTTP at `/mcp` on `MCP_BIND_ADDRESS`
(default `127.0.0.1`) and `MCP_PORT`. A bind beyond loopback is refused unless
`MCP_AUTH_TOKEN` is set, and every request must then carry
`Authorization: Bearer <token>`; the platform sends the server block's
`auth_token` so. The images bind `0.0.0.0` on an internal network and refuse
to start without the token.

`python3 server.py --stdio` serves over standard input and output instead, for
an operator who installs the program on the worker's host and points a server
block's `command` at the script (with `MALJAN_SAMPLE_ROOTS` in its
`env_allow` and its `sample_mount` empty).
