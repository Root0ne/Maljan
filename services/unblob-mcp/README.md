# unblob-mcp

unblob over MCP: the chunks a container or firmware image holds, and every file
they hold, carved and extracted. Tools around unblob 26.6.4 (MIT), in an image
of its own with the extractors unblob calls (7-Zip, sasquatch, e2fsprogs,
erofs-utils, lz4, lzip, lzop, partclone, simg2img, unar, upx, zstd) and its
Python packages pinned by hash (`requirements.txt`). The shared plumbing is
`../cli-sidecar`.

unblob reads the file, finds each chunk of a format it knows by the chunk's own
bytes (archives, compressed streams, file systems, firmware containers, a
payload appended to another file) and unpacks it, recursively. Nothing it
unpacks is run.

Shipped as the built-in server block `unblob`, switched off, reached at
`http://unblob-mcp:8096/mcp` under the compose profile `unblob`.

## Where the files go

Never beside the sample: the sample directory is mounted read-only. Each
`container_extract` call writes into a directory of its own, named by a fresh
id, under the carve root (`UNBLOB_CARVE_ROOT`, `/tmp/carved` in the image, a
tmpfs). unblob confines its own writes to that directory (Landlock, where the
kernel offers it) and refuses an archive member whose path or link leaves it,
and a device or other special file; the container runs as an unprivileged user
that could not make a device file besides. The answer is made by walking the
directory without following any link: a link is listed by what it names and
never read through, and only a regular file is hashed or handed on.

A file reaches another server only through the platform's artefact store: a
pack step that declares this tool's `outputs` (`/files/*/path`) reads each file
back over `get_artefact`, which opens it beneath the carve root component by
component with no link followed and refuses anything but a regular file; a
file of several names (a busybox link farm) is handed on once, under one
name with the others in `also_named`, and only when every name is inside the
same extraction. A name that is not UTF-8 is shown with its bytes escaped
(`\xe9`) and handed on percent-encoded, so it is read back by its own bytes. An extraction's directory is removed `CARVED_KEEP_SECONDS` after it
was written (3600 unless set), and at once when it holds no file.

Each run is held to machine-safety bounds, each the operator's to set, as the
container's memory ceiling is. It stops once the files it wrote pass the
larger of the sample's own size and the platform's sample upload bound (100
MiB, or `UPLOAD_MAX_BYTES` where the console's `upload_max_bytes` was raised),
or once it made more than `UNBLOB_MAX_ENTRIES` entries (100,000 unless set),
counted at once and then twice a second; a stopped run lists only the files
that fit under the bound and says so in `stopped`. No one file it writes may
pass that byte bound (the run's file size limit): a file cut there is named
under `not_handed_on` and the answer says it stopped. The carve root is the
container's own tmpfs, sized below its memory ceiling (`UNBLOB_TMPFS_SIZE`,
1536m), so what a run writes past the last count fills that file system, not
the container's memory; a new run first removes the oldest finished
extractions until there is room for its bound.

## Tools

| tool | arguments | answer |
| --- | --- | --- |
| `container_scan` | `path` | `file_type` (`magic`, `mime_type`), `chunks` (`handler`, `start_offset`, `end_offset`, `size`, `encrypted`; an `unknown` range with its `entropy`), `chunk_count`, `problems` |
| `container_extract` | `path`, `depth=10` | `files` (`path`, `name`, `size`, `sha256`, `also_named`, `magic`, `mime_type`), `file_count`, `bytes_written`, `not_handed_on` (`name`, `reason`), `links` (`name`, `target`), `special` (`name`, `kind`), `chunks` (as above, each with the `file` it was found in), `problems`, `stopped` when cut |
| `get_artefact` | `path`, `offset=0`, `length` (at most 4 MiB) | `content_b64`, `size` and, with the first chunk, `sha256`: the platform's artefact store reads a written file with it; never an analysis step |
| `capabilities` | | the capability manifest |

`problems` holds what unblob refused or could not do, each with the report's
name: a member whose path or link left the extraction, a special file, an
extractor that failed or is missing. Every offset is a byte offset in the file
named by `file` (`""` for the sample itself). `container_scan` keeps nothing:
it carves into a scratch directory that goes with the call.

The triage pack runs `container_extract` on an archive, disk image, virtual
disk, compiled help file, shortcut or unrecognised sample, by the format the
router gave it, and takes each file it wrote into the job's artefact store.
