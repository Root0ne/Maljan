// webcrack over one script, as one JSON document on standard output.
//
// Run by server.py as a program of its own (node deobfuscate.mjs [options]
// -- <path>), in a process group of its own under the shared plumbing's time
// bound. It reads the file, hands its JavaScript to webcrack's transforms and
// prints what they made of it; nothing of the script runs. webcrack would
// evaluate an obfuscator's string-decoder functions in a sandbox it is
// handed: none is handed here (sandbox: undefined), so that step is skipped
// and those calls stay in the code as written. webcrack runs its
// control-flow unflattening and dead-code removal only within that step, so
// a script guarded by an obfuscator-style string array keeps both as well.
// The image installs webcrack with npm ci --ignore-scripts and then removes
// the sandbox's module (isolated-vm), so nothing there could evaluate the
// script either.
//
// A JavaScript file is read whole. An HTA, a Windows Script File or any other
// file that opens with markup is read for its <script> blocks, and each block
// in JavaScript or JScript (or of no stated language) is one script; a block
// in another language (VBScript) is listed with its language and left as it
// is. A script encoded with JScript.Encode is left unread on its row, as is
// one webcrack cannot parse; the answer is unsupported_format only when no
// script was read.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const ENCODED_MARKER = "#@~^";
const LANGUAGE = /\b(?:language|type)\s*=\s*["']?([^"'\s>]+)/i;
// JScript, and JScript.Encode as a block declares it.
const ENCODED_LANGUAGE = /(?:javascript|jscript|ecmascript|^(?:text\/|application\/)?js)/i;
const JAVASCRIPT = /^(?:text\/|application\/)?(?:javascript|jscript|ecmascript|js)(?:[\d.]*)$/i;
const OPEN = "<script";
// Its length as a number, so index arithmetic never reads as markup.
const OPEN_LENGTH = OPEN.length;
const CLOSE = "</script";
const CDATA_OPEN = "<![CDATA[";
const CDATA_CLOSE = "]]>";
const UTF8 = new TextDecoder("utf-8", { fatal: false });

function parseArguments(argv) {
  const options = { unpack: true, unminify: true, deobfuscate: true, jsx: false, mangle: false };
  const at = argv.indexOf("--");
  const flags = at >= 0 ? argv.slice(0, at) : argv.slice(0, -1);
  const path = at >= 0 ? argv[at + 1] : argv[argv.length - 1];
  for (const flag of flags) {
    const name = flag.replace(/^--(no-)?/, "");
    if (!(name in options)) throw new Error(`unknown option ${flag}`);
    options[name] = !flag.startsWith("--no-");
  }
  return { options, path };
}

function cdataInner(source) {
  // A WSF block wraps its script in CDATA; read past it with plain string
  // searches, never a backtracking pattern over the block.
  const first = source.search(/\S/);
  const last = source.trimEnd().length;
  if (first < 0 || !source.startsWith(CDATA_OPEN, first)) return source;
  if (!source.endsWith(CDATA_CLOSE, last)) return source;
  return source.slice(first + CDATA_OPEN.length, last - CDATA_CLOSE.length);
}

// The scripts of a file, each with the byte offsets of its text in the file
// (start inclusive, end exclusive; a byte order mark counts). The file is
// scanned as latin1, one character per byte, so every index is a byte offset;
// each script's own bytes are decoded as UTF-8 for webcrack. One pass of
// indexOf over a lowercased copy: an unterminated <script tag or block ends
// the scan, so no input makes it more than linear.
export function scripts(bytes) {
  const latin1 = bytes.toString("latin1");
  const lower = latin1.toLowerCase();
  const body = latin1.startsWith("\xef\xbb\xbf") ? 3 : 0;
  // Markup first: the file's own words decide, never its name.
  if (!/^\s*</.test(latin1.slice(body, body + 4096)) || !lower.includes(OPEN)) {
    return [{ index: 0, language: "javascript", start: 0, end: bytes.length, source: UTF8.decode(bytes) }];
  }
  const found = [];
  let at = 0;
  for (;;) {
    const open = lower.indexOf(OPEN, at);
    if (open < 0) break;
    const after = lower.charAt(open + OPEN_LENGTH);
    if (after && !/[\s>/]/.test(after)) {
      // <scripts, <scripting: another tag.
      at = open + OPEN_LENGTH;
      continue;
    }
    const tagEnd = lower.indexOf(">", open + OPEN_LENGTH);
    if (tagEnd < 0) break;
    const start = tagEnd + 1;
    let end = lower.indexOf(CLOSE, start);
    const closed = end >= 0;
    if (!closed) end = lower.length;
    const attributes = latin1.slice(open + OPEN_LENGTH, tagEnd);
    const language = (LANGUAGE.exec(attributes) || [, "javascript"])[1];
    found.push({
      index: found.length,
      language: language.toLowerCase(),
      start,
      end,
      source: cdataInner(UTF8.decode(bytes.subarray(start, end))),
    });
    if (!closed) break;
    const closeEnd = lower.indexOf(">", end + CLOSE.length);
    if (closeEnd < 0) break;
    at = closeEnd + 1;
  }
  return found;
}

function bundleRows(bundle) {
  if (!bundle) return null;
  return {
    type: bundle.type,
    entry_id: bundle.entryId,
    modules: [...bundle.modules.values()].map((module) => ({
      id: module.id,
      path: module.path,
      is_entry: module.isEntry,
      code: module.code,
    })),
  };
}

async function main() {
  const { options, path } = parseArguments(process.argv.slice(2));
  // Loaded at the first script it rewrites: the scan, and a file with nothing
  // for webcrack to read, need nothing installed.
  let webcrack = null;
  const rows = [];
  for (const script of scripts(readFileSync(path))) {
    const row = {
      index: script.index,
      language: script.language,
      start: script.start,
      end: script.end,
    };
    if (ENCODED_LANGUAGE.test(script.language) && script.source.includes(ENCODED_MARKER)) {
      // JScript.Encode: this script alone is unread, the others go on.
      rows.push({
        ...row,
        deobfuscated: false,
        error: "encoded with JScript.Encode (#@~^), which webcrack does not read",
        code: script.source,
      });
      continue;
    }
    if (!JAVASCRIPT.test(script.language)) {
      rows.push({ ...row, deobfuscated: false, code: script.source });
      continue;
    }
    if (!script.source.trim()) {
      // An empty block: nothing to rewrite, so webcrack is not asked.
      rows.push({ ...row, deobfuscated: false, code: script.source });
      continue;
    }
    let result;
    try {
      webcrack ??= (await import("webcrack")).webcrack;
      // sandbox: undefined: webcrack evaluates nothing of the script.
      result = await webcrack(script.source, { ...options, sandbox: undefined });
    } catch (error) {
      // Not JavaScript webcrack can parse, or nested deeper than its parser's
      // stack: said on its row, the others go on.
      if (!(error instanceof SyntaxError || error instanceof RangeError)) throw error;
      const why =
        error instanceof RangeError
          ? "nested deeper than webcrack's parser can follow"
          : "not JavaScript webcrack can parse";
      rows.push({
        ...row,
        deobfuscated: false,
        error: `${why}: ${error.message}`,
        code: script.source,
      });
      continue;
    }
    rows.push({
      ...row,
      deobfuscated: true,
      changed: result.code.trim() !== script.source.trim(),
      code: result.code,
      bundle: bundleRows(result.bundle),
    });
  }
  const read = rows.filter((row) => row.deobfuscated);
  const unread = rows.filter((row) => row.error);
  if (!read.length && unread.length) {
    return {
      error: { code: "unsupported_format", message: `the script is ${unread[0].error}` },
    };
  }
  return { scripts: rows };
}

// Run as a program; imported (by a test), only the scan above is in use.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (answer) => {
      process.stdout.write(`${JSON.stringify(answer)}\n`);
    },
    (error) => {
      // The error's own words: a stack would name this image's files, not the script's.
      process.stderr.write(`${error && error.name ? `${error.name}: ${error.message}` : error}\n`);
      process.exitCode = 1;
    },
  );
}
