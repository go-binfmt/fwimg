// check.js runs the cases of a manifest through the playground engine and the
// js/wasm build, and compares what comes out with what the native build wrote
// (the manifest is written by cmd/fwimg/wasm_test.go).
//
//	node check.js WASM_EXEC.JS FWIMG.WASM MANIFEST.json
//
// Exit status 0: every case matched byte for byte. 1: a difference, printed.
"use strict";
const fs = require("fs");
const path = require("path");

const [execJS, wasmFile, manifestFile] = process.argv.slice(2);
if (!manifestFile) {
  console.error("usage: node check.js WASM_EXEC.JS FWIMG.WASM MANIFEST.json");
  process.exit(2);
}
const here = __dirname;
require(path.join(here, "engine.js")); // BEFORE wasm_exec.js: it installs the fs
require(path.resolve(execJS));
const E = globalThis.FwimgEngine;

const m = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
// The input goes by its own name, as it does natively, where `info` prints it.
const norm = (s, inPath) => s.split("/out").join("{out}").split(inPath).join("{in}");
const same = (a, b) => a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

(async () => {
  const mod = await E.compile(fs.readFileSync(wasmFile));
  let bad = 0, n = 0;
  const fail = (name, what) => { bad++; console.error("DIFF", name + ":", what); };

  for (const c of m.run || []) {
    n++;
    const input = new Uint8Array(fs.readFileSync(c.input));
    const inPath = "/" + E.safeName(path.basename(c.input));
    const args = c.args.map((a) => a.split("{in}").join(inPath).split("{out}").join("/out"));
    const r = await E.run(mod, args, { [inPath]: input });
    if (r.code !== c.wantCode) fail(c.name, "exit " + r.code + ", native " + c.wantCode);
    if (norm(r.stdout, inPath) !== c.wantStdout) fail(c.name, "stdout differs:\n" + norm(r.stdout, inPath) + "\nnative:\n" + c.wantStdout);
    if (norm(r.stderr, inPath) !== c.wantStderr) fail(c.name, "stderr differs:\n" + norm(r.stderr, inPath) + "\nnative:\n" + c.wantStderr);
    const out = r.files.get("/out");
    if (c.wantOut) {
      const want = fs.readFileSync(c.wantOut);
      if (!out) fail(c.name, "no output, native wrote " + want.length + " bytes");
      else if (!same(out.data.subarray(0, out.size), want)) fail(c.name, "output differs (" + out.size + " bytes, native " + want.length + ")");
    } else if (out) {
      fail(c.name, "wrote " + out.size + " bytes, native wrote nothing");
    }
  }

  for (const c of m.convert || []) {
    n++;
    const input = new Uint8Array(fs.readFileSync(c.input));
    const r = await E.convert(mod, input, c.options, path.basename(c.input));
    if (!r.ok) { fail(c.name, "convert refused: " + r.stderr); continue; }
    if (!same(r.output, fs.readFileSync(c.wantOut))) fail(c.name, "convert output differs");
    if ((r.info || "") !== c.wantInfo) fail(c.name, "info differs:\n" + r.info + "\nnative:\n" + c.wantInfo);
  }

  // The limits are refusals, not crashes.
  n++;
  try { await E.convert(mod, new Uint8Array(E.limits.MAX_INPUT + 1), { format: "binary" }); fail("limit", "an input above the limit was accepted"); } catch (e) { /* refused */ }
  n++;
  try { E.buildArgs({ nosuchoption: 1 }, "/in", "/out"); fail("option", "an unknown option was accepted"); } catch (e) { /* refused */ }
  n++;
  try { E.buildArgs({ maxSize: String(E.limits.MAX_MAX_SIZE + 1) }, "/in", "/out"); fail("max-size", "an oversized --max-size was accepted"); } catch (e) { /* refused */ }
  n++;
  { // a value that looks like a flag stays a value
    const a = E.buildArgs({ name: "--version" }, "/in", "/out");
    if (!a.includes("--name=--version")) fail("name", "a value starting with - was not glued to its flag: " + a.join(" "));
  }

  console.log(n + " cases, " + bad + " differences");
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
