// fwimg playground engine: runs the real fwimg command, built for js/wasm, on
// files held in memory. It is loaded BEFORE wasm_exec.js, because that file
// installs its own useless `fs` only when none exists, and Go's syscall package
// reads the global `fs` when the program starts.
//
// Nothing here touches the network or the disk: the input bytes go into an
// in-memory file system, the command reads and writes that, and the output
// bytes come back out of it. The command is the same code the native build
// runs (cmd/fwimg), so the bytes are the same by construction, and the test
// (cmd/fwimg/wasm_test.go) checks that they are.
//
// Usable in a Worker (importScripts), in Node (require) and in a page.
(function (root) {
  "use strict";

  // Limits. The page refuses a larger input before reading it; the engine
  // refuses it again, and bounds what the command may write, so that a hostile
  // input cannot make the tab allocate without limit.
  const MAX_INPUT = 32 * 1024 * 1024;
  const MAX_FS_BYTES = 192 * 1024 * 1024; // everything held by the in-memory fs
  const DEFAULT_MAX_SIZE = 128 * 1024 * 1024; // --max-size when the caller gives none
  const MAX_MAX_SIZE = 192 * 1024 * 1024;

  // open(2) flag values the Go side reads through fs.constants.
  const C = {
    O_RDONLY: 0, O_WRONLY: 1, O_RDWR: 2, O_CREAT: 64, O_EXCL: 128,
    O_TRUNC: 512, O_APPEND: 1024, O_DIRECTORY: 65536,
  };
  const S_IFREG = 0o100000, S_IFDIR = 0o040000, S_IFCHR = 0o020000;

  function err(code, msg) {
    const e = new Error(msg || code);
    e.code = code;
    return e;
  }

  function norm(p) {
    if (typeof p !== "string" || p === "") throw err("EINVAL");
    const out = [];
    for (const seg of p.split("/")) {
      if (seg === "" || seg === ".") continue;
      if (seg === "..") { out.pop(); continue; }
      out.push(seg);
    }
    return "/" + out.join("/");
  }
  function parent(p) {
    const i = p.lastIndexOf("/");
    return i <= 0 ? "/" : p.slice(0, i);
  }

  // The session is the file system of one run. The global `fs` stays one object
  // (Go keeps a reference to it); runs are sequential and swap the session.
  let sess = null;
  let ino = 1;

  function newSession() {
    return {
      files: new Map(), // path -> {data, size, mode, mtimeMs, ino}
      dirs: new Set(["/"]),
      fds: new Map(), // fd -> {path, node, dir, pos, flags}
      next: 3,
      total: 0,
      out: [], errb: [],
    };
  }

  function grow(node, need) {
    if (need <= node.data.length) return;
    const delta = need - node.size;
    if (sess.total + delta > MAX_FS_BYTES) throw err("ENOSPC", "in-memory file system full");
    const cap = Math.max(need, Math.min(node.data.length * 2, node.data.length + 16 * 1024 * 1024), 4096);
    const d = new Uint8Array(cap);
    d.set(node.data.subarray(0, node.size));
    node.data = d;
  }

  function setSize(node, n) {
    if (n > node.size) {
      if (sess.total + (n - node.size) > MAX_FS_BYTES) throw err("ENOSPC", "in-memory file system full");
      grow(node, n);
      node.data.fill(0, node.size, n);
    }
    sess.total += n - node.size;
    node.size = n;
  }

  function stat(node, isDir) {
    const now = Date.now();
    const size = isDir ? 4096 : node.size;
    return {
      dev: 1, ino: node ? node.ino : 1, mode: isDir ? S_IFDIR | 0o755 : node.mode,
      nlink: 1, uid: 0, gid: 0, rdev: 0, size, blksize: 4096, blocks: Math.ceil(size / 512),
      atimeMs: node ? node.mtimeMs : now, mtimeMs: node ? node.mtimeMs : now, ctimeMs: node ? node.mtimeMs : now,
      isDirectory() { return isDir; }, isFile() { return !isDir; },
    };
  }
  const charDev = () => ({
    dev: 1, ino: 0, mode: S_IFCHR | 0o620, nlink: 1, uid: 0, gid: 0, rdev: 0, size: 0,
    blksize: 4096, blocks: 0, atimeMs: 0, mtimeMs: 0, ctimeMs: 0,
    isDirectory() { return false; }, isFile() { return false; },
  });

  // Every operation completes through a microtask: Go's callbacks run on its own
  // event loop, never re-entrantly inside the call that asked.
  function wrap(fn) {
    return function (...args) {
      const cb = args.pop();
      let res, e = null;
      try { res = fn(...args); } catch (x) { e = x.code ? x : err("EIO", String(x && x.message)); }
      Promise.resolve().then(() => (e ? cb(e) : cb(null, res)));
    };
  }

  function lookup(path) {
    const p = norm(path);
    if (sess.dirs.has(p)) return { p, dir: true };
    const node = sess.files.get(p);
    if (!node) throw err("ENOENT", "no such file or directory: " + p);
    return { p, node };
  }
  function fdOf(fd) {
    const h = sess.fds.get(fd);
    if (!h) throw err("EBADF");
    return h;
  }

  const FS = {
    constants: C,
    // Standard output and error are collected: the command's messages are the
    // result, not console noise.
    writeSync(fd, buf) {
      (fd === 2 ? sess.errb : sess.out).push(buf.slice());
      return buf.length;
    },
    open: wrap((path, flags, mode) => {
      const p = norm(path);
      if (sess.dirs.has(p)) {
        if (flags & (C.O_WRONLY | C.O_RDWR)) throw err("EISDIR");
        const fd = sess.next++;
        sess.fds.set(fd, { path: p, dir: true, pos: 0 });
        return fd;
      }
      let node = sess.files.get(p);
      if (node && (flags & C.O_CREAT) && (flags & C.O_EXCL)) throw err("EEXIST");
      if (!node) {
        if (!(flags & C.O_CREAT)) throw err("ENOENT", "no such file or directory: " + p);
        if (!sess.dirs.has(parent(p))) throw err("ENOENT", "no such directory: " + parent(p));
        node = { data: new Uint8Array(0), size: 0, mode: S_IFREG | ((mode & 0o777) || 0o644), mtimeMs: Date.now(), ino: ino++ };
        sess.files.set(p, node);
      } else if (flags & C.O_TRUNC) {
        setSize(node, 0);
      }
      const fd = sess.next++;
      sess.fds.set(fd, { path: p, node, pos: 0, flags });
      return fd;
    }),
    close: wrap((fd) => { if (!sess.fds.delete(fd) && fd > 2) throw err("EBADF"); }),
    read: wrap((fd, buf, off, len, position) => {
      if (fd >= 0 && fd <= 2) return 0; // standard input is empty
      const h = fdOf(fd);
      if (h.dir) throw err("EISDIR");
      const at = position === null || position === undefined ? h.pos : position;
      const n = Math.max(0, Math.min(len, h.node.size - at));
      if (n > 0) buf.set(h.node.data.subarray(at, at + n), off);
      if (position === null || position === undefined) h.pos += n;
      return n;
    }),
    write: wrap((fd, buf, off, len, position) => {
      if (fd === 1 || fd === 2) return FS.writeSync(fd, buf.subarray(off, off + len));
      const h = fdOf(fd);
      if (h.dir || !(h.flags & (C.O_WRONLY | C.O_RDWR))) throw err("EBADF");
      let at = position === null || position === undefined ? h.pos : position;
      if (h.flags & C.O_APPEND) at = h.node.size;
      if (at + len > h.node.size) setSize(h.node, at + len);
      h.node.data.set(buf.subarray(off, off + len), at);
      h.node.mtimeMs = Date.now();
      if (position === null || position === undefined) h.pos = at + len;
      return len;
    }),
    fstat: wrap((fd) => {
      if (fd >= 0 && fd <= 2) return charDev();
      const h = fdOf(fd);
      return h.dir ? stat(null, true) : stat(h.node, false);
    }),
    stat: wrap((path) => { const l = lookup(path); return stat(l.node, !!l.dir); }),
    lstat: wrap((path) => { const l = lookup(path); return stat(l.node, !!l.dir); }),
    unlink: wrap((path) => {
      const l = lookup(path);
      if (l.dir) throw err("EISDIR");
      sess.total -= l.node.size;
      sess.files.delete(l.p);
    }),
    mkdir: wrap((path) => {
      const p = norm(path);
      if (sess.dirs.has(p) || sess.files.has(p)) throw err("EEXIST");
      if (!sess.dirs.has(parent(p))) throw err("ENOENT");
      sess.dirs.add(p);
    }),
    rmdir: wrap((path) => {
      const p = norm(path);
      if (!sess.dirs.has(p) || p === "/") throw err("ENOENT");
      for (const f of sess.files.keys()) if (parent(f) === p) throw err("ENOTEMPTY");
      for (const d of sess.dirs) if (d !== p && parent(d) === p) throw err("ENOTEMPTY");
      sess.dirs.delete(p);
    }),
    readdir: wrap((path) => {
      const p = norm(path);
      if (!sess.dirs.has(p)) throw err("ENOTDIR");
      const names = [];
      for (const f of sess.files.keys()) if (parent(f) === p) names.push(f.slice(p === "/" ? 1 : p.length + 1));
      for (const d of sess.dirs) if (d !== "/" && parent(d) === p) names.push(d.slice(p === "/" ? 1 : p.length + 1));
      return names.sort();
    }),
    rename: wrap((from, to) => {
      const l = lookup(from);
      if (l.dir) throw err("ENOSYS");
      const t = norm(to);
      if (!sess.dirs.has(parent(t))) throw err("ENOENT");
      const old = sess.files.get(t);
      if (old) sess.total -= old.size;
      sess.files.delete(l.p);
      sess.files.set(t, l.node);
    }),
    ftruncate: wrap((fd, n) => { const h = fdOf(fd); if (h.dir) throw err("EISDIR"); setSize(h.node, n); }),
    truncate: wrap((path, n) => { const l = lookup(path); if (l.dir) throw err("EISDIR"); setSize(l.node, n); }),
    fsync: wrap(() => {}),
    chmod: wrap((path, mode) => { const l = lookup(path); if (l.node) l.node.mode = (l.node.mode & ~0o777) | (mode & 0o777); }),
    fchmod: wrap((fd, mode) => { const h = fdOf(fd); if (h.node) h.node.mode = (h.node.mode & ~0o777) | (mode & 0o777); }),
    chown: wrap(() => {}), fchown: wrap(() => {}), lchown: wrap(() => {}),
    utimes: wrap(() => {}),
    link: wrap(() => { throw err("ENOSYS"); }),
    symlink: wrap(() => { throw err("ENOSYS"); }),
    readlink: wrap(() => { throw err("EINVAL"); }),
  };

  // A worker or a page has no `process`; Node's own is kept.
  if (!root.process) {
    root.process = {
      getuid() { return -1; }, getgid() { return -1; }, geteuid() { return -1; }, getegid() { return -1; },
      getgroups() { throw err("ENOSYS"); }, pid: -1, ppid: -1,
      umask() { return 0o022; }, cwd() { return "/"; }, chdir() { throw err("ENOSYS"); },
    };
  }
  root.fs = FS;

  // Which flag each option is. Values are always glued with "=", so a value
  // that starts with "-" can never be read as another flag.
  const OPTS = {
    format: "--output-target", inputFormat: "--input-target", base: "--base", load: "--load", entry: "--entry",
    name: "--name", pad: "--pad", gapFill: "--gap-fill", padTo: "--pad-to", maxSize: "--max-size",
    uimageArch: "--uimage-arch", uimageComp: "--uimage-comp", uf2Family: "--uf2-family",
    verilogWidth: "--verilog-data-width", verilogEndian: "--verilog-endian",
    ihexMode: "--ihex-mode", srecAddrLen: "--srec-addr-len", time: "--time",
    changeAddresses: "--change-addresses",
  };
  const BOOLS = { useVaddr: "--use-vaddr", crlf: "--crlf", srecCount: "--srec-count" };
  const LISTS = { only: "--only-section", remove: "--remove-section", region: "--region" };

  // buildArgs turns the options of the page into the command line. Unknown
  // options are an error, not ignored: a typo must not silently change nothing.
  function buildArgs(o, inPath, outPath) {
    const a = [];
    for (const [k, v] of Object.entries(o || {})) {
      if (v === undefined || v === null || v === "" || v === false) continue;
      if (k in OPTS) {
        a.push(OPTS[k] + "=" + v);
      } else if (k in BOOLS) {
        if (v === true) a.push(BOOLS[k]);
      } else if (k in LISTS) {
        for (const x of Array.isArray(v) ? v : [v]) if (x !== "") a.push(LISTS[k] + "=" + x);
      } else {
        throw new Error("unknown option " + k);
      }
    }
    if (!a.some((x) => x.startsWith("--max-size="))) a.push("--max-size=" + DEFAULT_MAX_SIZE);
    else {
      const m = Number(a.find((x) => x.startsWith("--max-size=")).slice(11));
      if (!(m > 0) || m > MAX_MAX_SIZE) throw new Error("--max-size must be between 1 and " + MAX_MAX_SIZE);
    }
    a.push("-o", outPath, inPath);
    return a;
  }

  let queue = Promise.resolve();

  // run executes the command with args on the given files ({path: Uint8Array})
  // and resolves {code, stdout, stderr, files}. Each run gets a new Go instance
  // and a new file system, so nothing survives from one run to the next and the
  // memory goes back when the result is dropped.
  function run(module, args, files) {
    const job = queue.then(() => runNow(module, args, files));
    queue = job.catch(() => {});
    return job;
  }

  async function runNow(module, args, files) {
    sess = newSession();
    try {
      for (const [p, bytes] of Object.entries(files || {})) {
        if (bytes.length > MAX_INPUT) throw new Error(p + " is " + bytes.length + " bytes, above the " + MAX_INPUT + " byte limit");
        const q = norm(p);
        sess.files.set(q, { data: bytes, size: bytes.length, mode: S_IFREG | 0o644, mtimeMs: Date.now(), ino: ino++ });
        sess.total += bytes.length;
      }
      const go = new root.Go();
      go.argv = ["fwimg", ...args];
      go.env = {};
      let code = 0;
      go.exit = (c) => { code = c; };
      const instance = await WebAssembly.instantiate(module, go.importObject);
      await go.run(instance);
      const dec = new TextDecoder();
      const text = (parts) => dec.decode(concat(parts));
      return { code, stdout: text(sess.out), stderr: text(sess.errb), files: sess.files };
    } finally {
      // keep sess for the caller to read result.files; the next run replaces it
    }
  }

  function concat(parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const r = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { r.set(p, o); o += p.length; }
    return r;
  }

  // convert is what the page calls: the input bytes and the options in, the
  // output bytes and the `info` of the input (as JSON text) out.
  // inputName is the name the input goes by in messages and in `info` (the
  // file's own name, cleaned: it becomes a path inside the in-memory file system).
  function safeName(n) {
    n = String(n || "input").split(/[\\/]/).pop().replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 100);
    return n === "" || n === "." || n === ".." || n === "out" ? "input" : n;
  }

  async function convert(module, input, options, inputName) {
    if (!(input instanceof Uint8Array)) throw new Error("input must be a Uint8Array");
    if (input.length === 0) throw new Error("the input is empty");
    if (input.length > MAX_INPUT) throw new Error("the input is " + input.length + " bytes, above the " + MAX_INPUT + " byte limit of the playground");
    const inPath = "/" + safeName(inputName);
    const args = buildArgs(options, inPath, "/out");
    const r = await run(module, args, { [inPath]: input });
    const out = r.files.get("/out");
    const res = {
      ok: r.code === 0 && !!out, code: r.code, stderr: r.stderr, args,
      output: out ? out.data.slice(0, out.size) : null, info: null, outputInfo: null,
    };
    // info of the input, whatever the conversion did: the person sees what
    // fwimg read even when the conversion is refused.
    // Only the options that say how to READ the input apply to info.
    const ia = ["info", "--json"];
    const o = options || {};
    for (const k of ["inputFormat", "base", "verilogWidth", "verilogEndian"]) if (o[k]) ia.push(OPTS[k] + "=" + o[k]);
    if (o.useVaddr === true) ia.push("--use-vaddr");
    ia.push(inPath);
    const i = await run(module, ia, { [inPath]: input });
    if (i.code === 0) res.info = i.stdout;
    else res.infoError = i.stderr;
    if (res.output) {
      // The output is read back as what it is; a flat binary has no format to
      // detect and is left without an info.
      const j = await run(module, ["info", "--json", "/out"], { "/out": res.output });
      if (j.code === 0) res.outputInfo = j.stdout;
    }
    return res;
  }

  async function compile(bytes) {
    return WebAssembly.compile(bytes);
  }

  const api = { run, convert, compile, buildArgs, safeName, limits: { MAX_INPUT, MAX_FS_BYTES, DEFAULT_MAX_SIZE, MAX_MAX_SIZE } };
  root.FwimgEngine = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : self);
