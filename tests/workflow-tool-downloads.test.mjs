// Tool downloads in this repository's workflows (DevSecOps should-fix, 2026-10-17):
//   1. every curl or wget download in .github/workflows/*.yml (a curl or wget command
//      with an http(s):// URL argument) writes to a named file (never piped into tar),
//      nothing else on its own logical line uses that file, and the next logical line
//      is `echo "<sha256>  <file>" | sha256sum -c -`, so nothing is extracted unchecked.
//      UNCHECKED_ALLOWED lists the downloads that have no sha256 yet. It may only shrink:
//      the only download it may ever hold is the mesh repository's helm download;
//   2. each install step runs with stub uname, curl, sha256sum, tar and sudo on PATH for
//      x86_64 and aarch64 (asset and sha256 for that architecture, checked before tar,
//      and only members the real archive holds extracted), for riscv64 (::error::,
//      nothing downloaded), with a checksum mismatch (nothing extracted) and with a
//      version other than the pinned one (::error::, nothing downloaded).
import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflowsDir = path.join(repoRoot, ".github", "workflows");
const load = (file) => YAML.parse(fs.readFileSync(path.join(workflowsDir, file), "utf8"));

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "fbx-test-"));
after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));

// --- 1. static scan ----------------------------------------------------------------

// The one download allowed without a sha256: helm in this repository, whose sha256 is
// not pinned yet. Nothing may be added here; remove the entry once helm is pinned.
const MAY_ONLY_SHRINK_TO = [{ file: "mesh-manifests.yml", step: "Install validation tools", url: "https://get.helm.sh/" }];
const UNCHECKED_ALLOWED = [{ file: "mesh-manifests.yml", step: "Install validation tools", url: "https://get.helm.sh/" }];

const SHA_CHECK = /^echo\s+"(?:[0-9a-f]{64}|\$\{?\w+\}?)\s\s(.+)"\s*\|\s*sha256sum\s+-c\s+-$/;
const unquote = (s) => s.replace(/["']/g, "");

// Run body -> lines with continuations joined, without blanks and comments.
const logicalLines = (run) =>
  run
    .replace(/\\\n[ \t]*/g, " ")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

// One logical line -> its token lists: first the line's own, then one for each command
// substitution in it ($( ), <( ), >( ) or backticks, also inside double quotes). A
// list holds shell words ({ word }, quotes and backslashes removed) and operators
// ({ op }); a substitution stays in the word it is part of as its source text, so
// -H "Authorization: Bearer $(cat t)" is one word. `{` and `}` as whole words are
// operators; a redirection such as 2>&1 stays one word; an unquoted # at the start of a
// word ends the line.
function shellTokens(line) {
  const lists = [];
  const frames = [{ tokens: [], word: null, dq: false, kind: null }];
  let f = frames[0];
  const add = (s) => (f.word = (f.word ?? "") + s);
  const flush = () => {
    if (f.word !== null) f.tokens.push(f.word === "{" || f.word === "}" ? { op: f.word } : { word: f.word });
    f.word = null;
  };
  const op = (o) => (flush(), f.tokens.push({ op: o }));
  const open = (kind, start) => frames.push((f = { tokens: [], word: null, dq: false, kind, start }));
  const close = (end) => {
    flush();
    const inner = frames.pop();
    lists.push(inner.tokens);
    f = frames[frames.length - 1];
    add(line.slice(inner.start, end));
  };
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    const two = line.slice(i, i + 2);
    if (c === "\\") {
      const n = line[++i] ?? "";
      add(f.dq && !'"$`\\'.includes(n) ? c + n : n);
    } else if (c === "'" && !f.dq) {
      const end = line.indexOf("'", i + 1);
      add(line.slice(i + 1, end < 0 ? line.length : end));
      i = end < 0 ? line.length : end;
    } else if (c === '"') {
      f.dq = !f.dq;
      add("");
    } else if (two === "$(" || (!f.dq && (two === "<(" || two === ">("))) {
      open("$(", i++);
    } else if (c === "`") {
      if (f.kind === "`" && !f.dq) close(i + 1);
      else open("`", i);
    } else if (c === ")" && !f.dq && f.kind === "$(") {
      close(i + 1);
    } else if (f.dq) {
      add(c);
    } else if (/\s/.test(c)) {
      flush();
    } else if (c === "#" && f.word === null) {
      break;
    } else if (c === ">" || c === "<" || two === "&>") {
      add(two === "&>" || two === ">&" || two === "<&" ? two : c);
      if (two === "&>" || two === ">&" || two === "<&") i++;
    } else if (["&&", "||", ";;", "|&"].includes(two)) {
      op(two);
      i++;
    } else if (";&|()".includes(c)) {
      op(c);
    } else {
      add(c);
    }
  }
  while (frames.length > 1) close(line.length);
  flush();
  return [f.tokens, ...lists];
}

// Token list -> its simple commands: the words of each and the operator after it.
function simpleCommands(tokens) {
  const cmds = [];
  let words = [];
  for (const t of tokens) {
    if ("word" in t) words.push(t.word);
    else if (words.length) cmds.push({ words, after: t.op });
    if (!("word" in t)) words = [];
  }
  if (words.length) cmds.push({ words, after: null });
  return cmds;
}

// The program a simple command runs, past assignments, the keywords that may start a
// command and the wrappers sudo, env, timeout, command, time, nice, stdbuf and xargs
// (xargs: true, its URLs come from its input); written as curl, /usr/bin/curl, \curl,
// "curl" or 'curl' it is curl. null when it runs nothing (command -v curl). A program
// held in a variable ("$CURL") is out of scope: the scan cannot see it.
const ASSIGNMENT = /^[A-Za-z_]\w*\+?=/;
const KEYWORDS = new Set(["!", "if", "then", "else", "elif", "do", "while", "until", "exec", "nohup", "builtin"]);
const WRAPPER_OPTIONS = { sudo: /^-[ugpCDhrtTU]$/, timeout: /^-[sk]$/, time: /^-[fo]$/, nice: /^-n$/, stdbuf: /^-[ioe]$/, xargs: /^-[adEILnPs]$/ };
function program(words) {
  const w = [...words];
  let xargs = false;
  const skipOptions = (withValue) => {
    while (w.length && w[0].startsWith("-")) if (withValue.test(w.shift())) w.shift();
  };
  for (;;) {
    while (w.length && (ASSIGNMENT.test(w[0]) || KEYWORDS.has(w[0]))) w.shift();
    if (!w.length) return null;
    const name = w[0].split("/").pop();
    if (name !== "env" && name !== "command" && !(name in WRAPPER_OPTIONS)) return { name, args: w.slice(1), xargs };
    w.shift();
    if (name === "env") {
      while (w.length && (w[0].startsWith("-") || ASSIGNMENT.test(w[0]))) if (/^-[uCS]$/.test(w.shift())) w.shift();
    } else if (name === "command") {
      if (w.length && /^-\w*[vV]/.test(w[0])) return null;
      skipOptions(/^$/);
    } else {
      skipOptions(WRAPPER_OPTIONS[name]);
      if (name === "timeout") w.shift(); // the duration
      if (name === "xargs") xargs = true;
    }
  }
}

// The commands `sh -c <string>` (also bash, dash, zsh, ksh, with -ec and the like) or
// `eval <words>` runs, or null.
const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh"]);
function shellString({ name, args }) {
  if (name === "eval") return args.join(" ");
  if (!SHELLS.has(name)) return null;
  let c = false;
  for (let k = 0; k < args.length; k++) {
    if (/^[-+]o$/.test(args[k])) k++;
    else if (/^-[A-Za-z]*c[A-Za-z]*$/.test(args[k])) c = true;
    else if (!/^[-+]/.test(args[k])) return c ? args[k] : null;
  }
  return null;
}

// The file a curl (-o f, --output f, --output=f, -sSfLo f) or wget (-O f, -qO f,
// --output-document f, --output-document=f) download writes, or null.
function outputFile({ name, args }) {
  const [short, long] = name === "curl" ? [/^-[A-Za-z0-9]*o$/, "--output"] : [/^-[A-Za-z0-9]*O$/, "--output-document"];
  for (let k = 0; k < args.length; k++) {
    if (args[k].startsWith(`${long}=`)) return args[k].slice(long.length + 1);
    if (args[k] === long || short.test(args[k])) return args[k + 1] ?? null;
  }
  return null;
}

// What may follow a download on its own line: echo, printf or exit (as in
// `|| { echo "::error::..."; exit 1; }`) or a bare assignment, none running a command
// substitution. Anything else (tar, cd, cp, mkdir, ...) may use the file before its check.
const SUBSTITUTION = /\$\(|`|[<>]\(/;
const harmless = (c) => {
  const p = program(c.words);
  return (!p || ["echo", "printf", "exit"].includes(p.name)) && !c.words.some((w) => SUBSTITUTION.test(w));
};

// Every download in one run block, each with the reason it is unsafe (or null). A download
// is a curl or wget command with an http(s):// URL argument (or behind xargs), so
// `apt-get install curl`, `command -v curl` or `curl --version` is none; a URL held only
// in a variable (curl "$u") is therefore not seen either, like a program held in a
// variable. sh -c and eval strings are scanned as run blocks of their own; any other
// command with a curl or wget word and a URL (retry curl URL) is flagged, as the scan
// cannot tell what it runs.
function downloadsIn(run) {
  const lines = logicalLines(run);
  return lines.flatMap((line, i) =>
    shellTokens(line).flatMap((tokens, nested) => {
      const cmds = simpleCommands(tokens);
      return cmds.flatMap((c, k) => {
        const p = program(c.words);
        if (!p) return [];
        const inner = shellString(p);
        if (inner !== null) return downloadsIn(inner);
        const urls = p.args.filter((a) => /^https?:\/\//.test(a));
        if (!["curl", "wget"].includes(p.name)) {
          const runs = !["echo", "printf"].includes(p.name) && p.args.find((a) => !a.includes("://") && ["curl", "wget"].includes(a.split("/").pop()));
          return runs && urls.length ? [{ line, url: urls[0], problem: `runs ${runs} through ${p.name}, which the scan cannot read` }] : [];
        }
        if (!urls.length && !p.xargs) return [];
        const d = { line, url: urls[0] ?? "", problem: null };
        const bad = (problem) => [{ ...d, problem }];
        if (urls.length > 1) return bad("fetches more than one URL; give each its own download");
        if (c.after === "|" || c.after === "|&") return bad("is piped instead of written to a file");
        const file = outputFile(p);
        if (!file || file === "-" || /^[<>]\(/.test(file)) return bad("does not write to a named file");
        if (nested) return bad("runs inside a command substitution; give it a line of its own");
        if (c.after === "&") return bad("runs in the background, so its check can run before it ends");
        if (!cmds.slice(k + 1).every(harmless)) return bad("is used on the download line before its sha256 check");
        const check = SHA_CHECK.exec(lines[i + 1] ?? "");
        if (!check || unquote(check[1]) !== file) {
          return bad(`is not checked with sha256sum -c on the line after the download of ${file}`);
        }
        return [d];
      });
    }),
  );
}

function workflowDownloads() {
  return fs
    .readdirSync(workflowsDir)
    .filter((f) => /\.ya?ml$/.test(f))
    .flatMap((file) =>
      Object.entries(load(file).jobs ?? {}).flatMap(([job, j]) =>
        (j.steps ?? [])
          .filter((s) => typeof s.run === "string")
          .flatMap((s) => downloadsIn(s.run).map((d) => ({ file, job, step: s.name, ...d }))),
      ),
    );
}
const allowed = (d) => UNCHECKED_ALLOWED.some((a) => a.file === d.file && a.step === d.step && d.url.startsWith(a.url));

test("the download scan flags piped, unchecked and late-checked downloads and passes checked ones", () => {
  const problem = (run) => downloadsIn(run).map((d) => d.problem);
  assert.deepEqual(problem('curl -sSfL "https://example.test/a.tgz" | tar -xz -C "$d"'), ["is piped instead of written to a file"]);
  assert.match(problem('curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz\ntar -xzf "$d/a.tgz" -C "$d"')[0], /not checked/);
  assert.match(
    problem('curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz\ntar -xzf "$d/a.tgz" -C "$d"\necho "${s}  $d/a.tgz" | sha256sum -c -')[0],
    /not checked/,
  );
  assert.match(problem('curl -sSfLO https://example.test/a.tgz\necho "${s}  a.tgz" | sha256sum -c -')[0], /named file/);
  assert.match(problem('curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz\nsha256sum -c "$d/a.tgz.sha256"\ntar -xzf "$d/a.tgz"')[0], /not checked/);
  assert.deepEqual(
    problem('curl -sSfL -o "$d/a.tgz" \\\n  "https://example.test/a.tgz"\necho "${sha256}  $d/a.tgz" | sha256sum -c -\ntar -xzf "$d/a.tgz" -C "$d" a'),
    [null],
  );
  assert.deepEqual(problem('wget -q -O "$d/a.tgz" https://example.test/a.tgz\necho "' + "a".repeat(64) + '  $d/a.tgz" | sha256sum -c -'), [null]);
  assert.deepEqual(problem('curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz || exit 1\necho "${s}  $d/a.tgz" | sha256sum -c -'), [null]);
});

const SELF_CHECK = '\necho "${s}  $d/a.tgz" | sha256sum -c -';
const scanProblems = (run) => downloadsIn(run).map((d) => d.problem);

test("the download scan flags a use of the file on the download line and wants the check on the very next line", () => {
  for (const use of [
    ' && tar -xzf "$d/a.tgz" -C "$d"',
    '; tar -xzf "$d/a.tgz" -C "$d"',
    ' && tar -xzf "$d/a.tgz" -C "$d" && sudo install "$d/a" /usr/local/bin/a',
    ' || cp "$d/a.tgz" "$d/b.tgz"',
  ]) {
    const run = `curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz${use}${SELF_CHECK}`;
    assert.deepEqual(scanProblems(run), ["is used on the download line before its sha256 check"], run);
  }
  assert.deepEqual(scanProblems(`wget -q -O "$d/a.tgz" https://example.test/a.tgz; tar -xzf "$d/a.tgz"${SELF_CHECK}`), [
    "is used on the download line before its sha256 check",
  ]);
  assert.match(scanProblems(`curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz\nmkdir -p "$d/x"${SELF_CHECK}`)[0], /not checked/);
  assert.deepEqual(scanProblems(`curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz && echo fetched\n\n# verify it${SELF_CHECK}`), [null]);
});

test("the download scan sees curl and wget however the command is spelled or wrapped", () => {
  const piped = ["is piped instead of written to a file"];
  for (const cmd of [
    "/usr/bin/curl",
    "\\curl",
    '"curl"',
    "'curl'",
    '"/usr/bin/curl"',
    "HTTPS_PROXY=http://proxy.test:3128 curl",
    "timeout 60 curl",
    "timeout -s KILL 60 curl",
    "command curl",
    "env -i PATH=/usr/bin curl",
    "sudo curl",
    "sudo -u runner -E curl",
    "sudo env A=1 timeout 30 curl",
    "! curl",
    "if curl",
  ]) {
    assert.deepEqual(scanProblems(`${cmd} -sSfL https://example.test/a.tgz | tar -xz -C "$d"`), piped, cmd);
  }
  assert.deepEqual(scanProblems('/usr/bin/wget -qO- https://example.test/a.tgz | tar -xz -C "$d"'), piped);
  assert.deepEqual(scanProblems('{ curl -sSfL https://example.test/a.tgz | tar -xz -C "$d"; }'), piped);
  for (const run of [
    "x=`curl -sSfL https://example.test/a.tgz`",
    'x="$(curl -sSfL https://example.test/a.tgz)"',
    'tar -xz -C "$d" < <(curl -sSfL https://example.test/a.tgz)',
    '{ curl -sSfL https://example.test/a.tgz; } > "$d/a.tgz"',
  ]) {
    assert.deepEqual(scanProblems(run), ["does not write to a named file"], run);
  }
  assert.deepEqual(scanProblems(`/usr/bin/curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz${SELF_CHECK}`), [null]);
});

test("the download scan ignores lines that download nothing and reads every output-file form", () => {
  for (const run of [
    "sudo apt-get install -y --no-install-recommends curl jq",
    'command -v curl >/dev/null || { echo "::error::curl missing"; exit 1; }',
    "curl --version",
    "wget --help",
    'echo "fetching with curl then verifying"',
    "kubectl version --client # unlike curl here",
  ]) {
    assert.deepEqual(scanProblems(run), [], run);
  }
  for (const dl of [
    'curl -sSfLo "$d/a.tgz" https://example.test/a.tgz',
    'curl -sSfL --output "$d/a.tgz" https://example.test/a.tgz',
    'curl -sSfL --output="$d/a.tgz" https://example.test/a.tgz',
    'wget -O "$d/a.tgz" https://example.test/a.tgz',
    'wget -qO "$d/a.tgz" https://example.test/a.tgz',
    'wget -q --output-document "$d/a.tgz" https://example.test/a.tgz',
    'wget -q --output-document="$d/a.tgz" https://example.test/a.tgz',
  ]) {
    assert.deepEqual(scanProblems(dl + SELF_CHECK), [null], dl);
    assert.match(scanProblems(dl)[0], /not checked/, dl);
  }
  assert.match(scanProblems(`wget -qO - https://example.test/a.tgz > "$d/a.tgz"${SELF_CHECK}`)[0], /named file/);
});

test("the download scan keeps a command substitution inside the word it belongs to", () => {
  const piped = ["is piped instead of written to a file"];
  for (const run of [
    'curl -sSfL -H "Authorization: Bearer $(cat "$RUNNER_TEMP/token")" https://example.test/a.tgz | tar -xz -C "$d"',
    'curl -sSfL -A "fbx-$(uname -m)" https://example.test/a.tgz | tar -xz -C "$d"',
    'curl -sSfL -A "x`uname -m`" https://example.test/a.tgz | tar -xz -C "$d"',
  ]) {
    assert.deepEqual(scanProblems(run), piped, run);
  }
  const archFile = 'curl -sSfL -o "$d/x-$(uname -m).tgz" https://example.test/a.tgz';
  assert.match(scanProblems(`${archFile}\ntar -xzf "$d"/x-*.tgz`)[0], /not checked/);
  assert.deepEqual(scanProblems(`${archFile}\necho "\${s}  $d/x-$(uname -m).tgz" | sha256sum -c -`), [null]);
  assert.deepEqual(scanProblems('curl -sSfL -o >(tar -xz -C "$d") https://example.test/a.tgz'), ["does not write to a named file"]);
  assert.deepEqual(scanProblems('wget -q -O >(tar -xz -C "$d") https://example.test/a.tgz'), ["does not write to a named file"]);
});

test("the download scan reads curl and wget behind time, nice, stdbuf, builtin, xargs, sh -c and eval", () => {
  const piped = ["is piped instead of written to a file"];
  for (const run of [
    'sudo sh -c "cd /usr/local/bin && curl -sSfL https://example.test/a.tgz | tar -xz"',
    "bash -ec 'curl -sSfL https://example.test/a.tgz | tar -xz -C /usr/local/bin'",
    'bash -o pipefail -c "curl -sSfL https://example.test/a.tgz | tar -xz"',
    'eval "curl -sSfL https://example.test/a.tgz | tar -xz"',
    'time -p curl -sSfL https://example.test/a.tgz | tar -xz -C "$d"',
    'nice -n 10 curl -sSfL https://example.test/a.tgz | tar -xz -C "$d"',
    'nice -10 wget -qO- https://example.test/a.tgz | tar -xz -C "$d"',
    'stdbuf -o L curl -sSfL https://example.test/a.tgz | tar -xz -C "$d"',
    'builtin command curl -sSfL https://example.test/a.tgz | tar -xz -C "$d"',
    "echo https://example.test/a.tgz | xargs curl -sSfL | tar -xz",
    "echo https://example.test/a.tgz | xargs -n 1 -P 2 curl -sSfL | tar -xz",
  ]) {
    assert.deepEqual(scanProblems(run), piped, run);
  }
  assert.deepEqual(scanProblems('retry -t 3 -- curl -sSfL https://example.test/a.tgz | tar -xz -C "$d"'), [
    "runs curl through retry, which the scan cannot read",
  ]);
});

test("the download scan wants one URL per curl or wget command", () => {
  for (const run of [
    `curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz -o "$d/b.tgz" https://example.test/b.tgz${SELF_CHECK}\ntar -xzf "$d/b.tgz"`,
    `curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz https://example.test/b.tgz > "$d/b.tgz"${SELF_CHECK}\ntar -xzf "$d/b.tgz"`,
    `wget -q -O "$d/a.tgz" https://example.test/a.tgz https://example.test/b.tgz${SELF_CHECK}`,
  ]) {
    assert.deepEqual(scanProblems(run), ["fetches more than one URL; give each its own download"], run);
  }
});

test("the download scan lets only echo, printf or exit follow a download on its line", () => {
  const dl = 'curl -sSfL -o "$d/a.tgz" https://example.test/a.tgz';
  for (const rest of [
    ' && tar -xzf "${d}/a.tgz" -C "$d"',
    ' && cd "$d" && tar -xzf a.tgz',
    ' && mkdir -p "$d/x"',
    ' && echo "$(tar -xzf "${d}/a.tgz")"',
    ' || { cp "${d}/a.tgz" "$d/b.tgz"; exit 1; }',
  ]) {
    assert.deepEqual(scanProblems(dl + rest + SELF_CHECK), ["is used on the download line before its sha256 check"], rest);
  }
  assert.deepEqual(scanProblems(`${dl} &${SELF_CHECK}`), ["runs in the background, so its check can run before it ends"]);
  for (const rest of [
    ' || { echo "::error::could not download $d/a.tgz" >&2; exit 1; }',
    ' && echo "downloaded $d/a.tgz"',
  ]) {
    assert.deepEqual(scanProblems(dl + rest + SELF_CHECK), [null], rest);
  }
  assert.deepEqual(scanProblems('curl -sSfL -o f https://example.test/a.tgz && echo fetched\necho "${s}  f" | sha256sum -c -'), [null]);
});

test("every curl or wget download in .github/workflows is sha256-checked before it is used", () => {
  const found = workflowDownloads();
  for (const step of ["Install gitleaks", "Install validation tools"]) {
    assert.ok(found.some((d) => d.step === step), `the scan sees the download in '${step}'`);
  }
  const problems = found.filter((d) => d.problem && !allowed(d)).map((d) => `${d.file} '${d.step}': ${d.url || d.line} ${d.problem}`);
  assert.deepEqual(problems, []);
});

test("the unchecked-download allowlist only shrinks and holds no stale entry", () => {
  for (const a of UNCHECKED_ALLOWED) {
    assert.ok(
      MAY_ONLY_SHRINK_TO.some((m) => m.file === a.file && m.step === a.step && m.url === a.url),
      `${a.file} '${a.step}' ${a.url} may not be added: check its sha256 instead`,
    );
  }
  const found = workflowDownloads();
  for (const a of UNCHECKED_ALLOWED) {
    assert.ok(
      found.some((d) => d.problem && d.file === a.file && d.step === a.step && d.url.startsWith(a.url)),
      `${a.file} '${a.step}' ${a.url} is checked now: remove it from UNCHECKED_ALLOWED`,
    );
  }
});

// --- 2. stubbed runs -----------------------------------------------------------------

// Members of each pinned release asset, as tar -tzf lists them on the real archive.
const ARCHIVE_MEMBERS = {
  "gitleaks_8.24.3_linux_x64.tar.gz": ["gitleaks", "LICENSE", "README.md"],
  "gitleaks_8.24.3_linux_arm64.tar.gz": ["gitleaks", "LICENSE", "README.md"],
  "kubeconform-linux-amd64.tar.gz": ["kubeconform", "LICENSE"],
  "kubeconform-linux-arm64.tar.gz": ["kubeconform", "LICENSE"],
  "kustomize_v5.5.0_linux_amd64.tar.gz": ["kustomize"],
  "kustomize_v5.5.0_linux_arm64.tar.gz": ["kustomize"],
  "istioctl-1.24.3-linux-amd64.tar.gz": ["istioctl"],
  "istioctl-1.24.3-linux-arm64.tar.gz": ["istioctl"],
  "helm-v3.16.3-linux-amd64.tar.gz": ["linux-amd64/helm", "linux-amd64/LICENSE", "linux-amd64/README.md"],
  "helm-v3.16.3-linux-arm64.tar.gz": ["linux-arm64/helm", "linux-arm64/LICENSE", "linux-arm64/README.md"],
};

// Stubs that log their calls. curl writes the URL's asset name to its -o file,
// sha256sum exits shaExit, sudo only logs. tar knows the members of each asset in
// ARCHIVE_MEMBERS: it creates the members it is asked for (all when none is named) in
// its -C directory after --strip-components, and like GNU tar it exits 2 with "Not found
// in archive" for a member the archive does not hold.
function stubs(arch, shaExit = 0) {
  const bin = fs.mkdtempSync(path.join(tmpRoot, "bin-"));
  const log = path.join(bin, "calls.log");
  const write = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  write("uname", `[ "$1" = "-m" ] && echo ${arch} || echo Linux`);
  write(
    "curl",
    `echo "curl $*" >> "${log}"; out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; http://*|https://*) url="$1" ;; esac; shift; done
[ -n "$out" ] && printf '%s\\n' "\${url##*/}" > "$out"; exit 0`,
  );
  write("sha256sum", `echo "sha256sum $* <<$(cat)" >> "${log}"; exit ${shaExit}`);
  const held = Object.entries(ARCHIVE_MEMBERS).map(([asset, members]) => `  ${asset}) held=(${members.join(" ")}) ;;`);
  write(
    "tar",
    `echo "tar $*" >> "${log}"; dir=.; file=""; strip=0; members=()
while [ $# -gt 0 ]; do case "$1" in -C) dir="$2"; shift 2 ;; --strip-components=*) strip="\${1#*=}"; shift ;; -f|-*f) file="$2"; shift 2 ;; -*) shift ;; *) members+=("$1"); shift ;; esac; done
case "$(cat "$file" 2>/dev/null)" in
${held.join("\n")}
  *) echo "tar: $file: Cannot open: not a release asset this stub knows" >&2; exit 2 ;;
esac
[ \${#members[@]} -gt 0 ] || members=("\${held[@]}")
status=0
for m in "\${members[@]}"; do
  found=""; for h in "\${held[@]}"; do [ "$h" = "$m" ] && found=1; done
  if [ -z "$found" ]; then echo "tar: $m: Not found in archive" >&2; status=2; continue; fi
  out="$m"; for ((k = 0; k < strip; k++)); do case "$out" in */*) out="\${out#*/}" ;; *) out="" ;; esac; done
  [ -n "$out" ] || continue
  mkdir -p "$dir/$(dirname "$out")"; printf '#!/bin/sh\\necho "%s stub"\\n' "\${out##*/}" > "$dir/$out"; chmod +x "$dir/$out"
done
[ "$status" -eq 0 ] || echo "tar: Exiting with failure status due to previous errors" >&2
exit "$status"`,
  );
  write("sudo", `echo "sudo $*" >> "${log}"`);
  return { bin, log: () => (fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "") };
}

function runStep(run, env, stubBin, files = {}) {
  const dir = fs.mkdtempSync(path.join(tmpRoot, "step-"));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  const ghPath = path.join(dir, "github-path");
  fs.writeFileSync(ghPath, "");
  const script = path.join(dir, "step.sh");
  fs.writeFileSync(script, run);
  const res = spawnSync("bash", ["--noprofile", "--norc", "-e", script], {
    cwd: dir,
    encoding: "utf8",
    env: { PATH: `${stubBin}:${process.env.PATH}`, HOME: dir, RUNNER_TEMP: path.join(dir, "runner-temp"), GITHUB_PATH: ghPath, ...env },
  });
  const ghPathLines = fs.readFileSync(ghPath, "utf8").split("\n").filter(Boolean);
  return { status: res.status, out: res.stdout + res.stderr, runnerTemp: path.join(dir, "runner-temp"), path: ghPathLines };
}

// [asset, tar arguments before -C is added, the file it creates or null when tar fails]
const STUB_TAR_CASES = [
  ["gitleaks_8.24.3_linux_x64.tar.gz", "gitleaks", "gitleaks"],
  ["gitleaks_8.24.3_linux_arm64.tar.gz", "gitleaks_8.24.3/gitleaks", null],
  ["kubeconform-linux-amd64.tar.gz", "kubeconform", "kubeconform"],
  ["kubeconform-linux-arm64.tar.gz", "./kubeconform", null],
  ["kustomize_v5.5.0_linux_amd64.tar.gz", "kustomize", "kustomize"],
  ["kustomize_v5.5.0_linux_arm64.tar.gz", "kustomize_v5.5.0/kustomize", null],
  ["istioctl-1.24.3-linux-amd64.tar.gz", "istioctl", "istioctl"],
  ["istioctl-1.24.3-linux-arm64.tar.gz", "./istioctl", null],
  ["helm-v3.16.3-linux-amd64.tar.gz", "--strip-components=1 linux-amd64/helm", "helm"],
  ["helm-v3.16.3-linux-arm64.tar.gz", "--strip-components=1 linux-amd64/helm", null],
  ["helm-v3.16.3-linux-arm64.tar.gz", "--strip-components=1 helm", null],
];

test("the stub tar extracts only the members the real release archive holds", () => {
  for (const [asset, args, creates] of STUB_TAR_CASES) {
    const s = stubs("x86_64");
    const r = runStep(
      `mkdir -p "$RUNNER_TEMP/x"\ncurl -sSfL -o "$RUNNER_TEMP/a.tgz" https://example.test/r/${asset}\ntar -xzf "$RUNNER_TEMP/a.tgz" -C "$RUNNER_TEMP/x" ${args}`,
      {},
      s.bin,
    );
    if (creates) {
      assert.equal(r.status, 0, `${asset} ${args}: ${r.out}`);
      assert.ok(fs.existsSync(path.join(r.runnerTemp, "x", creates)), `${asset} ${args} creates ${creates}`);
    } else {
      assert.equal(r.status, 2, `${asset} ${args} fails like GNU tar: ${r.out}`);
      assert.match(r.out, /Not found in archive/, `${asset} ${args}`);
    }
  }
});

// Release sha256 per architecture, from each release's own checksum file.
const STEPS = [
  {
    file: "required-gates.yml", job: "security", step: "Install gitleaks", bin: "gitleaks", dl: "gitleaks-dl", versionEnv: null,
    asset: { x86_64: "gitleaks_8.24.3_linux_x64.tar.gz", aarch64: "gitleaks_8.24.3_linux_arm64.tar.gz" },
    sha: { x86_64: "9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c", aarch64: "5f2edbe1f49f7b920f9e06e90759947d3c5dfc16f752fb93aaafc17e9d14cf07" },
  },
];

for (const t of STEPS) {
  test(`${t.file} '${t.step}' fetches the ${t.bin} asset for the runner architecture, checks its pinned sha256, then extracts`, () => {
    const wf = load(t.file);
    const step = wf.jobs[t.job].steps.find((s) => s.name === t.step);
    assert.ok(step, `${t.file} job ${t.job}: step '${t.step}' missing`);
    const env = { ...wf.env, ...wf.jobs[t.job].env, ...step.env };
    for (const arch of ["x86_64", "aarch64"]) {
      const s = stubs(arch);
      const r = runStep(step.run, env, s.bin);
      assert.equal(r.status, 0, r.out);
      const calls = s.log();
      const file = path.join(r.runnerTemp, t.dl, `${t.bin}.tar.gz`);
      assert.ok(calls.includes(`curl -sSfL -o ${file} `) && calls.includes(`/${t.asset[arch]}\n`), calls);
      assert.ok(calls.includes(`sha256sum -c - <<${t.sha[arch]}  ${file}\n`), calls);
      assert.ok(calls.indexOf("sha256sum") < calls.indexOf("tar "), "checksum before extract");
      assert.ok(calls.includes(`tar -xzf ${file} -C ${path.join(r.runnerTemp, t.dl)} ${t.bin}\n`), `${t.bin} is extracted by its member name: ${calls}`);
      const src = path.join(r.runnerTemp, t.dl, t.bin);
      assert.ok(calls.includes(`sudo install ${src} /usr/local/bin/${t.bin}\n`), calls);
      assert.ok(fs.existsSync(src), `${t.bin} is extracted to ${src}`);
    }
    const bad = stubs("aarch64", 1);
    const mismatch = runStep(step.run, env, bad.bin);
    assert.notEqual(mismatch.status, 0, "a checksum mismatch fails the step");
    assert.doesNotMatch(bad.log(), /^(tar|sudo) /m, "nothing is extracted or installed after a mismatch");
    const odd = stubs("riscv64");
    const unsupported = runStep(step.run, env, odd.bin);
    assert.notEqual(unsupported.status, 0);
    assert.match(unsupported.out, /::error::.*riscv64/);
    assert.equal(odd.log(), "", "nothing is downloaded for an unsupported architecture");
    if (t.versionEnv) {
      const other = stubs("x86_64");
      const unpinned = runStep(step.run, { ...env, [t.versionEnv]: "v9.9.9" }, other.bin);
      assert.notEqual(unpinned.status, 0, "a version other than the pinned one fails the step");
      assert.match(unpinned.out, /::error::.*v9\.9\.9/);
      assert.equal(other.log(), "", "nothing is downloaded for an unpinned version");
    }
  });
}

// "Install validation tools": kustomize, kubeconform and istioctl are pinned and checked;
// helm is fetched for the runner architecture but has no sha256 yet (UNCHECKED_ALLOWED).
const MESH_TOOLS = [
  { bin: "kustomize", asset: { x86_64: "kustomize_v5.5.0_linux_amd64.tar.gz", aarch64: "kustomize_v5.5.0_linux_arm64.tar.gz" },
    sha: { x86_64: "6703a3a70a0c47cf0b37694030b54f1175a9dfeb17b3818b623ed58b9dbc2a77", aarch64: "b4170d1acb8cfacace9f72884bef957ff56efdcd4813b66e7604aabc8b57e93d" } },
  { bin: "kubeconform", asset: { x86_64: "kubeconform-linux-amd64.tar.gz", aarch64: "kubeconform-linux-arm64.tar.gz" },
    sha: { x86_64: "95f14e87aa28c09d5941f11bd024c1d02fdc0303ccaa23f61cef67bc92619d73", aarch64: "dc82f79bb03c5479b1ae5fd4af221e4b5a3111f62bf01a2795d9c5c20fa96644" } },
  { bin: "istioctl", asset: { x86_64: "istioctl-1.24.3-linux-amd64.tar.gz", aarch64: "istioctl-1.24.3-linux-arm64.tar.gz" },
    sha: { x86_64: "877d629fee03cad68bf0d5561ea9fb64f287af28ec58581b8b6c49e5c650cbc9", aarch64: "264ef6ce29d3ef3789367342c2b6aa11872244b40920a04ac672bb3302e319a7" } },
];
const HELM_DIR = { x86_64: "linux-amd64", aarch64: "linux-arm64" };

test("mesh-manifests.yml 'Install validation tools' fetches each tool for the runner architecture and checks kustomize, kubeconform and istioctl before extracting", () => {
  const wf = load("mesh-manifests.yml");
  const job = wf.jobs["render-and-validate"];
  const step = job.steps.find((s) => s.name === "Install validation tools");
  assert.ok(step, "step 'Install validation tools' missing");
  // GitHub sets RUNNER_ENVIRONMENT to github-hosted or self-hosted.
  const env = { ...wf.env, ...job.env, ...step.env, RUNNER_ENVIRONMENT: "github-hosted" };
  const istioFile = "deploy/istio/ISTIO_VERSION";
  const pinned = { [istioFile]: fs.readFileSync(path.join(repoRoot, istioFile), "utf8") };
  for (const arch of ["x86_64", "aarch64"]) {
    const s = stubs(arch);
    const r = runStep(step.run, env, s.bin, pinned);
    assert.equal(r.status, 0, r.out);
    const calls = s.log();
    for (const t of MESH_TOOLS) {
      const file = path.join(r.runnerTemp, "dl", `${t.bin}.tar.gz`);
      assert.ok(calls.includes(`curl -sSfL -o ${file} `) && calls.includes(`/${t.asset[arch]}\n`), `${t.bin}: ${calls}`);
      const check = calls.indexOf(`sha256sum -c - <<${t.sha[arch]}  ${file}\n`);
      assert.ok(check >= 0, `${t.bin} checked against its ${arch} sha256: ${calls}`);
      const extract = calls.indexOf(`tar -xzf ${file} -C ${path.join(r.runnerTemp, "bin")} ${t.bin}\n`);
      assert.ok(extract >= 0, `${t.bin} is extracted by its member name: ${calls}`);
      assert.ok(check < extract, `${t.bin} checked before it is extracted`);
    }
    const helm = path.join(r.runnerTemp, "dl", "helm.tar.gz");
    assert.ok(calls.includes(`curl -sSfL -o ${helm} https://get.helm.sh/helm-${env.HELM_VERSION}-${HELM_DIR[arch]}.tar.gz\n`), calls);
    assert.ok(calls.includes(`tar -xzf ${helm} -C ${path.join(r.runnerTemp, "bin")} --strip-components=1 ${HELM_DIR[arch]}/helm\n`), calls);
    assert.deepEqual(r.path, [path.join(r.runnerTemp, "bin")], "the tool directory is added to GITHUB_PATH");
    for (const b of ["kustomize", "kubeconform", "istioctl", "helm"]) {
      assert.ok(fs.existsSync(path.join(r.runnerTemp, "bin", b)), `${b} is in the GITHUB_PATH directory`);
    }
    assert.match(r.out, /helm stub/, "the step ends by running the installed helm");
  }
  const bad = stubs("aarch64", 1);
  const mismatch = runStep(step.run, env, bad.bin, pinned);
  assert.notEqual(mismatch.status, 0, "a checksum mismatch fails the step");
  assert.doesNotMatch(bad.log(), /^tar /m, "nothing is extracted after a mismatch");
  const odd = stubs("riscv64");
  const unsupported = runStep(step.run, env, odd.bin, pinned);
  assert.notEqual(unsupported.status, 0);
  assert.match(unsupported.out, /::error::.*riscv64/);
  assert.equal(odd.log(), "", "nothing is downloaded for an unsupported architecture");
  const unpinned = [
    [{ ...env, KUSTOMIZE_VERSION: "v9.9.9" }, pinned, /::error::.*kustomize v9\.9\.9/],
    [{ ...env, KUBECONFORM_VERSION: "v9.9.9" }, pinned, /::error::.*kubeconform v9\.9\.9/],
    [env, { [istioFile]: "1.25.0\n" }, /::error::.*istioctl 1\.25\.0/],
    // helm, unpinned: another HELM_VERSION, or a runner that is not GitHub-hosted.
    [{ ...env, HELM_VERSION: "v3.17.0" }, pinned, /::error::helm v3\.17\.0 /],
    [{ ...env, RUNNER_ENVIRONMENT: "self-hosted" }, pinned, /::error::helm .*RUNNER_ENVIRONMENT=self-hosted/],
    [Object.fromEntries(Object.entries(env).filter(([k]) => k !== "RUNNER_ENVIRONMENT")), pinned, /::error::helm .*RUNNER_ENVIRONMENT=unset/],
  ];
  for (const [e, files, message] of unpinned) {
    const other = stubs("x86_64");
    const r = runStep(step.run, e, other.bin, files);
    assert.notEqual(r.status, 0, "a version other than the pinned one fails the step");
    assert.match(r.out, message);
    assert.equal(other.log(), "", "nothing is downloaded for an unpinned version");
  }
});
