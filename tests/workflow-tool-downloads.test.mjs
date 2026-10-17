// Tool downloads in this repository's workflows (DevSecOps should-fix, 2026-10-17):
//   1. every curl or wget download in .github/workflows/*.yml writes to a file (never
//      piped into tar), and the next line of the same run block that uses that file is
//      `echo "<sha256>  <file>" | sha256sum -c -`, so nothing is extracted unchecked.
//      UNCHECKED_ALLOWED lists the downloads that have no sha256 yet. It may only shrink:
//      the only download it may ever hold is the mesh repository's helm download;
//   2. each install step runs with stub uname, curl, sha256sum, tar and sudo on PATH for
//      x86_64 and aarch64 (asset and sha256 for that architecture, checked before tar),
//      for riscv64 (::error::, nothing downloaded), with a checksum mismatch (nothing
//      extracted) and with a version other than the pinned one (::error::, nothing
//      downloaded).
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

const DOWNLOAD = /(^|[\s;&|(!`])(curl|wget)\s/;
const PIPE = /(^|[^|])\|(?!\|)/;
const SHA_CHECK = /^echo\s+"(?:[0-9a-f]{64}|\$\{?\w+\}?)\s\s(.+)"\s*\|\s*sha256sum\s+-c\s+-$/;
const unquote = (s) => s.replace(/["']/g, "");

// Run body -> lines with continuations joined, without blanks and comments.
const logicalLines = (run) =>
  run
    .replace(/\\\n[ \t]*/g, " ")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));

// Every download in one run block, each with the reason it is unsafe (or null).
function downloadsIn(run) {
  const lines = logicalLines(run);
  return lines.flatMap((line, i) => {
    const m = DOWNLOAD.exec(line);
    if (!m) return [];
    const rest = line.slice(m.index + m[0].length);
    const url = (rest.match(/https?:\/\/[^\s"']+/) ?? [""])[0];
    const d = { line, url, problem: null };
    if (PIPE.test(rest)) return [{ ...d, problem: "is piped instead of written to a file" }];
    const out = rest.match(m[2] === "curl" ? /(?:^|\s)(?:-o|--output)\s+("[^"]+"|'[^']+'|\S+)/ : /(?:^|\s)(?:-O|--output-document)\s+("[^"]+"|'[^']+'|\S+)/);
    if (!out) return [{ ...d, problem: "does not write to a named file" }];
    const file = unquote(out[1]);
    const next = lines.slice(i + 1).find((l) => unquote(l).includes(file));
    const check = next && SHA_CHECK.exec(next);
    if (!check || unquote(check[1]) !== file) {
      return [{ ...d, problem: `is not checked with sha256sum -c before ${file} is next used` }];
    }
    return [d];
  });
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

// Stubs that log their calls. curl writes its -o file, sha256sum exits shaExit, tar
// creates each member it is asked for (basename) in its -C directory, sudo only logs.
function stubs(arch, shaExit = 0) {
  const bin = fs.mkdtempSync(path.join(tmpRoot, "bin-"));
  const log = path.join(bin, "calls.log");
  const write = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  write("uname", `[ "$1" = "-m" ] && echo ${arch} || echo Linux`);
  write("curl", `echo "curl $*" >> "${log}"; out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done; [ -n "$out" ] && echo fake > "$out"; exit 0`);
  write("sha256sum", `echo "sha256sum $* <<$(cat)" >> "${log}"; exit ${shaExit}`);
  write(
    "tar",
    `echo "tar $*" >> "${log}"; dir=""; members=()
while [ $# -gt 0 ]; do case "$1" in -C) dir="$2"; shift 2 ;; -xzf|-f) shift 2 ;; -*) shift ;; *) members+=("$1"); shift ;; esac; done
for m in "\${members[@]}"; do b="\${m##*/}"; printf '#!/bin/sh\\necho "%s stub"\\n' "$b" > "$dir/$b"; chmod +x "$dir/$b"; done`,
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
  const env = { ...wf.env, ...job.env, ...step.env };
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
      assert.ok(check < calls.indexOf(`tar -xzf ${file} `), `${t.bin} checked before it is extracted`);
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
  ];
  for (const [e, files, message] of unpinned) {
    const other = stubs("x86_64");
    const r = runStep(step.run, e, other.bin, files);
    assert.notEqual(r.status, 0, "a version other than the pinned one fails the step");
    assert.match(r.out, message);
    assert.equal(other.log(), "", "nothing is downloaded for an unpinned version");
  }
});
