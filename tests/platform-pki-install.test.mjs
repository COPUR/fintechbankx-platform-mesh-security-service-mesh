// The platform installs cert-manager and trust-manager (pinned jetstack Helm
// charts), then the platform PKI (ClusterIssuer, Bundles rds-ca-bundle and
// fintechbankx-internal-ca), then Istio, waiting after each step. Service
// charts assume ConfigMap rds-ca-bundle and the ClusterIssuer exist.
// Both chart archives are pinned by content (deploy/cert-manager/CHART_DIGESTS):
// pulled, checked with sha256sum -c and installed from the verified local file.
// The install script runs in plan mode here, or with --apply against stubbed
// helm and kubectl in a throwaway copy: nothing touches a cluster.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync, mkdtempSync, mkdirSync, cpSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import YAML, { parseAllDocuments } from 'yaml';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const yamlDocs = (p) => parseAllDocuments(read(p)).map((d) => d.toJS()).filter(Boolean);
const PINNED = /^v\d+\.\d+\.\d+$/;
const CERT_MANAGER_VERSION = read('deploy/cert-manager/CERT_MANAGER_VERSION').trim();
const TRUST_MANAGER_VERSION = read('deploy/cert-manager/TRUST_MANAGER_VERSION').trim();
const ENVS = ['dev', 'staging', 'prod'];

const plan = (env) =>
  execFileSync('bash', [join(ROOT, 'scripts/istio/install-mesh.sh'), env], { encoding: 'utf8' })
    .split('\n')
    .filter((l) => l.startsWith('+ '))
    .map((l) => l.slice(2));

const indexOf = (steps, re, from = 0) => {
  const i = steps.findIndex((s, n) => n >= from && re.test(s));
  assert.ok(i >= 0, `no step matching ${re} after step ${from}:\n${steps.join('\n')}`);
  return i;
};

test('chart versions are pinned to exact releases', () => {
  assert.match(CERT_MANAGER_VERSION, PINNED);
  assert.match(TRUST_MANAGER_VERSION, PINNED);
  // Newest lines whose e2e matrices cover Kubernetes 1.31 (the validated
  // K8S_VERSION); trust-manager v0.20 serves Bundle trust.cert-manager.io/v1alpha1.
  assert.match(CERT_MANAGER_VERSION, /^v1\.19\./);
  assert.match(TRUST_MANAGER_VERSION, /^v0\.20\./);
});

for (const env of ENVS) {
  test(`${env}: install order cert-manager -> trust-manager -> platform PKI -> Istio, each waited for`, () => {
    const s = plan(env);
    const cm = indexOf(s, /^helm upgrade --install cert-manager \S+\/cert-manager-v[\d.]+\.tgz /);
    const cmWait = indexOf(s, /^kubectl -n cert-manager wait --for=condition=Available .*deployment\/cert-manager-webhook/, cm);
    const tm = indexOf(s, /^helm upgrade --install trust-manager \S+\/trust-manager-v[\d.]+\.tgz /, cmWait);
    const tmWait = indexOf(s, /^kubectl -n cert-manager wait --for=condition=Available .*deployment\/trust-manager/, tm);
    const pki = indexOf(s, new RegExp(`^kubectl apply --server-side -k \\S*/deploy/kustomize/platform-pki/${env}$`), tmWait);
    const issuerWait = indexOf(s, /^kubectl wait --for=condition=Ready .*clusterissuer\/fintechbankx-internal-ca/, pki);
    const bundleWait = indexOf(s, /^kubectl wait --for=condition=Synced .*bundle\/rds-ca-bundle/, pki);
    const istioBase = indexOf(s, /^helm upgrade --install istio-base /, Math.max(issuerWait, bundleWait));
    const istiod = indexOf(s, /^helm upgrade --install istiod /, istioBase);
    const mesh = indexOf(s, new RegExp(`^kubectl apply --server-side -k \\S*/deploy/kustomize/overlays/${env}$`), istiod);
    const gateway = indexOf(s, /^helm upgrade --install istio-ingressgateway /, mesh);
    indexOf(s, /^verify ConfigMap rds-ca-bundle in every namespace/, gateway);
    // CRDs established before trust-manager (its chart creates a Certificate)
    // and before the PKI (Bundle objects).
    assert.ok(indexOf(s, /crd\/certificates\.cert-manager\.io/, cm) < tm);
    assert.ok(indexOf(s, /crd\/bundles\.trust\.cert-manager\.io/, tm) < pki);
    // External Secrets CRDs are a precondition checked before anything installs.
    assert.ok(indexOf(s, /^kubectl get crd externalsecrets\.external-secrets\.io/) < cm);
  });

  test(`${env}: every helm install pins its chart and uses committed values; jetstack charts from verified archives`, () => {
    const s = plan(env);
    const installs = s.filter((l) => l.startsWith('helm upgrade --install '));
    assert.equal(installs.length, 5);
    for (const l of installs) {
      for (const f of [...l.matchAll(/-f (\S+)/g)].map((m) => m[1])) assert.ok(existsSync(f), `values file ${f}`);
      assert.ok(l.includes(' --wait'), `no --wait: ${l}`);
    }
    // Istio: repository chart at a pinned version.
    for (const l of installs.slice(2)) assert.match(l, /--version \d+\.\d+\.\d+ /, l);
    // Jetstack: the pulled archive of the pinned version, never a repository reference.
    const archives = [`cert-manager-${CERT_MANAGER_VERSION}.tgz`, `trust-manager-${TRUST_MANAGER_VERSION}.tgz`];
    const charts = ['cert-manager', 'trust-manager'];
    installs.slice(0, 2).forEach((l, i) => {
      const chart = l.split(' ')[4];
      assert.ok(chart.endsWith(`/${archives[i]}`), l);
      assert.doesNotMatch(l, /jetstack\//, l);
      const pull = indexOf(s, new RegExp(`^helm pull jetstack/${charts[i]} --version ${[CERT_MANAGER_VERSION, TRUST_MANAGER_VERSION][i]} -d `));
      const verify = indexOf(s, new RegExp(`^verify_chart_archive \\S+/deploy/cert-manager/CHART_DIGESTS ${chart.replace(/[.]/g, '\\.')}$`), pull);
      // Both archives are verified before the first install.
      assert.ok(verify < s.indexOf(installs[0]), `${archives[i]} verified after an install`);
    });
  });
}

test('values: CRDs installed, trust namespace holds every Bundle source, ConfigMap targets only', () => {
  const cm = YAML.parse(read('deploy/cert-manager/helm/cert-manager.values.yaml'));
  const tm = YAML.parse(read('deploy/cert-manager/helm/trust-manager.values.yaml'));
  assert.equal(cm.crds.enabled, true);
  assert.equal(tm.crds.enabled, true);
  assert.equal(tm.secretTargets.enabled, false);
  const trustNs = tm.app.trust.namespace;

  const bundleFiles = [
    'k8s/platform/cert-manager/bundle-rds-ca.yaml',
    'k8s/platform/cert-manager/bundle-internal-ca.yaml',
    'deploy/kustomize/components/corporate-directory/corporate-directory-ca.yaml',
  ];
  const docs = bundleFiles.flatMap(yamlDocs);
  const bundles = docs.filter((d) => d.kind === 'Bundle');
  assert.equal(bundles.length, 3);
  for (const b of bundles) {
    assert.equal(b.apiVersion, 'trust.cert-manager.io/v1alpha1', `${b.metadata.name}: API served by trust-manager ${TRUST_MANAGER_VERSION}`);
    assert.ok(b.spec.target.configMap && !b.spec.target.secret, `${b.metadata.name}: secretTargets are disabled`);
    if (tm.defaultPackage?.enabled === false) {
      assert.ok(!b.spec.sources.some((s) => 'useDefaultCAs' in s), `${b.metadata.name}: useDefaultCAs needs defaultPackage`);
    }
  }
  assert.ok(bundles.some((b) => b.metadata.name === 'rds-ca-bundle'));

  // Source objects live in the trust namespace.
  const kustomization = YAML.parse(read('k8s/platform/cert-manager/kustomization.yaml'));
  const rdsSource = kustomization.configMapGenerator.find((g) => g.name === 'amazon-rds-ca-source');
  assert.equal(rdsSource.namespace, trustNs);
  const externalSecrets = [
    ...yamlDocs('k8s/platform/cert-manager/internal-ca-externalsecret.yaml'),
    ...docs,
  ].filter((d) => d.kind === 'ExternalSecret');
  for (const b of bundles) {
    for (const src of b.spec.sources) {
      const ref = src.secret || src.configMap;
      if (!ref) continue;
      const es = externalSecrets.find((e) => (e.spec.target?.name || e.metadata.name) === ref.name);
      const ns = es ? es.metadata.namespace : ref.name === 'amazon-rds-ca-source' ? rdsSource.namespace : undefined;
      assert.equal(ns, trustNs, `${b.metadata.name}: source ${ref.name} must be in ${trustNs}`);
    }
  }
});

test('platform-pki params equal the mesh overlay params', () => {
  const env = (p) =>
    Object.fromEntries(
      read(p)
        .split('\n')
        .filter((l) => l && !l.startsWith('#'))
        .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
    );
  for (const e of ENVS) {
    const pki = env(`deploy/kustomize/platform-pki/${e}/params.env`);
    const mesh = env(`deploy/kustomize/overlays/${e}/params.env`);
    assert.deepEqual(Object.keys(pki).sort(), ['AWS_REGION', 'ENVIRONMENT', 'PLATFORM_SECRETS_ROLE_ARN']);
    for (const [k, v] of Object.entries(pki)) assert.equal(v, mesh[k], `${e} ${k}`);
  }
  assert.deepEqual(readdirSync(join(ROOT, 'deploy/kustomize/platform-pki')).sort(), [...ENVS].sort());
});

test('no script applies manifests from a remote URL for cert-manager or trust-manager', () => {
  for (const f of readdirSync(join(ROOT, 'scripts/istio')).filter((n) => n.endsWith('.sh'))) {
    const s = read(`scripts/istio/${f}`);
    assert.doesNotMatch(s, /kubectl apply -f https?:\/\/\S*(cert-manager|trust-manager)/, f);
  }
});

test('validate-manifests renders and kubeconforms both jetstack charts at the pinned versions', () => {
  assert.match(read('scripts/ci/validate-manifests.sh'), /bash "\$ROOT\/scripts\/ci\/validate-jetstack-charts\.sh"/);
  const s = read('scripts/ci/validate-jetstack-charts.sh');
  assert.match(s, /"\$HELM" pull jetstack\/cert-manager --version "\$CERT_MANAGER_VERSION"/);
  assert.match(s, /"\$HELM" pull jetstack\/trust-manager --version "\$TRUST_MANAGER_VERSION"/);
  assert.match(s, /kubeconform_run -skip CustomResourceDefinition "\$OUT\/cert-manager\.yaml" "\$OUT\/trust-manager\.yaml"/);
});

// ------------------------------------------------------------ chart digests
const ARCHIVES = [`cert-manager-${CERT_MANAGER_VERSION}.tgz`, `trust-manager-${TRUST_MANAGER_VERSION}.tgz`];
const SHA256 = /^[0-9a-f]{64}$/;
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const digestLines = (text) =>
  text
    .split('\n')
    .filter((l) => l.trim() && !l.trimStart().startsWith('#'))
    .map((l) => l.trim().split(/\s+/));

test('CHART_DIGESTS names exactly the pinned archives, each with a sha256 or the marked placeholder', () => {
  const text = read('deploy/cert-manager/CHART_DIGESTS');
  const lines = digestLines(text);
  assert.deepEqual(lines.map(([, name]) => name).sort(), [...ARCHIVES].sort());
  for (const [digest, name] of lines) {
    assert.ok(SHA256.test(digest) || digest === 'PLACEHOLDER', `${name}: ${digest}`);
  }
  if (lines.some(([d]) => d === 'PLACEHOLDER')) {
    // A placeholder must say so: install --apply refuses it; CI prints the digests to fill it from.
    assert.match(text, /PLACEHOLDER - NOT A DIGEST/);
    assert.match(text, /install-mesh\.sh --apply fails closed/);
    assert.match(text, /CHART_DIGEST <archive> <sha256>/);
  }
});

// Charts pulled by the helm stub: deterministic content per chart and version.
const stubArchive = (chart, version) => `chart ${chart} ${version}\n`;
const STUB_HELM = `#!/usr/bin/env bash
echo "helm $*" >> "$STUB_LOG"
case "$1" in
  pull)
    ref="$2"; shift 2; ver=""; dir=""
    while [ $# -gt 0 ]; do case "$1" in --version) ver="$2"; shift 2;; -d) dir="$2"; shift 2;; *) shift;; esac; done
    chart="\${ref##*/}"
    printf 'chart %s %s\\n' "$chart" "$ver" > "$dir/$chart-$ver.tgz"
    if [ "\${STUB_TAMPER:-}" = "$chart" ]; then echo tampered >> "$dir/$chart-$ver.tgz"; fi ;;
  template)
    printf 'name: certificates.cert-manager.io\\nname: bundles.trust.cert-manager.io\\n- --trust-namespace=cert-manager\\n' ;;
esac
exit 0
`;
const STUB_LOGGER = (tool) => `#!/usr/bin/env bash\necho "${tool} $*" >> "$STUB_LOG"\nexit 0\n`;

/** Throwaway copy of the scripts and deploy/cert-manager, with stub tools on PATH. */
function sandbox(digests) {
  const dir = mkdtempSync(join(tmpdir(), 'pki-install-'));
  for (const p of ['scripts/istio/install-mesh.sh', 'scripts/lib/chart-digests.sh', 'scripts/ci/validate-jetstack-charts.sh', 'deploy/cert-manager', 'deploy/istio/ISTIO_VERSION']) {
    cpSync(join(ROOT, p), join(dir, p), { recursive: true });
  }
  if (digests !== undefined) writeFileSync(join(dir, 'deploy/cert-manager/CHART_DIGESTS'), digests);
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  for (const [tool, body] of [['helm', STUB_HELM], ['kubectl', STUB_LOGGER('kubectl')], ['kubeconform', STUB_LOGGER('kubeconform')]]) {
    writeFileSync(join(bin, tool), body);
    chmodSync(join(bin, tool), 0o755);
  }
  const log = join(dir, 'calls.log');
  writeFileSync(log, '');
  const runScript = (script, args, env = {}) => {
    const r = spawnSync('bash', [join(dir, script), ...args], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, STUB_LOG: log, ...env },
    });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr, calls: readFileSync(log, 'utf8').split('\n').filter(Boolean) };
  };
  return { dir, runScript, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const goodDigests = () =>
  `# test digests\n${sha256(stubArchive('cert-manager', CERT_MANAGER_VERSION))}  ${ARCHIVES[0]}\n` +
  `${sha256(stubArchive('trust-manager', TRUST_MANAGER_VERSION))}  ${ARCHIVES[1]}\n`;
const placeholderDigests = `PLACEHOLDER  ${ARCHIVES[0]}\nPLACEHOLDER  ${ARCHIVES[1]}\n`;
const mutating = (calls) => calls.filter((c) => /^helm (upgrade|install)|^kubectl (apply|create|delete|patch)/.test(c));

test('install-mesh --apply refuses a PLACEHOLDER digest before any helm or kubectl call', () => {
  const sb = sandbox(placeholderDigests);
  try {
    const r = sb.runScript('scripts/istio/install-mesh.sh', ['dev', '--apply']);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /refusing --apply/);
    assert.deepEqual(r.calls, []);
    // Plan mode still prints the plan, with a warning.
    const p = sb.runScript('scripts/istio/install-mesh.sh', ['dev']);
    assert.equal(p.status, 0);
    assert.match(p.stderr, /WARNING: plan only/);
  } finally {
    sb.cleanup();
  }
});

test('install-mesh --apply installs both jetstack charts from the verified archives', () => {
  const sb = sandbox(goodDigests());
  try {
    const r = sb.runScript('scripts/istio/install-mesh.sh', ['dev', '--apply']);
    assert.equal(r.status, 0, r.stderr);
    const installs = r.calls.filter((c) => /^helm upgrade --install (cert|trust)-manager /.test(c));
    assert.equal(installs.length, 2);
    installs.forEach((c, i) => assert.ok(c.split(' ')[4].endsWith(`/${ARCHIVES[i]}`), c));
  } finally {
    sb.cleanup();
  }
});

test('install-mesh --apply stops on a tampered archive before installing either chart', () => {
  for (const chart of ['cert-manager', 'trust-manager']) {
    const sb = sandbox(goodDigests());
    try {
      const r = sb.runScript('scripts/istio/install-mesh.sh', ['dev', '--apply'], { STUB_TAMPER: chart });
      assert.notEqual(r.status, 0, chart);
      assert.match(r.stderr, new RegExp(`${chart}-v[\\d.]+\\.tgz does not match its sha256`));
      assert.deepEqual(mutating(r.calls), [], `${chart}: ${r.calls.join('; ')}`);
    } finally {
      sb.cleanup();
    }
  }
});

test('validate-jetstack-charts: a PLACEHOLDER renders, prints CHART_DIGEST and passes; a mismatch fails', () => {
  const run = (digests, env = {}) => {
    const sb = sandbox(digests);
    try {
      return sb.runScript('scripts/ci/validate-jetstack-charts.sh', [], { OUT: join(sb.dir, 'out'), ...env });
    } finally {
      sb.cleanup();
    }
  };
  const templates = (r) => r.calls.filter((c) => c.startsWith('helm template')).length;
  const printed = (r) => r.stdout.split('\n').filter((l) => l.startsWith('CHART_DIGEST '));
  const stubDigest = (i) =>
    sha256(i === 0 ? stubArchive('cert-manager', CERT_MANAGER_VERSION) : stubArchive('trust-manager', TRUST_MANAGER_VERSION));

  // Placeholder: pulled, rendered and validated; each archive's sha256 printed; warning, exit 0.
  const placeholder = run(placeholderDigests);
  assert.equal(placeholder.status, 0, placeholder.stderr);
  assert.equal(templates(placeholder), 2);
  assert.ok(placeholder.calls.some((c) => c.startsWith('kubeconform ')));
  assert.deepEqual(printed(placeholder), ARCHIVES.map((a, i) => `CHART_DIGEST ${a} ${stubDigest(i)}`));
  assert.match(placeholder.stderr, /WARNING cert-manager-v[\d.]+\.tgz is NOT verified/);
  // The printed line is what an operator commits: it then verifies.
  const filled = printed(placeholder).map((l) => `${l.split(' ')[2]}  ${l.split(' ')[1]}`).join('\n') + '\n';
  const verified = run(filled);
  assert.equal(verified.status, 0, verified.stderr);
  assert.deepEqual(printed(verified), []);
  assert.equal(templates(verified), 2);

  // A committed digest that does not match fails before anything renders.
  const tampered = run(goodDigests(), { STUB_TAMPER: 'trust-manager' });
  assert.notEqual(tampered.status, 0);
  assert.equal(templates(tampered), 0, tampered.calls.join('; '));
  const wrong = run(`${'0'.repeat(64)}  ${ARCHIVES[0]}\nPLACEHOLDER  ${ARCHIVES[1]}\n`);
  assert.notEqual(wrong.status, 0);
  assert.equal(templates(wrong), 0);
  assert.match(wrong.stderr, /cert-manager-v[\d.]+\.tgz does not match its sha256/);
  // Mixed: the verified archive passes silently, the placeholder one is printed.
  const mixed = run(`${stubDigest(0)}  ${ARCHIVES[0]}\nPLACEHOLDER  ${ARCHIVES[1]}\n`);
  assert.equal(mixed.status, 0, mixed.stderr);
  assert.deepEqual(printed(mixed), [`CHART_DIGEST ${ARCHIVES[1]} ${stubDigest(1)}`]);

  const skipped = run(placeholderDigests, { JETSTACK_CHARTS: 'skip' });
  assert.equal(skipped.status, 0);
  assert.match(skipped.stderr, /NOT verified/);
  assert.deepEqual(skipped.calls, []);
  // A missing entry, a stray extra line or a malformed digest is an error, skipped or not.
  for (const env of [{}, { JETSTACK_CHARTS: 'skip' }]) {
    assert.notEqual(run(`PLACEHOLDER  ${ARCHIVES[0]}\n`, env).status, 0);
    assert.notEqual(run(`${placeholderDigests}PLACEHOLDER  cert-manager-v0.0.1.tgz\n`, env).status, 0);
    assert.notEqual(run(`TODO  ${ARCHIVES[0]}\nPLACEHOLDER  ${ARCHIVES[1]}\n`, env).status, 0);
  }
});

// ------------------------------------------- committed digests (published archives)
// The values come from two CI pulls of the published archives (Mesh Manifests
// run 38049446800, attempt 1 at 2026-10-10T11:44Z and attempt 2 at 14:54Z, on
// different runners), whose CHART_DIGEST lines agree.
const committedDigests = () => digestLines(read('deploy/cert-manager/CHART_DIGESTS'));

test('committed CHART_DIGESTS holds a sha256 for exactly the pinned archives and no PLACEHOLDER', () => {
  const text = read('deploy/cert-manager/CHART_DIGESTS');
  const lines = committedDigests();
  assert.equal(lines.length, 2, lines.map((l) => l.join(' ')).join('\n'));
  assert.deepEqual(lines.map(([, name]) => name), ARCHIVES);
  for (const l of lines) {
    assert.equal(l.length, 2, l.join(' '));
    assert.match(l[0], SHA256, l[1]);
  }
  assert.notEqual(lines[0][0], lines[1][0]);
  assert.doesNotMatch(text, /PLACEHOLDER/);
  // sha256sum -c format: digest, two spaces, archive name.
  const entries = text.split('\n').filter((l) => l.trim() && !l.trimStart().startsWith('#'));
  for (const l of entries) assert.match(l, /^[0-9a-f]{64} {2}(cert|trust)-manager-v\d+\.\d+\.\d+\.tgz$/, l);
  // The file says where the values came from.
  assert.match(text, /38049446800/);
});

test('install-mesh accepts the committed digests and still stops on an archive that does not match them', () => {
  const sb = sandbox(); // committed CHART_DIGESTS
  try {
    const p = sb.runScript('scripts/istio/install-mesh.sh', ['dev']);
    assert.equal(p.status, 0, p.stderr);
    assert.doesNotMatch(p.stderr, /WARNING: plan only|chart digests:/);
    // --apply passes the preflight, pulls, and refuses the stub archive (not the published one).
    const r = sb.runScript('scripts/istio/install-mesh.sh', ['dev', '--apply']);
    assert.notEqual(r.status, 0);
    assert.doesNotMatch(r.stderr, /refusing --apply/);
    assert.ok(r.calls.some((c) => c.startsWith('helm pull jetstack/cert-manager ')), r.calls.join('; '));
    assert.match(r.stderr, /cert-manager-v[\d.]+\.tgz does not match its sha256/);
    assert.deepEqual(mutating(r.calls), []);
  } finally {
    sb.cleanup();
  }
});

test('validate-jetstack-charts verifies against the committed digests: no warning, a mismatch fails before rendering', () => {
  const sb = sandbox();
  try {
    const skip = sb.runScript('scripts/ci/validate-jetstack-charts.sh', [], { OUT: join(sb.dir, 'out-skip'), JETSTACK_CHARTS: 'skip' });
    assert.equal(skip.status, 0, skip.stderr);
    assert.doesNotMatch(skip.stderr, /chart digests:/);
    const r = sb.runScript('scripts/ci/validate-jetstack-charts.sh', [], { OUT: join(sb.dir, 'out') });
    assert.notEqual(r.status, 0);
    assert.doesNotMatch(r.stdout, /^CHART_DIGEST /m);
    assert.doesNotMatch(r.stderr, /NOT verified|has no sha256/);
    assert.match(r.stderr, /does not match its sha256/);
    assert.equal(r.calls.filter((c) => c.startsWith('helm template')).length, 0);
  } finally {
    sb.cleanup();
  }
});

// CI runs `npm test` (which refuses a PLACEHOLDER, test above) before
// validate-manifests.sh, so a placeholder never reaches the warn-and-print
// path in CI. The scripts must say so: that path is a local step for an
// operator filling CHART_DIGESTS after a version bump.
test('jetstack digest scripts describe the placeholder path as local: CI fails a PLACEHOLDER at npm test', () => {
  const wf = read('.github/workflows/mesh-manifests.yml');
  const unit = wf.indexOf('npm test');
  const render = wf.indexOf('bash scripts/ci/validate-manifests.sh');
  assert.ok(unit >= 0 && render > unit, 'the workflow runs npm test before validate-manifests.sh');
  const header = (p) => read(p).split('\n').filter((l) => l.startsWith('#')).join('\n');
  for (const p of ['scripts/ci/validate-jetstack-charts.sh', 'scripts/ci/validate-manifests.sh', 'scripts/lib/chart-digests.sh']) {
    const h = header(p);
    assert.match(h, /tests\/platform-pki-install\.test\.mjs/, `${p}: names the test that fails a PLACEHOLDER in CI`);
    assert.doesNotMatch(h, /passes with a warning; only|^# CI only\./m, `${p}: still claims a PLACEHOLDER passes CI`);
  }
});
