// The platform installs cert-manager and trust-manager (pinned jetstack Helm
// charts), then the platform PKI (ClusterIssuer, Bundles rds-ca-bundle and
// fintechbankx-internal-ca), then Istio, waiting after each step. Service
// charts assume ConfigMap rds-ca-bundle and the ClusterIssuer exist.
// The install script runs in plan mode here: it prints, it changes nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
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
    const cm = indexOf(s, /^helm upgrade --install cert-manager jetstack\/cert-manager /);
    const cmWait = indexOf(s, /^kubectl -n cert-manager wait --for=condition=Available .*deployment\/cert-manager-webhook/, cm);
    const tm = indexOf(s, /^helm upgrade --install trust-manager jetstack\/trust-manager /, cmWait);
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

  test(`${env}: every helm install pins its chart version and uses committed values`, () => {
    const installs = plan(env).filter((l) => l.startsWith('helm upgrade --install '));
    assert.equal(installs.length, 5);
    for (const l of installs) {
      const version = l.match(/--version (\S+)/)?.[1];
      assert.ok(version, `unpinned: ${l}`);
      assert.match(version, /^v?\d+\.\d+\.\d+$/, l);
      for (const f of [...l.matchAll(/-f (\S+)/g)].map((m) => m[1])) assert.ok(existsSync(f), `values file ${f}`);
      assert.ok(l.includes(' --wait'), `no --wait: ${l}`);
    }
    assert.ok(installs[0].includes(`--version ${CERT_MANAGER_VERSION} `));
    assert.ok(installs[1].includes(`--version ${TRUST_MANAGER_VERSION} `));
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
  const s = read('scripts/ci/validate-manifests.sh');
  assert.match(s, /"\$HELM" pull jetstack\/cert-manager --version "\$CERT_MANAGER_VERSION"/);
  assert.match(s, /"\$HELM" pull jetstack\/trust-manager --version "\$TRUST_MANAGER_VERSION"/);
  assert.match(s, /kubeconform_run -skip CustomResourceDefinition "\$OUT\/cert-manager\.yaml" "\$OUT\/trust-manager\.yaml"/);
});
