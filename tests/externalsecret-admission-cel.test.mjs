// Executes the CEL of the generated ValidatingAdmissionPolicy
// fintechbankx-externalsecret-scope with cel-go (tests/cel/main.go), the CEL
// implementation the kube-apiserver uses, against concrete admission requests.
// Variables are composed as the apiserver does (in order, under `variables`);
// see tests/cel/main.go for what is not modelled (typed schemas, cost limits).
//
// Needs Go on PATH; cel-go comes from the module cache or the Go proxy. Without
// Go the tests are skipped (reported as skipped, never as passed).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { repoRoot, loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const ENV = 'prod';
const celDir = join(repoRoot, 'tests', 'cel');
const goAvailable = spawnSync('go', ['version'], { encoding: 'utf8' }).status === 0;
const skip = goAvailable ? false : 'go is not on PATH: the CEL of the admission policy was NOT evaluated';

// The policy as an overlay renders it: mesh-params replaces ENVIRONMENT.
function policySpec() {
  const [vap] = render(loadContract())['externalsecret-admission.yaml'];
  assert.equal(vap.kind, 'ValidatingAdmissionPolicy');
  const spec = structuredClone(vap.spec);
  const env = spec.variables.find((v) => v.name === 'env');
  assert.equal(env.expression, "'ENVIRONMENT'");
  env.expression = `'${ENV}'`;
  return spec;
}

const nsObject = (name, kind) => ({
  metadata: { name, labels: { 'kubernetes.io/metadata.name': name, 'fintechbankx.io/namespace-kind': kind } },
});
const SERVICE_NS = { payments: 'service', lending: 'service', observability: 'platform', sandbox: 'service' };

function admissionCase(name, ns, { label, store = 'aws-secrets-manager', storeKind = 'ClusterSecretStore', keys = [], dataFrom, data } = {}) {
  return {
    name,
    request: { namespace: ns, operation: 'CREATE', kind: { group: 'external-secrets.io', version: 'v1beta1', kind: 'ExternalSecret' } },
    namespaceObject: nsObject(ns, SERVICE_NS[ns]),
    object: {
      apiVersion: 'external-secrets.io/v1beta1',
      kind: 'ExternalSecret',
      metadata: { name, namespace: ns, ...(label ? { labels: { 'app.kubernetes.io/name': label } } : {}) },
      spec: {
        secretStoreRef: { kind: storeKind, name: store },
        ...(keys.length || data ? { data: data || keys.map((key, i) => ({ secretKey: `k${i}`, remoteRef: { key } })) } : {}),
        ...(dataFrom ? { dataFrom } : {}),
      },
    },
  };
}

function evaluate(spec, cases) {
  const run = spawnSync('go', ['run', '.'], {
    cwd: celDir,
    input: JSON.stringify({ policy: spec, cases }),
    encoding: 'utf8',
    env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'local', GOFLAGS: '-mod=readonly' },
    timeout: 300_000,
  });
  assert.equal(run.status, 0, `cel harness failed: ${run.stderr}`);
  return Object.fromEntries(JSON.parse(run.stdout).map((r) => [r.name, r]));
}

const BULK = 'payment-bulk-orchestration-service';
const cases = [
  admissionCase('own-slug', 'payments', { label: BULK, keys: [`${ENV}/${BULK}/db-app`, `${ENV}/${BULK}/oidc-client`] }),
  admissionCase('platform-internal-ca', 'payments', { label: BULK, keys: [`${ENV}/platform/internal-ca`] }),
  admissionCase('platform-internal-ca-extract', 'payments', { label: BULK, dataFrom: [{ extract: { key: `${ENV}/platform/internal-ca` } }] }),
  admissionCase('identity-keycloak', 'lending', { label: 'loan-lifecycle-service', keys: [`${ENV}/identity-keycloak/bootstrap-admin-client`] }),
  admissionCase('platform-store', 'payments', { label: BULK, store: 'aws-secrets-manager-platform', keys: [`${ENV}/${BULK}/db-app`] }),
  admissionCase('namespaced-store', 'payments', { label: BULK, storeKind: 'SecretStore', keys: [`${ENV}/${BULK}/db-app`] }),
  admissionCase('neighbour-slug', 'payments', { label: BULK, keys: [`${ENV}/payment-initiation-settlement-service/db-app`] }),
  admissionCase('foreign-label', 'payments', { label: 'loan-lifecycle-service', keys: [`${ENV}/loan-lifecycle-service/db-app`] }),
  admissionCase('unlabelled', 'payments', { keys: [`${ENV}/${BULK}/db-app`] }),
  admissionCase('other-environment', 'payments', { label: BULK, keys: [`staging/${BULK}/db-app`] }),
  admissionCase('find', 'lending', { label: 'loan-lifecycle-service', dataFrom: [{ find: { name: { regexp: '.*' } } }] }),
  admissionCase('source-ref', 'lending', {
    label: 'loan-lifecycle-service',
    data: [{ secretKey: 'k', remoteRef: { key: `${ENV}/loan-lifecycle-service/db-app` }, sourceRef: { storeRef: { kind: 'ClusterSecretStore', name: 'aws-secrets-manager-platform' } } }],
  }),
  admissionCase('shared-namespace', 'observability', { keys: [`${ENV}/observability/remote-write`, `${ENV}/observability-grafana/oidc-client`] }),
  admissionCase('shared-namespace-platform-key', 'observability', { keys: [`${ENV}/platform/internal-ca`] }),
  admissionCase('no-scope', 'sandbox', { label: 'anything', keys: [`${ENV}/anything/x`] }),
];

test('CEL: a service-namespace ExternalSecret for <env>/platform/internal-ca is rejected', { skip }, () => {
  const r = evaluate(policySpec(), cases);
  for (const name of ['platform-internal-ca', 'platform-internal-ca-extract']) {
    assert.equal(r[name].allowed, false, name);
    assert.deepEqual(r[name].messages, [`every remote key must start with ${ENV}/${BULK}/; got ${ENV}/platform/internal-ca`], name);
  }
  assert.equal(r['own-slug'].allowed, true, r['own-slug'].messages.join('; '));
});

test('CEL: store, slug, label, find and sourceRef rules reject; own and shared scopes admit', { skip }, () => {
  const r = evaluate(policySpec(), cases);
  const allowed = Object.entries(r).filter(([, v]) => v.allowed).map(([k]) => k).sort();
  assert.deepEqual(allowed, ['own-slug', 'shared-namespace']);
  const msg = (name) => r[name].messages.join(' | ');
  assert.match(msg('platform-store'), /secretStoreRef must be ClusterSecretStore aws-secrets-manager/);
  assert.match(msg('namespaced-store'), /secretStoreRef must be ClusterSecretStore aws-secrets-manager/);
  assert.match(msg('neighbour-slug'), /got prod\/payment-initiation-settlement-service\/db-app/);
  assert.match(msg('identity-keycloak'), /got prod\/identity-keycloak\/bootstrap-admin-client/);
  assert.match(msg('foreign-label'), /must carry label app.kubernetes.io\/name set to one of its service accounts: payment-bulk-orchestration-service, /);
  assert.match(msg('unlabelled'), /must carry label app.kubernetes.io\/name/);
  assert.match(msg('other-environment'), /got staging\//);
  assert.match(msg('find'), /no find, no sourceRef/);
  assert.match(msg('source-ref'), /may not override the store/);
  assert.match(msg('shared-namespace-platform-key'), /must start with prod\/observability\/ or prod\/observability-grafana\/; got prod\/platform\/internal-ca/);
  assert.match(msg('no-scope'), /namespace sandbox has no secret scope/);
});

test('CEL: the rejection comes from the key-prefix validation (the test can fail)', { skip }, () => {
  const spec = policySpec();
  spec.validations = spec.validations.filter((v) => !v.expression.includes('variables.prefixes.exists'));
  const r = evaluate(spec, cases);
  assert.equal(r['platform-internal-ca'].allowed, true, 'without the prefix rule the platform key would be admitted');
});
