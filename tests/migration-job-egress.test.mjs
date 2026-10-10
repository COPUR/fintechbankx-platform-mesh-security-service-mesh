// Flyway migration Job pods (Helm pre-install/pre-upgrade hook) carry their
// service's app.kubernetes.io/name and app.kubernetes.io/component=db-migration
// (cicd-templates 335a345). They must reach the service's Aurora database and
// nothing else a service pod gets: no MSK, no inbound, no call edge.
//  - allow-egress-msk selects name AND component=service, so no migration pod
//    (and no pod without the component label) reaches the brokers;
//  - allow-egress-aurora selects the name only, so the migration pod does;
//  - compliance-evidence-service-db-migration (own ServiceAccount) is a
//    workload of its own: no RequestAuthentication, no AuthorizationPolicy,
//    no secret slug, and the renderer refuses MSK, edges or a loose selector.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract, secretScopes, expandEdges, principal } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const contract = loadContract();
const generated = (file) =>
  YAML.parseAllDocuments(readFileSync(join(repoRoot, 'deploy/kustomize/base/generated', file), 'utf8'))
    .map((d) => d.toJSON())
    .filter(Boolean);
const netpols = generated('network-policies.yaml');

/** Kubernetes label selector semantics (matchLabels AND matchExpressions). */
function selects(selector, labels) {
  for (const [k, v] of Object.entries(selector.matchLabels || {})) if (labels[k] !== v) return false;
  for (const e of selector.matchExpressions || []) {
    const has = Object.hasOwn(labels, e.key);
    const ok = {
      In: () => has && e.values.includes(labels[e.key]),
      NotIn: () => !has || !e.values.includes(labels[e.key]),
      Exists: () => has,
      DoesNotExist: () => !has,
    }[e.operator];
    if (!ok) throw new Error(`unknown operator ${e.operator}`);
    if (!ok()) return false;
  }
  return true;
}

const pod = (name, component) => ({
  'app.kubernetes.io/name': name,
  'app.kubernetes.io/instance': name,
  ...(component ? { 'app.kubernetes.io/component': component } : {}),
});
const egressPoliciesSelecting = (ns, labels) =>
  netpols
    .filter((d) => d.metadata.namespace === ns && d.spec.policyTypes.includes('Egress') && selects(d.spec.podSelector, labels))
    .map((d) => d.metadata.name)
    .sort();

test('no MSK egress policy selects a db-migration pod; the API pod is selected', () => {
  const msk = netpols.filter((d) => d.metadata.name === 'allow-egress-msk');
  assert.ok(msk.length >= 6, 'every service namespace with MSK users has the policy');
  for (const d of msk) {
    const names = d.spec.podSelector.matchExpressions.find((e) => e.key === 'app.kubernetes.io/name').values;
    for (const name of names) {
      const where = `${d.metadata.namespace}/${name}`;
      assert.equal(selects(d.spec.podSelector, pod(name, 'db-migration')), false, `${where} migration pod reaches MSK`);
      assert.equal(selects(d.spec.podSelector, pod(name, 'service')), true, `${where} API pod lost MSK`);
      // Fail closed: a chart that does not label its pods component=service gets no MSK egress.
      assert.equal(selects(d.spec.podSelector, pod(name)), false, `${where} pod without component reaches MSK`);
    }
  }
});

test('Aurora egress stays name-only, so every db-migration pod reaches its database', () => {
  const aurora = netpols.filter((d) => d.metadata.name === 'allow-egress-aurora');
  assert.ok(aurora.length >= 6);
  for (const d of aurora) {
    assert.deepEqual(d.spec.podSelector.matchExpressions.map((e) => e.key), ['app.kubernetes.io/name']);
    for (const name of d.spec.podSelector.matchExpressions[0].values) {
      assert.equal(selects(d.spec.podSelector, pod(name, 'db-migration')), true, `${d.metadata.namespace}/${name}`);
    }
  }
});

test('the compliance migration Job pod reaches Aurora and never MSK', () => {
  const job = contract.namespaces.find((n) => n.name === 'compliance').workloads.find(
    (w) => w.serviceAccount === 'compliance-evidence-service-db-migration',
  );
  assert.ok(job, 'compliance-evidence-service-db-migration is in the mesh contract');
  assert.equal(job.role, 'db-migration');
  const labels = { ...job.selector, 'app.kubernetes.io/instance': 'compliance-evidence-service' };
  assert.deepEqual(egressPoliciesSelecting('compliance', labels), [
    'allow-egress-aurora',
    // The service's edge egress keys on its name label only, so it selects the
    // Job pod at L3/L4 too; no AuthorizationPolicy admits the Job's principal
    // (next test), so Keycloak and the collector reject it. Narrowing these
    // to component=service waits for every chart to carry the label.
    'allow-egress-compliance-evidence-service-to-identity',
    'allow-egress-compliance-evidence-service-to-observability',
    'allow-egress-dns',
    'allow-egress-istiod',
    'allow-egress-vpc-https', // namespace-wide (podSelector {}), not specific to the Job
    'default-deny-all',
  ]);
  assert.ok(!egressPoliciesSelecting('compliance', labels).includes('allow-egress-msk'));
  // The API pod of the same service keeps MSK.
  assert.ok(egressPoliciesSelecting('compliance', pod('compliance-evidence-service', 'service')).includes('allow-egress-msk'));
});

test('the compliance migration Job has no inbound, no call edge and no secret slug of its own', () => {
  const sa = 'compliance-evidence-service-db-migration';
  const p = principal(contract, 'compliance', sa);
  const text = (file) => readFileSync(join(repoRoot, 'deploy/kustomize/base/generated', file), 'utf8');
  for (const file of ['authorization-policies.yaml', 'request-authentication.yaml', 'destination-rules.yaml', 'ingress-routing.yaml']) {
    assert.ok(!text(file).includes(sa), `${file} names ${sa}`);
  }
  assert.ok(!text('authorization-policies.yaml').includes(p));
  assert.ok(!expandEdges(contract).some((e) => e.from.sa === sa || e.to.sa === sa));
  assert.deepEqual(secretScopes(contract).compliance, ['compliance-evidence-service']);
});

test('renderer refuses a migration Job with MSK, a loose selector, a call edge or inbound traffic', () => {
  const mutate = (fn) => {
    const c = structuredClone(contract);
    const job = c.namespaces.find((n) => n.name === 'compliance').workloads.find((w) => w.role === 'db-migration');
    fn(job, c);
    return c;
  };
  assert.throws(() => render(mutate((j) => j.datastores.push('msk'))), /Aurora only/);
  assert.throws(() => render(mutate((j) => (j.selector = { 'app.kubernetes.io/name': 'compliance-evidence-service' }))), /selector must be exactly/);
  assert.throws(() => render(mutate((j) => (j.migrates = 'risk-decisioning-service'))), /migrates must name/);
  assert.throws(() => render(mutate((j) => (j.apiPrefix = '/api/v1/migrate'))), /no inbound/);
  assert.throws(
    () =>
      render(
        mutate((j, c) =>
          c.edges.push({
            from: 'compliance/compliance-evidence-service-db-migration',
            to: 'identity/keycloak',
            port: 8080,
            methods: ['GET'],
            paths: ['/realms/*'],
          }),
        ),
      ),
    /no call edge/,
  );
  assert.doesNotThrow(() => render(contract));
});

test('the migration drill checklist stays under the Database migration Jobs section', () => {
  const doc = readFileSync(join(repoRoot, 'docs/mesh/DEPLOYABLE_MESH_BASELINE.md'), 'utf8').split('\n');
  const at = doc.findIndex((l) => l.startsWith('**Drill checklist for the first dev-cluster install**'));
  assert.ok(at > 0, 'drill checklist present');
  const heading = doc.slice(0, at).reverse().find((l) => /^#{1,6} /.test(l));
  assert.equal(heading, '### Database migration Jobs (Proposed)');
});
