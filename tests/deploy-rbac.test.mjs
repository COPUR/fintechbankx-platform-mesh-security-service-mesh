// Deploy RBAC: terraform-modules github-oidc maps each service deploy role to
// the Kubernetes group fintechbankx:deploy:<namespace> through an EKS access
// entry without an access policy. generated/deploy-rbac.yaml binds that group,
// in its own namespace only, to a Role with the Helm release verbs on the kinds
// the service charts render (tests/fixtures/deploy-chart-resources.json) and
// read-only access for diagnosing a failed rollout. No Secrets: the
// cicd-templates helm-deploy.yml keeps releases in ConfigMaps
// (HELM_DRIVER=configmap).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract, serviceNamespaces } from '../scripts/lib/contract.mjs';

const contract = loadContract();
const NAME = 'fintechbankx-deploy';
const RBAC = 'rbac.authorization.k8s.io';
const docs = YAML.parseAllDocuments(readFileSync(join(repoRoot, 'deploy/kustomize/base/generated/deploy-rbac.yaml'), 'utf8'))
  .map((d) => d.toJSON())
  .filter(Boolean);
const fixture = JSON.parse(readFileSync(join(repoRoot, 'tests/fixtures/deploy-chart-resources.json'), 'utf8'));
const serviceNs = serviceNamespaces(contract).map((n) => n.name).sort();
const roles = docs.filter((d) => d.kind === 'Role');
const bindings = docs.filter((d) => d.kind === 'RoleBinding');
const rules = roles.flatMap((r) => r.rules.map((rule) => ({ ns: r.metadata.namespace, ...rule })));

/** Verbs the Role of `ns` grants on (apiGroup, resource). */
function verbs(ns, apiGroup, resource) {
  const out = new Set();
  for (const r of rules.filter((x) => x.ns === ns)) {
    if (r.apiGroups.includes(apiGroup) && r.resources.includes(resource)) r.verbs.forEach((v) => out.add(v));
  }
  return out;
}

const READ = ['get', 'list', 'watch'];
const RELEASE = ['create', 'get', 'update', 'patch', 'delete'];
// Read-only, not rendered by any chart: helm --wait lists ReplicaSets; pods and
// events explain a failed rollout or hook (helm reads neither).
const READ_ONLY = [
  { apiGroup: '', resource: 'pods' },
  { apiGroup: 'apps', resource: 'replicasets' },
  { apiGroup: '', resource: 'events' },
  { apiGroup: 'events.k8s.io', resource: 'events' },
];

test('exactly one Role and one RoleBinding fintechbankx-deploy per kind: service namespace, none elsewhere', () => {
  assert.ok(serviceNs.length >= 7, 'lending, payments, customer, risk, compliance, open-finance, corebanking');
  assert.deepEqual(docs.map((d) => d.kind).filter((k) => k !== 'Role' && k !== 'RoleBinding'), [], 'nothing but Roles and RoleBindings');
  for (const set of [roles, bindings]) {
    assert.deepEqual(set.map((d) => d.metadata.namespace).sort(), serviceNs);
    for (const d of set) {
      assert.equal(d.apiVersion, `${RBAC}/v1`);
      assert.equal(d.metadata.name, NAME);
    }
  }
});

test("each RoleBinding binds exactly its namespace's deploy group to that namespace's Role", () => {
  for (const b of bindings) {
    const ns = b.metadata.namespace;
    assert.deepEqual(b.subjects, [{ kind: 'Group', apiGroup: RBAC, name: `fintechbankx:deploy:${ns}` }], ns);
    assert.deepEqual(b.roleRef, { apiGroup: RBAC, kind: 'Role', name: NAME }, ns);
  }
});

test('the Role grants no Secrets, pod subresources, RBAC, NetworkPolicy, monitoring, Istio or secret stores, no wildcard and no escalation verb', () => {
  const forbiddenResources = new Set([
    'secrets', 'pods/exec', 'pods/log', 'pods/attach', 'pods/portforward', 'pods/proxy', 'pods/ephemeralcontainers',
    'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings', 'networkpolicies', 'secretstores', 'clustersecretstores',
    'serviceaccounts/token',
  ]);
  const forbiddenGroups = new Set([RBAC, 'networking.k8s.io', 'monitoring.coreos.com', 'admissionregistration.k8s.io']);
  const forbiddenVerbs = new Set(['escalate', 'bind', 'impersonate', 'deletecollection', '*']);
  assert.ok(rules.length > 0);
  for (const r of rules) {
    const where = `${r.ns}: ${JSON.stringify(r)}`;
    assert.deepEqual(Object.keys(r).sort(), ['apiGroups', 'ns', 'resources', 'verbs'], `${where}: no resourceNames or nonResourceURLs`);
    for (const g of r.apiGroups) {
      assert.ok(!g.includes('*'), `${where}: wildcard apiGroup`);
      assert.ok(!forbiddenGroups.has(g) && !g.endsWith('istio.io'), `${where}: apiGroup ${g}`);
    }
    for (const res of r.resources) {
      assert.ok(!res.includes('*'), `${where}: wildcard resource`);
      assert.ok(!forbiddenResources.has(res) && !res.includes('/'), `${where}: resource ${res}`);
    }
    for (const v of r.verbs) assert.ok(!forbiddenVerbs.has(v), `${where}: verb ${v}`);
  }
});

test('the Role covers every (apiGroup, resource) the surveyed service charts render with create, get, update, patch and delete', () => {
  assert.ok(fixture.resources.length >= 9);
  for (const ns of serviceNs) {
    for (const { apiGroup, resource } of fixture.resources) {
      const granted = verbs(ns, apiGroup, resource);
      for (const v of [...RELEASE, 'list', 'watch']) assert.ok(granted.has(v), `${ns}: ${apiGroup || 'core'}/${resource} lacks ${v}`);
    }
    for (const { apiGroup, resource } of READ_ONLY) {
      assert.deepEqual([...verbs(ns, apiGroup, resource)].sort(), [...READ].sort(), `${ns}: ${apiGroup || 'core'}/${resource} is read-only`);
    }
  }
});

test('the Role grants nothing beyond the chart kinds and the read-only set; opt-in platform kinds are not granted', () => {
  const allowed = new Set([...fixture.resources, ...READ_ONLY].map(({ apiGroup, resource }) => `${apiGroup}/${resource}`));
  for (const r of rules) {
    for (const g of r.apiGroups) for (const res of r.resources) assert.ok(allowed.has(`${g}/${res}`), `${r.ns}: ${g || 'core'}/${res} is not a chart kind`);
  }
  for (const ns of serviceNs) {
    for (const { apiGroup, resource } of fixture.optIn) assert.equal(verbs(ns, apiGroup, resource).size, 0, `${ns}: ${resource}`);
  }
});

test('the base kustomization lists generated/deploy-rbac.yaml', () => {
  const k = YAML.parse(readFileSync(join(repoRoot, 'deploy/kustomize/base/kustomization.yaml'), 'utf8'));
  assert.ok(k.resources.includes('generated/deploy-rbac.yaml'));
});

test('a surveyed chart that reads a Secret with lookup is named in the fixture and in the doc as not deployable', () => {
  // Helm 3.16 lookup returns empty only on NotFound; the Forbidden answer to a
  // Role without Secrets aborts the render on every upgrade --install.
  const lookups = fixture.secretLookups;
  assert.ok(lookups && typeof lookups === 'object', 'fixture.secretLookups');
  const doc = readFileSync(join(repoRoot, 'docs/mesh/DEPLOYABLE_MESH_BASELINE.md'), 'utf8');
  const section = doc.slice(doc.indexOf('## Deploy RBAC (Proposed)'), doc.indexOf('### Workload admission'));
  for (const [chart, where] of Object.entries(lookups)) {
    assert.ok(Object.keys(fixture.charts).some((k) => k.includes(chart)), `${chart} is a surveyed chart`);
    assert.match(where, /lookup "v1" "Secret"/, chart);
    const release = chart.split('/').pop().split(' ')[0];
    assert.match(section, new RegExp(`\\(${release}\\)[^]*does not\\s+deploy with this Role`), `doc names ${release} as not deployable`);
  }
  for (const ns of serviceNs) assert.equal(verbs(ns, '', 'secrets').size, 0, `${ns}: the fix is the chart, not a Secrets grant`);
});
