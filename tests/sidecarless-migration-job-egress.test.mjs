// Sidecar-less Flyway migration Jobs of customer, risk and compliance (CRC
// branch claude/customer-risk-compliance-deployable-ygi0zo, each chart's
// templates/migration-job.yaml and _helpers.tpl). The Job pods run WITHOUT an
// Istio sidecar (sidecar.istio.io/inject "false" written after podLabels),
// as their own ServiceAccount <service>-db-migration (no token), and carry
// app.kubernetes.io/name=<service>, instance=<release> and
// component=db-migration plus the chart's podLabels.
//  - each Job pod reaches DNS and its service's Aurora (5432) and nothing else:
//    no MSK, istiod, VPC endpoints, east-west or ingress;
//  - each is a documented R9 exception scoped to name + component;
//  - no other pod in those namespaces gains anything, and a pod with the same
//    labels in another namespace gets nothing an unlabelled pod there does not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract, expandEdges, serviceWorkloads, secretScopes, principal } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';
import { checkZeroTrust, loadRepoDocs } from '../scripts/validation/validate-strict-mtls.mjs';

const contract = loadContract();
const generatedText = (file) => readFileSync(join(repoRoot, 'deploy/kustomize/base/generated', file), 'utf8');
const netpols = YAML.parseAllDocuments(generatedText('network-policies.yaml')).map((d) => d.toJSON()).filter(Boolean);

// Pod template labels: <x>.migrationSelectorLabels + podLabels (without the
// inject key) + sidecar.istio.io/inject "false", plus the Job controller's labels.
const JOBS = [
  {
    ns: 'risk',
    owner: 'risk-decisioning-service',
    podLabels: { 'app.kubernetes.io/part-of': 'fintechbankx-risk', 'fintechbankx.io/service-id': 'svc-rsk-decisioning' },
  },
  {
    ns: 'customer',
    owner: 'customer-profile-kyc-service',
    podLabels: {
      app: 'customer-profile-kyc-service',
      'app.kubernetes.io/part-of': 'fintechbankx-customer',
      'fintechbankx.io/service-id': 'svc-cus-profile-kyc',
    },
  },
  {
    ns: 'compliance',
    owner: 'compliance-evidence-service',
    podLabels: { 'app.kubernetes.io/part-of': 'fintechbankx-compliance', 'fintechbankx.io/service-id': 'svc-cmp-evidence' },
  },
].map((j) => ({
  ...j,
  sa: `${j.owner}-db-migration`,
  pod: {
    'app.kubernetes.io/name': j.owner,
    'app.kubernetes.io/instance': j.owner,
    'app.kubernetes.io/component': 'db-migration',
    ...j.podLabels,
    'sidecar.istio.io/inject': 'false',
    'batch.kubernetes.io/job-name': `${j.owner}-db-migration`,
    'job-name': `${j.owner}-db-migration`,
  },
}));
const JOB_NS = new Set(JOBS.map((j) => j.ns));
const apiPod = (name, extra = {}) => ({
  'app.kubernetes.io/name': name,
  'app.kubernetes.io/instance': name,
  'app.kubernetes.io/component': 'service',
  ...extra,
});

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
const selecting = (docs, ns, labels, type) =>
  docs.filter(
    (d) => d.kind === 'NetworkPolicy' && d.metadata.namespace === ns && d.spec.policyTypes.includes(type) && selects(d.spec.podSelector, labels),
  );
const names = (docs) => docs.map((d) => d.metadata.name).sort();
const rules = (docs) =>
  docs.map((d) => ({ name: d.metadata.name, ingress: d.spec.ingress, egress: d.spec.egress })).sort((a, b) => a.name.localeCompare(b.name));
const workload = (c, j) => c.namespaces.find((n) => n.name === j.ns).workloads.find((w) => w.serviceAccount === j.sa);

for (const j of JOBS) {
  test(`${j.ns}: the migration Job is a sidecar-less db-migration workload matching the chart pod labels`, () => {
    const w = workload(contract, j);
    assert.ok(w, `${j.ns}/${j.sa} is in the mesh contract`);
    assert.equal(w.role, 'db-migration');
    assert.equal(w.migrates, j.owner);
    assert.deepEqual(w.selector, { 'app.kubernetes.io/name': j.owner, 'app.kubernetes.io/component': 'db-migration' });
    assert.ok(selects({ matchLabels: w.selector }, j.pod), 'selector matches the Job pod');
    assert.ok(!selects({ matchLabels: w.selector }, apiPod(j.owner, j.podLabels)), 'selector does not match the API pods');
    assert.equal(w.sidecar, false);
    assert.equal(w.service, null);
    assert.equal(w.destinationRule, false);
    assert.deepEqual(w.datastores, ['aurora-postgresql']);
  });

  test(`${j.ns}: the migration Job pod gets egress to DNS and its service's Aurora only`, () => {
    const egress = selecting(netpols, j.ns, j.pod, 'Egress');
    assert.deepEqual(names(egress), ['allow-egress-aurora', 'allow-egress-dns', 'default-deny-all']);
    const aurora = egress.find((d) => d.metadata.name === 'allow-egress-aurora');
    assert.ok(selects(aurora.spec.podSelector, apiPod(j.owner, j.podLabels)), 'the API pods use the same Aurora policy');
    assert.deepEqual(aurora.spec.egress, [{ to: [{ ipBlock: { cidr: '192.0.2.0/24' } }], ports: [{ protocol: 'TCP', port: 5432 }] }]);
    const dns = egress.find((d) => d.metadata.name === 'allow-egress-dns');
    assert.deepEqual(dns.spec.egress.flatMap((r) => r.ports.map((p) => `${p.protocol}/${p.port}`)), ['UDP/53', 'TCP/53']);
  });

  test(`${j.ns}: the migration Job pod gets no MSK, istiod, VPC, east-west egress and no ingress`, () => {
    const egress = names(selecting(netpols, j.ns, j.pod, 'Egress'));
    for (const n of ['allow-egress-msk', 'allow-egress-istiod', 'allow-egress-vpc-https', 'allow-egress-documentdb', 'allow-egress-redis']) {
      assert.ok(!egress.includes(n), `${n} selects the Job pod`);
    }
    for (const n of egress) assert.ok(!/-to-/.test(n), `${n} gives the Job pod east-west egress`);
    assert.deepEqual(names(selecting(netpols, j.ns, j.pod, 'Ingress')), ['default-deny-all']);
    // The API pods keep everything they had.
    const api = names(selecting(netpols, j.ns, apiPod(j.owner, j.podLabels), 'Egress'));
    for (const n of ['allow-egress-aurora', 'allow-egress-msk', 'allow-egress-istiod', 'allow-egress-vpc-https', `allow-egress-${j.owner}-to-identity`, `allow-egress-${j.owner}-to-observability`]) {
      assert.ok(api.includes(n), `${j.owner} API pods lost ${n}`);
    }
    const apiIn = names(selecting(netpols, j.ns, apiPod(j.owner, j.podLabels), 'Ingress'));
    for (const n of ['allow-ingress-from-istio-ingress', 'allow-ingress-node-health', 'allow-ingress-observability-scrape']) {
      assert.ok(apiIn.includes(n), `${j.owner} API pods lost ${n}`);
    }
  });

  test(`${j.ns}: the migration Job has no in-mesh identity, edge or secret slug`, () => {
    const p = principal(contract, j.ns, j.sa);
    for (const file of ['authorization-policies.yaml', 'request-authentication.yaml', 'destination-rules.yaml', 'ingress-routing.yaml', 'sidecars.yaml']) {
      assert.ok(!generatedText(file).includes(j.sa), `${file} names ${j.sa}`);
      assert.ok(!generatedText(file).includes(p), `${file} names ${p}`);
    }
    assert.ok(!expandEdges(contract).some((e) => e.from.sa === j.sa || e.to.sa === j.sa));
    assert.ok(!serviceWorkloads(contract).some((w) => w.serviceAccount === j.sa));
    assert.deepEqual(secretScopes(contract)[j.ns], [j.owner]);
  });

  test(`${j.ns}: R9 exception scoped to the Job, not the service`, () => {
    const refs = contract.exceptions.workloadInjection.map((x) => x.workload);
    assert.ok(refs.includes(`${j.ns}/${j.sa}`));
    assert.ok(!refs.includes(`${j.ns}/${j.owner}`), 'the Deployment keeps its sidecar');
    const deployable = loadRepoDocs().filter((d) => ['deploy/', 'k8s/platform/'].some((x) => d.file.startsWith(x)));
    assert.deepEqual(checkZeroTrust(deployable, contract).filter((e) => e.startsWith('R9')), []);
    const c = structuredClone(contract);
    c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== `${j.ns}/${j.sa}`);
    assert.ok(checkZeroTrust(deployable, c).some((e) => e.startsWith(`R9 ${j.ns}/${j.sa}`)));
  });
}

// Baseline: the same contract without the three Job workloads (and their exceptions).
const withoutJobs = () => {
  const c = structuredClone(contract);
  for (const j of JOBS) {
    const n = c.namespaces.find((x) => x.name === j.ns);
    n.workloads = n.workloads.filter((w) => w.serviceAccount !== j.sa);
    c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== `${j.ns}/${j.sa}`);
  }
  return c;
};

test('nothing else in customer, risk or compliance gains anything; other namespaces are unchanged', () => {
  const now = render(contract);
  const before = render(withoutJobs());
  for (const file of Object.keys(now).filter((f) => f !== 'network-policies.yaml')) {
    assert.deepEqual(now[file], before[file], `${file} changed`);
  }
  const outside = (docs) => docs.filter((d) => !JOB_NS.has(d.metadata.namespace));
  assert.deepEqual(outside(now['network-policies.yaml']), outside(before['network-policies.yaml']));
  for (const j of JOBS) {
    const probes = [
      apiPod(j.owner, j.podLabels),
      { 'app.kubernetes.io/name': j.owner }, // chart without a component label
      { 'app.kubernetes.io/name': j.owner, 'app.kubernetes.io/component': 'history-guard-check' },
      { 'app.kubernetes.io/name': 'something-else', 'app.kubernetes.io/component': 'service' },
      {}, // any other pod in the namespace
    ];
    for (const labels of probes) {
      for (const type of ['Ingress', 'Egress']) {
        assert.deepEqual(
          rules(selecting(now['network-policies.yaml'], j.ns, labels, type)),
          rules(selecting(before['network-policies.yaml'], j.ns, labels, type)),
          `${j.ns} ${type} of ${JSON.stringify(labels)} changed`,
        );
      }
    }
    // The Job pod itself only loses: every rule it has now it also had before.
    for (const type of ['Ingress', 'Egress']) {
      const had = rules(selecting(before['network-policies.yaml'], j.ns, j.pod, type)).map((r) => JSON.stringify(r));
      for (const r of rules(selecting(now['network-policies.yaml'], j.ns, j.pod, type))) {
        assert.ok(had.includes(JSON.stringify(r)), `${j.ns} Job pod gained ${type} ${r.name}`);
      }
    }
  }
});

test('a pod with a Job pod\'s labels in another namespace gets nothing an unlabelled pod there does not get', () => {
  for (const j of JOBS) {
    for (const n of contract.namespaces.filter((x) => x.name !== j.ns)) {
      // A subset: in customer, risk or compliance the component exclusion
      // gives such a pod less than an unlabelled pod, never more.
      for (const type of ['Ingress', 'Egress']) {
        const base = names(selecting(netpols, n.name, {}, type));
        for (const name of names(selecting(netpols, n.name, j.pod, type))) {
          assert.ok(base.includes(name), `${j.ns} Job-labelled pod in ${n.name} gains ${type} ${name}`);
        }
      }
      const ports = selecting(netpols, n.name, j.pod, 'Egress').flatMap((d) => (d.spec.egress || []).flatMap((r) => (r.ports || []).map((p) => p.port)));
      assert.ok(!ports.includes(5432), `${j.ns} Job-labelled pod reaches Aurora from ${n.name}`);
    }
  }
});

test('renderer refuses a loose or extended migration Job; a meshed one keeps istiod and still no MSK', () => {
  const mutate = (j, fn) => {
    const c = structuredClone(contract);
    fn(workload(c, j), c);
    return c;
  };
  for (const j of JOBS) {
    assert.throws(() => render(mutate(j, (w) => w.datastores.push('msk'))), /Aurora only/);
    assert.throws(() => render(mutate(j, (w) => (w.selector = { 'app.kubernetes.io/name': j.owner }))), /selector must be exactly/);
    assert.throws(() => render(mutate(j, (w) => (w.migrates = 'no-such-service'))), /migrates must name/);
    assert.throws(() => render(mutate(j, (w) => (w.serviceId = 'svc-x'))), /no inbound/);
    assert.throws(() => render(mutate(j, (w) => (w.destinationRule = true))), /no callee/);
    assert.throws(() => render(mutate(j, (w) => (w.sidecar = true))), /sidecar: false or absent/);
    assert.throws(
      () => render(mutate(j, (w, c) => c.edges.push({ from: `${j.ns}/${j.sa}`, to: 'identity/keycloak', port: 8080, methods: ['GET'], paths: ['/realms/*'] }))),
      /no call edge/,
    );
  }
  // A meshed Job (sidecar absent, native sidecar) is still rendered: istiod, never MSK.
  const j = JOBS[0];
  const meshed = render(mutate(j, (w) => delete w.sidecar))['network-policies.yaml'];
  const egress = names(selecting(meshed, j.ns, j.pod, 'Egress'));
  assert.ok(egress.includes('allow-egress-istiod') && egress.includes('allow-egress-aurora'), egress.join(', '));
  assert.ok(!egress.includes('allow-egress-msk'));
  assert.doesNotThrow(() => render(contract));
});
