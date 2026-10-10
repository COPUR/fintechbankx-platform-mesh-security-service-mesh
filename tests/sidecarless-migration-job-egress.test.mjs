// Sidecar-less Flyway migration Jobs (Helm pre-install/pre-upgrade hooks).
// Every service chart that renders a migration Job renders it WITHOUT an Istio
// sidecar (sidecar.istio.io/inject "false") with app.kubernetes.io/name=
// <service>, instance=<release> and component=db-migration:
//  - customer, risk and compliance (CRC branch
//    claude/customer-risk-compliance-deployable-ygi0zo, each chart's
//    templates/migration-job.yaml and _helpers.tpl) as their own
//    ServiceAccount <service>-db-migration (no token);
//  - loan-lifecycle (629444d), payment initiation/settlement (9671414),
//    recurring mandates (ceb45b5), bulk orchestration (fe1d583), request to
//    pay (2cd8e3c) and consent authorization (e4f56b1) as the namespace
//    default ServiceAccount (the pod spec names none) with
//    automountServiceAccountToken false. The pod labels below are the ones
//    each chart renders with its own CI args (deployability.yml, release
//    "ci"), plus the Job controller's labels.
// For each Job:
//  - its pod reaches DNS and its service's Aurora (5432) and nothing else:
//    no MSK, istiod, VPC endpoints, east-west or ingress;
//  - it is a documented R9 exception scoped to name + component;
//  - no other pod in those namespaces gains anything, and a pod with the same
//    labels in another namespace gets nothing an unlabelled pod there does not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract, expandEdges, serviceWorkloads, secretScopes, principal, knownServiceAccounts } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';
import { checkZeroTrust, loadRepoDocs } from '../scripts/validation/validate-strict-mtls.mjs';

const contract = loadContract();
const generatedText = (file) => readFileSync(join(repoRoot, 'deploy/kustomize/base/generated', file), 'utf8');
const netpols = YAML.parseAllDocuments(generatedText('network-policies.yaml')).map((d) => d.toJSON()).filter(Boolean);

const jobPod = (job, labels) => ({ ...labels, 'batch.kubernetes.io/job-name': job, 'job-name': job });

// CRC: pod template labels = <x>.migrationSelectorLabels + podLabels (without
// the inject key) + sidecar.istio.io/inject "false"; own ServiceAccount.
const CRC = [
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
  name: `${j.owner}-db-migration`,
  sa: `${j.owner}-db-migration`,
  pod: jobPod(`${j.owner}-db-migration`, {
    'app.kubernetes.io/name': j.owner,
    'app.kubernetes.io/instance': j.owner,
    'app.kubernetes.io/component': 'db-migration',
    ...j.podLabels,
    'sidecar.istio.io/inject': 'false',
  }),
  api: { 'app.kubernetes.io/name': j.owner, 'app.kubernetes.io/instance': j.owner, 'app.kubernetes.io/component': 'service', ...j.podLabels },
}));

// Namespace default ServiceAccount (no serviceAccountName, no token): pod
// labels exactly as rendered (templates/migration-job.yaml pod template),
// next to the service's Deployment pod labels from the same render.
const DEFAULT_SA = [
  {
    ns: 'lending',
    owner: 'loan-lifecycle-service',
    name: 'loan-lifecycle-service-db-migration', // loan 629444d migration-job.yaml:55-74
    pod: { 'fintechbankx.io/squad': 'lending' },
    api: { 'fintechbankx.io/squad': 'lending', 'app.kubernetes.io/part-of': 'fintechbankx-lending', 'fintechbankx.io/service-id': 'svc-ln-loan-lifecycle' },
  },
  {
    ns: 'payments',
    owner: 'payment-initiation-settlement-service',
    name: 'payment-initiation-settlement-service-db-migration', // initiation 9671414 migration-job.yaml:54-73
    pod: { 'fintechbankx.io/squad': 'payments' },
    api: { 'fintechbankx.io/squad': 'payments', 'app.kubernetes.io/part-of': 'fintechbankx-payments', 'fintechbankx.io/service-id': 'svc-pay-initiation-settlement' },
  },
  {
    ns: 'payments',
    owner: 'payment-recurring-mandates-service',
    name: 'payment-recurring-mandates-service-db-migration', // mandates ceb45b5 migration-job.yaml:58-77
    pod: {},
    api: { 'app.kubernetes.io/part-of': 'fintechbankx-payments', 'fintechbankx.io/service-id': 'svc-pay-recurring-mandates' },
  },
  {
    ns: 'payments',
    owner: 'payment-bulk-orchestration-service',
    name: 'payment-bulk-orchestration-service-db-migration', // bulk fe1d583 migration-job.yaml:55-79
    pod: { 'fintechbankx.io/squad': 'payments' },
    api: { 'fintechbankx.io/squad': 'payments', 'app.kubernetes.io/part-of': 'fintechbankx-payments', 'fintechbankx.io/service-id': 'svc-pay-bulk-orchestration' },
  },
  {
    ns: 'payments',
    owner: 'payment-request-to-pay-service',
    name: 'payment-request-to-pay-service-db-migration', // rtp 2cd8e3c migration-job.yaml:57-77
    pod: { 'fintechbankx.io/squad': 'payments' },
    api: { 'fintechbankx.io/squad': 'payments', 'app.kubernetes.io/part-of': 'fintechbankx-payments', 'fintechbankx.io/service-id': 'svc-pay-request-to-pay' },
  },
  {
    ns: 'open-finance',
    owner: 'consent-authorization-service',
    name: 'consent-authorization-service-migrate', // consent e4f56b1 migration-job.yaml:52-61
    pod: { 'fintechbankx.io/service-id': 'svc-of-consent-authorization' },
    api: { 'app.kubernetes.io/part-of': 'fintechbankx-open-finance', 'fintechbankx.io/service-id': 'svc-of-consent-authorization' },
  },
].map((j) => ({
  ...j,
  sa: 'default',
  pod: jobPod(j.name, {
    'app.kubernetes.io/name': j.owner,
    'app.kubernetes.io/instance': 'ci',
    'app.kubernetes.io/component': 'db-migration',
    ...j.pod,
    'sidecar.istio.io/inject': 'false',
  }),
  api: {
    'app.kubernetes.io/name': j.owner,
    'app.kubernetes.io/instance': 'ci',
    'app.kubernetes.io/component': 'service',
    app: j.owner,
    version: 'ci',
    ...j.api,
    'sidecar.istio.io/inject': 'true',
  },
}));

const JOBS = [...CRC, ...DEFAULT_SA];
const JOB_NS = new Set(JOBS.map((j) => j.ns));
const apiPod = (name) => ({ 'app.kubernetes.io/name': name, 'app.kubernetes.io/instance': name, 'app.kubernetes.io/component': 'service' });

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
const workload = (c, j) => c.namespaces.find((n) => n.name === j.ns).workloads.find((w) => (w.name || w.serviceAccount) === j.name);
const serviceSas = (ns) => [...new Set(serviceWorkloads(contract).filter((w) => w.ns === ns).map((w) => w.serviceAccount))].sort();

for (const j of JOBS) {
  const ref = `${j.ns}/${j.name}`;

  test(`${ref}: a sidecar-less db-migration workload matching the chart pod labels and identity`, () => {
    const w = workload(contract, j);
    assert.ok(w, `${ref} is in the mesh contract`);
    assert.equal(w.role, 'db-migration');
    assert.equal(w.migrates, j.owner);
    assert.equal(w.serviceAccount, j.sa, 'the ServiceAccount the chart renders the Job pod with');
    if (j.sa === 'default') assert.equal(w.name, j.name, 'a Job on the namespace default ServiceAccount is named after its Job');
    assert.deepEqual(w.selector, { 'app.kubernetes.io/name': j.owner, 'app.kubernetes.io/component': 'db-migration' });
    assert.ok(selects({ matchLabels: w.selector }, j.pod), 'selector matches the rendered Job pod labels');
    assert.ok(!selects({ matchLabels: w.selector }, j.api), 'selector does not match the rendered API pod labels');
    assert.equal(w.sidecar, false);
    assert.equal(w.service, null);
    assert.equal(w.destinationRule, false);
    assert.deepEqual(w.datastores, ['aurora-postgresql']);
  });

  test(`${ref}: the Job pod gets egress to DNS and its service's Aurora only`, () => {
    const egress = selecting(netpols, j.ns, j.pod, 'Egress');
    assert.deepEqual(names(egress), ['allow-egress-aurora', 'allow-egress-dns', 'default-deny-all']);
    const aurora = egress.find((d) => d.metadata.name === 'allow-egress-aurora');
    assert.ok(selects(aurora.spec.podSelector, j.api), 'the API pods use the same Aurora policy');
    assert.deepEqual(aurora.spec.egress, [{ to: [{ ipBlock: { cidr: '192.0.2.0/24' } }], ports: [{ protocol: 'TCP', port: 5432 }] }]);
    const dns = egress.find((d) => d.metadata.name === 'allow-egress-dns');
    assert.deepEqual(dns.spec.egress.flatMap((r) => r.ports.map((p) => `${p.protocol}/${p.port}`)), ['UDP/53', 'TCP/53']);
  });

  test(`${ref}: the Job pod gets no MSK, istiod, VPC, east-west egress and no ingress`, () => {
    const egress = names(selecting(netpols, j.ns, j.pod, 'Egress'));
    for (const n of ['allow-egress-msk', 'allow-egress-istiod', 'allow-egress-vpc-https', 'allow-egress-documentdb', 'allow-egress-redis']) {
      assert.ok(!egress.includes(n), `${n} selects the Job pod`);
    }
    for (const n of egress) assert.ok(!/-to-/.test(n), `${n} gives the Job pod east-west egress`);
    assert.deepEqual(names(selecting(netpols, j.ns, j.pod, 'Ingress')), ['default-deny-all']);
    // The API pods keep everything they had.
    const api = names(selecting(netpols, j.ns, j.api, 'Egress'));
    for (const n of ['allow-egress-aurora', 'allow-egress-msk', 'allow-egress-istiod', 'allow-egress-vpc-https', `allow-egress-${j.owner}-to-identity`, `allow-egress-${j.owner}-to-observability`]) {
      assert.ok(api.includes(n), `${j.owner} API pods lost ${n}`);
    }
    const apiIn = names(selecting(netpols, j.ns, j.api, 'Ingress'));
    for (const n of ['allow-ingress-from-istio-ingress', 'allow-ingress-node-health', 'allow-ingress-observability-scrape']) {
      assert.ok(apiIn.includes(n), `${j.owner} API pods lost ${n}`);
    }
  });

  test(`${ref}: the Job has no in-mesh identity, edge or secret slug`, () => {
    const p = principal(contract, j.ns, j.sa);
    for (const file of ['authorization-policies.yaml', 'request-authentication.yaml', 'destination-rules.yaml', 'ingress-routing.yaml', 'sidecars.yaml']) {
      assert.ok(!generatedText(file).includes(j.name), `${file} names ${j.name}`);
      assert.ok(!generatedText(file).includes(p), `${file} names ${p}`);
    }
    assert.ok(!expandEdges(contract).some((e) => (e.from.ns === j.ns && e.from.name === j.name) || (e.to.ns === j.ns && e.to.name === j.name)));
    assert.ok(!expandEdges(contract).some((e) => (e.from.ns === j.ns && e.from.sa === j.sa) || (e.to.ns === j.ns && e.to.sa === j.sa)));
    assert.ok(!serviceWorkloads(contract).some((w) => w.ns === j.ns && (w.name || w.serviceAccount) === j.name));
    assert.ok(!secretScopes(contract)[j.ns].includes(j.sa), `${j.sa} is no secret slug of ${j.ns}`);
    assert.deepEqual(secretScopes(contract)[j.ns], serviceSas(j.ns));
    assert.ok(secretScopes(contract)[j.ns].includes(j.owner));
  });

  test(`${ref}: R9 exception scoped to the Job, not the service`, () => {
    const refs = contract.exceptions.workloadInjection.map((x) => x.workload);
    assert.ok(refs.includes(ref));
    assert.ok(!refs.includes(`${j.ns}/${j.owner}`), 'the Deployment keeps its sidecar');
    const deployable = loadRepoDocs().filter((d) => ['deploy/', 'k8s/platform/'].some((x) => d.file.startsWith(x)));
    assert.deepEqual(checkZeroTrust(deployable, contract).filter((e) => e.startsWith('R9')), []);
    const c = structuredClone(contract);
    c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== ref);
    assert.ok(checkZeroTrust(deployable, c).some((e) => e.startsWith(`R9 ${ref}`)));
  });
}

// Baseline: the same contract without the Job workloads (and their exceptions).
const withoutJobs = () => {
  const c = structuredClone(contract);
  for (const j of JOBS) {
    const n = c.namespaces.find((x) => x.name === j.ns);
    n.workloads = n.workloads.filter((w) => (w.name || w.serviceAccount) !== j.name);
    c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== `${j.ns}/${j.name}`);
  }
  return c;
};

test('nothing else in the Jobs\' namespaces gains anything; other namespaces are unchanged', () => {
  const now = render(contract);
  const before = render(withoutJobs());
  for (const file of Object.keys(now).filter((f) => f !== 'network-policies.yaml')) {
    assert.deepEqual(now[file], before[file], `${file} changed`);
  }
  const outside = (docs) => docs.filter((d) => !JOB_NS.has(d.metadata.namespace));
  assert.deepEqual(outside(now['network-policies.yaml']), outside(before['network-policies.yaml']));
  for (const ns of JOB_NS) {
    const probes = [
      ...serviceWorkloads(contract).filter((w) => w.ns === ns).flatMap((w) => [
        apiPod(w.serviceAccount),
        { 'app.kubernetes.io/name': w.serviceAccount }, // chart without a component label (the ATM Deployment)
        { 'app.kubernetes.io/name': w.serviceAccount, 'app.kubernetes.io/component': 'history-guard-check' },
      ]),
      ...JOBS.filter((j) => j.ns === ns).map((j) => j.api),
      { 'app.kubernetes.io/name': 'something-else', 'app.kubernetes.io/component': 'service' },
      {}, // any other pod in the namespace
    ];
    for (const labels of probes) {
      for (const type of ['Ingress', 'Egress']) {
        assert.deepEqual(
          rules(selecting(now['network-policies.yaml'], ns, labels, type)),
          rules(selecting(before['network-policies.yaml'], ns, labels, type)),
          `${ns} ${type} of ${JSON.stringify(labels)} changed`,
        );
      }
    }
  }
  for (const j of JOBS) {
    // The Job pod itself only loses: every rule it has now it also had before.
    for (const type of ['Ingress', 'Egress']) {
      const had = rules(selecting(before['network-policies.yaml'], j.ns, j.pod, type)).map((r) => JSON.stringify(r));
      for (const r of rules(selecting(now['network-policies.yaml'], j.ns, j.pod, type))) {
        assert.ok(had.includes(JSON.stringify(r)), `${j.ns}/${j.name} Job pod gained ${type} ${r.name}`);
      }
    }
  }
});

test('a pod with a Job pod\'s labels in another namespace gets nothing an unlabelled pod there does not get', () => {
  for (const j of JOBS) {
    for (const n of contract.namespaces.filter((x) => x.name !== j.ns)) {
      // A subset: in a namespace with a sidecar-less db-migration Job the
      // component exclusion gives such a pod less than an unlabelled pod, never more.
      for (const type of ['Ingress', 'Egress']) {
        const base = names(selecting(netpols, n.name, {}, type));
        for (const name of names(selecting(netpols, n.name, j.pod, type))) {
          assert.ok(base.includes(name), `${j.ns}/${j.name} Job-labelled pod in ${n.name} gains ${type} ${name}`);
        }
      }
      const ports = selecting(netpols, n.name, j.pod, 'Egress').flatMap((d) => (d.spec.egress || []).flatMap((r) => (r.ports || []).map((p) => p.port)));
      assert.ok(!ports.includes(5432), `${j.ns}/${j.name} Job-labelled pod reaches Aurora from ${n.name}`);
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
      () => render(mutate(j, (w, c) => c.edges.push({ from: `${j.ns}/${j.name}`, to: 'identity/keycloak', port: 8080, methods: ['GET'], paths: ['/realms/*'] }))),
      /no call edge/,
    );
  }
  // A meshed Job on its own ServiceAccount (sidecar absent, native sidecar) is still rendered: istiod, never MSK.
  const j = CRC[0];
  const meshed = render(mutate(j, (w) => delete w.sidecar))['network-policies.yaml'];
  const egress = names(selecting(meshed, j.ns, j.pod, 'Egress'));
  assert.ok(egress.includes('allow-egress-istiod') && egress.includes('allow-egress-aurora'), egress.join(', '));
  assert.ok(!egress.includes('allow-egress-msk'));
  assert.doesNotThrow(() => render(contract));
});

// The namespace default ServiceAccount (a pod spec that names none) is shared
// by every pod of the namespace without an account of its own, so it is never
// an identity: only a sidecar-less Job (no principal) with a workload name of
// its own may declare it, nothing may call or be called as <ns>/default, and
// it is no known service account or principal.
test('the namespace default ServiceAccount is never an identity', () => {
  const rtp = DEFAULT_SA.find((j) => j.owner === 'payment-request-to-pay-service');
  const mutate = (fn) => {
    const c = structuredClone(contract);
    fn(workload(c, rtp), c);
    return c;
  };
  // Meshed on the default ServiceAccount: it would present cluster.local/ns/payments/sa/default.
  assert.throws(() => render(mutate((w) => delete w.sidecar)), /payments\/payment-request-to-pay-service-db-migration.*namespace default ServiceAccount/);
  // No name of its own: the workload reference would be payments/default.
  assert.throws(() => render(mutate((w) => delete w.name)), /payments\/default.*namespace default ServiceAccount/);
  // A service workload on the default ServiceAccount.
  const svc = structuredClone(contract);
  svc.namespaces.find((n) => n.name === 'open-finance').workloads.find((w) => w.serviceAccount === 'atm-directory-service').serviceAccount = 'default';
  assert.throws(() => render(svc), /open-finance\/default.*namespace default ServiceAccount/);
  // An edge naming <ns>/default.
  const edge = structuredClone(contract);
  edge.edges.push({ from: 'payments/default', to: 'identity/keycloak', port: 8080, methods: ['GET'], paths: ['/realms/*'] });
  assert.throws(() => render(edge), /payments\/default.*namespace default ServiceAccount/);
  for (const ns of JOB_NS) assert.ok(!knownServiceAccounts(contract).has(`${ns}/default`), `${ns}/default is a known service account`);
  assert.doesNotThrow(() => render(contract));
});

// A workload reference <ns>/<name> (name defaults to the service account)
// keys the policies, exceptions and edges of one workload, and resolveWorkload
// returns the first workload with that reference. The four payments Jobs all
// run as serviceAccount default, so their names alone tell them apart: a name
// used twice resolves both Jobs to the first one's selector, so the policies
// keyed on the second Job's service do not exclude its pods (request to pay's
// Job pod keeps that service's east-west egress), and one R9 exception would
// cover both Jobs. Every reference belongs to one workload of its namespace.
test('a workload reference belongs to one workload of its namespace', () => {
  const rtp = DEFAULT_SA.find((j) => j.owner === 'payment-request-to-pay-service');
  const initiationJob = DEFAULT_SA.find((j) => j.owner === 'payment-initiation-settlement-service').name;
  const deployable = loadRepoDocs().filter((d) => ['deploy/', 'k8s/platform/'].some((x) => d.file.startsWith(x)));
  const renamed = (to, keepException) => {
    const c = structuredClone(contract);
    workload(c, rtp).name = to;
    const x = c.exceptions.workloadInjection.find((e) => e.workload === `${rtp.ns}/${rtp.name}`);
    if (keepException) x.workload = `${rtp.ns}/${to}`;
    else c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((e) => e !== x);
    return c;
  };
  const shared = (ref) => new RegExp(`${ref.replace('/', '\\/')}: 2 workloads of ${ref.split('/')[0]} use this reference`);

  // Request to pay's Job named after the initiation Job: two default-ServiceAccount Jobs, one reference.
  assert.throws(() => render(renamed(initiationJob, true)), shared(`payments/${initiationJob}`));
  assert.throws(() => render(renamed(initiationJob, false)), shared(`payments/${initiationJob}`));
  // R9: the initiation Job's exception does not cover a second workload of that name.
  assert.ok(
    checkZeroTrust(deployable, renamed(initiationJob, false)).some((e) => e.startsWith(`R9 payments/${initiationJob}`)),
    'R9 accepts one exception for two workloads',
  );
  // Named after the request to pay API workload (reference payments/payment-request-to-pay-service):
  // refused for the shared reference, not only because a migration Job is in no call edge.
  assert.throws(() => render(renamed(rtp.owner, true)), shared(`payments/${rtp.owner}`));
  // Any role: the products guard check named after consent's migration Job.
  const guard = structuredClone(contract);
  const consentJob = DEFAULT_SA.find((j) => j.owner === 'consent-authorization-service').name;
  const check = guard.namespaces.find((n) => n.name === 'open-finance').workloads.find((w) => w.role === 'history-guard-check');
  guard.exceptions.workloadInjection = guard.exceptions.workloadInjection.filter((e) => e.workload !== `open-finance/${check.name}`);
  check.name = consentJob;
  assert.throws(() => render(guard), shared(`open-finance/${consentJob}`));
  assert.ok(checkZeroTrust(deployable, guard).some((e) => e.startsWith(`R9 open-finance/${consentJob}`)));

  assert.doesNotThrow(() => render(contract));
  assert.deepEqual(checkZeroTrust(deployable, contract).filter((e) => e.startsWith('R9')), []);
});

// The namespace-wide policies exclude a sidecar-less Job by component only
// (one selector cannot say NOT (name=X AND component=Y)). A meshed Job with the
// same component in the same namespace would lose istiod, VPC endpoints and
// ingress with it, and its proxy could not reach istiod, so the renderer
// refuses that mix. Every chart in the contract runs its db-migration Job
// sidecar-less (request to pay too, since 2cd8e3c), so the refusal is shown
// by giving one Job a native sidecar (and the ServiceAccount of its own a
// meshed Job needs). Distinct components (a sidecar-less guard check next to
// a meshed migration Job) still render, and the meshed Job keeps istiod.
test('renderer refuses a namespace mixing sidecar-less and meshed Jobs of one component', () => {
  const PAYMENTS = DEFAULT_SA.filter((j) => j.ns === 'payments');
  assert.deepEqual(PAYMENTS.map((j) => j.owner).sort(), [
    'payment-bulk-orchestration-service',
    'payment-initiation-settlement-service',
    'payment-recurring-mandates-service',
    'payment-request-to-pay-service',
  ]);
  const egressOf = (c, ns, labels) => names(selecting(render(c)['network-policies.yaml'], ns, labels, 'Egress'));
  // A meshed Job needs a ServiceAccount of its own (never the namespace default).
  const meshedOn = (c, j) => {
    const w = workload(c, j);
    delete w.sidecar;
    w.serviceAccount = j.name;
    delete w.name;
    c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== `${j.ns}/${j.name}`);
  };

  // Payments: request to pay's Job meshed next to the three sidecar-less ones.
  const mixed = structuredClone(contract);
  meshedOn(mixed, PAYMENTS.find((j) => j.owner === 'payment-request-to-pay-service'));
  assert.throws(() => render(mixed), /payments\/payment-request-to-pay-service-db-migration.*component db-migration/);

  // Same in a CRC namespace: a meshed Job next to the sidecar-less one.
  const crc = structuredClone(contract);
  const meshedRisk = { ...structuredClone(workload(contract, CRC[0])), serviceAccount: 'risk-decisioning-service-db-migration-meshed' };
  delete meshedRisk.sidecar;
  crc.namespaces.find((n) => n.name === 'risk').workloads.push(meshedRisk);
  assert.throws(() => render(crc), /risk\/risk-decisioning-service-db-migration-meshed.*component db-migration/);

  // All sidecar-less (the contract): DNS and Aurora only.
  for (const j of PAYMENTS) assert.deepEqual(egressOf(contract, 'payments', j.pod), ['allow-egress-aurora', 'allow-egress-dns', 'default-deny-all']);
  // All meshed: renders; meshed Jobs keep istiod and VPC endpoints.
  const allOn = structuredClone(contract);
  for (const j of PAYMENTS) meshedOn(allOn, j);
  for (const j of PAYMENTS) {
    const eg = egressOf(allOn, 'payments', j.pod);
    assert.ok(eg.includes('allow-egress-istiod') && eg.includes('allow-egress-vpc-https'), `${j.owner}: ${eg.join(', ')}`);
  }

  // A meshed migration Job next to the sidecar-less history-guard check (another component) renders and keeps istiod.
  const ofMixed = structuredClone(contract);
  meshedOn(ofMixed, DEFAULT_SA.find((j) => j.owner === 'consent-authorization-service'));
  const consentPod = DEFAULT_SA.find((j) => j.owner === 'consent-authorization-service').pod;
  const eg = egressOf(ofMixed, 'open-finance', consentPod);
  assert.ok(eg.includes('allow-egress-istiod') && eg.includes('allow-egress-vpc-https'), eg.join(', '));
  const checkPod = { 'app.kubernetes.io/name': 'open-products-catalog-service', 'app.kubernetes.io/component': 'history-guard-check' };
  assert.deepEqual(egressOf(ofMixed, 'open-finance', checkPod), ['allow-egress-aurora', 'allow-egress-dns', 'default-deny-all']);
});

// Every service namespace with an Aurora service now has a sidecar-less
// db-migration Job, and its policies exclude that component, so in each one a
// meshed (native sidecar) db-migration Job is refused when it is modelled and,
// left out of the contract, its pod gets no istiod egress: its proxy never
// gets ready (holdApplicationUntilProxyStarts), so Flyway never starts and the
// hook fails at the Job's deadline. The README tells service
// charts to run the Job without a sidecar and names the per-namespace rule;
// it must not offer the native sidecar as the default.
test('a meshed db-migration Job is refused in every service namespace, and the README says so', () => {
  const withAurora = serviceWorkloads(contract).filter((w) => (w.datastores || []).includes('aurora-postgresql'));
  const namespaces = [...new Set(withAurora.map((w) => w.ns))].sort();
  assert.deepEqual(namespaces, ['compliance', 'customer', 'lending', 'open-finance', 'payments', 'risk']);
  for (const ns of namespaces) {
    const jobs = contract.namespaces.find((n) => n.name === ns).workloads.filter((w) => w.role === 'db-migration');
    assert.ok(jobs.length && jobs.every((w) => w.sidecar === false), `${ns}: every db-migration Job is sidecar-less`);
    for (const svc of withAurora.filter((w) => w.ns === ns)) {
      // A chart's meshed migration Job pod, not in the contract.
      const pod = {
        'app.kubernetes.io/name': svc.serviceAccount,
        'app.kubernetes.io/instance': 'ci',
        'app.kubernetes.io/component': 'db-migration',
        'sidecar.istio.io/inject': 'true',
      };
      assert.ok(!names(selecting(netpols, ns, pod, 'Egress')).includes('allow-egress-istiod'), `${ns}/${svc.serviceAccount}: meshed Job pod reaches istiod`);
      // The same Job modelled as a meshed workload on a ServiceAccount of its own.
      const c = structuredClone(contract);
      c.namespaces.find((n) => n.name === ns).workloads.push({
        serviceAccount: `${svc.serviceAccount}-db-migration-meshed`,
        role: 'db-migration',
        migrates: svc.serviceAccount,
        sourceRepo: svc.sourceRepo,
        selector: { 'app.kubernetes.io/name': svc.serviceAccount, 'app.kubernetes.io/component': 'db-migration' },
        service: null,
        destinationRule: false,
        datastores: ['aurora-postgresql'],
      });
      assert.throws(() => render(c), new RegExp(`${ns}/${svc.serviceAccount}-db-migration-meshed: shares component db-migration`));
    }
  }
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8').replace(/\s+/g, ' ');
  assert.doesNotMatch(readme, /migration Job[^;]*\bwith the sidecar\b[^;]*\bthe default\b/i, 'README offers the native sidecar as the default');
  const bullet = readme.slice(readme.indexOf('Flyway migration Job'));
  assert.match(bullet.slice(0, bullet.indexOf('- reference secrets')), /without a sidecar.*checkSidecarLessJobComponents/);
});
