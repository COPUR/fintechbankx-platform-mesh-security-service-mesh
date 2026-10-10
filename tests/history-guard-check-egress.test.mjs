// open-products-catalog-service history-guard check pods (products PR #14,
// deploy/helm/open-products-catalog-service/templates/history-guard-check.yaml):
// the 15-minute verify CronJob and the pre-upgrade gate Job. Their pods run
// WITHOUT an Istio sidecar (sidecar.istio.io/inject "false"; a sidecar would
// keep the Job from completing), as the Deployment's ServiceAccount, and call
// fbx_history_guard.verify() on the products Aurora database.
//  - they reach DNS and the products Aurora database (5432) and nothing else:
//    no istiod, no VPC endpoints, no MSK, no east-west, no ingress;
//  - they are a documented R9 exception scoped to name + component, and no
//    AuthorizationPolicy, RequestAuthentication or call edge names them;
//  - nothing changes for any other pod, in open-finance or elsewhere.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract, expandEdges, serviceWorkloads, secretScopes } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';
import { checkZeroTrust, loadRepoDocs } from '../scripts/validation/validate-strict-mtls.mjs';

const contract = loadContract();
const NS = 'open-finance';
const OWNER = 'open-products-catalog-service';
const CHECK = 'open-products-catalog-service-history-guard-check';
const generatedText = (file) => readFileSync(join(repoRoot, 'deploy/kustomize/base/generated', file), 'utf8');
const generated = (file) => YAML.parseAllDocuments(generatedText(file)).map((d) => d.toJSON()).filter(Boolean);
const netpols = generated('network-policies.yaml');

// Pod template labels of both check workloads (products _helpers.tpl
// products.historyGuardCheckPod), plus the labels the Job controller adds.
const checkPod = {
  'app.kubernetes.io/name': OWNER,
  'app.kubernetes.io/instance': OWNER,
  'app.kubernetes.io/component': 'history-guard-check',
  'app.kubernetes.io/version': '0.1.0',
  'app.kubernetes.io/part-of': 'fintechbankx-open-finance',
  'app.kubernetes.io/managed-by': 'Helm',
  'fintechbankx.io/service-id': 'svc-of-open-products-catalog',
  'helm.sh/chart': 'open-products-catalog-service-0.1.0',
  'sidecar.istio.io/inject': 'false',
  'batch.kubernetes.io/job-name': `${OWNER}-history-guard-check-29123456`,
  'job-name': `${OWNER}-history-guard-check-29123456`,
};
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

test('the contract declares the check pods as a sidecar-less workload matching the products chart labels', () => {
  const w = contract.namespaces.find((n) => n.name === NS).workloads.find((x) => x.name === CHECK);
  assert.ok(w, `${NS}/${CHECK} is in the mesh contract`);
  assert.equal(w.role, 'history-guard-check');
  assert.equal(w.checks, OWNER);
  assert.equal(w.serviceAccount, OWNER, 'the chart runs the check pods as the Deployment ServiceAccount');
  assert.deepEqual(w.selector, { 'app.kubernetes.io/name': OWNER, 'app.kubernetes.io/component': 'history-guard-check' });
  assert.ok(selects({ matchLabels: w.selector }, checkPod), 'selector matches the chart pod labels');
  assert.ok(!selects({ matchLabels: w.selector }, apiPod(OWNER)), 'selector does not match the products API pods');
  assert.equal(w.sidecar, false);
  assert.equal(w.service, null);
  assert.equal(w.destinationRule, false);
  assert.deepEqual(w.datastores, ['aurora-postgresql']);
});

test('check pods get egress to DNS and the products Aurora database only', () => {
  const egress = selecting(netpols, NS, checkPod, 'Egress');
  assert.deepEqual(names(egress), ['allow-egress-aurora', 'allow-egress-dns', 'default-deny-all']);
  const aurora = egress.find((d) => d.metadata.name === 'allow-egress-aurora');
  // The same policy (same AURORA_CIDR, same port) the products API pods use.
  assert.ok(selects(aurora.spec.podSelector, apiPod(OWNER)), 'products API pods use the same Aurora policy');
  assert.deepEqual(aurora.spec.egress, [{ to: [{ ipBlock: { cidr: '192.0.2.0/24' } }], ports: [{ protocol: 'TCP', port: 5432 }] }]);
  const dns = egress.find((d) => d.metadata.name === 'allow-egress-dns');
  assert.deepEqual(dns.spec.egress.flatMap((r) => r.ports.map((p) => p.port)), [53, 53]);
});

test('check pods get no MSK, istiod, VPC-endpoint, east-west or other datastore egress', () => {
  const egress = names(selecting(netpols, NS, checkPod, 'Egress'));
  for (const n of ['allow-egress-msk', 'allow-egress-istiod', 'allow-egress-vpc-https', 'allow-egress-documentdb', 'allow-egress-redis']) {
    assert.ok(!egress.includes(n), `${n} selects the check pods`);
  }
  for (const n of egress) assert.ok(!/-to-/.test(n), `${n} gives the check pods east-west egress`);
  // The products API pods keep everything they had.
  const api = names(selecting(netpols, NS, apiPod(OWNER), 'Egress'));
  for (const n of ['allow-egress-aurora', 'allow-egress-istiod', 'allow-egress-vpc-https', `allow-egress-${OWNER}-to-identity`, `allow-egress-${OWNER}-to-observability`]) {
    assert.ok(api.includes(n), `products API pods lost ${n}`);
  }
});

test('check pods accept no ingress', () => {
  assert.deepEqual(names(selecting(netpols, NS, checkPod, 'Ingress')), ['default-deny-all']);
  const api = names(selecting(netpols, NS, apiPod(OWNER), 'Ingress'));
  for (const n of ['allow-ingress-from-istio-ingress', 'allow-ingress-node-health', 'allow-ingress-observability-scrape']) {
    assert.ok(api.includes(n), `products API pods lost ${n}`);
  }
});

test('check pods have no in-mesh identity: no AuthorizationPolicy, RequestAuthentication, edge or secret slug', () => {
  for (const file of ['authorization-policies.yaml', 'request-authentication.yaml', 'destination-rules.yaml', 'ingress-routing.yaml', 'sidecars.yaml']) {
    assert.ok(!generatedText(file).includes(CHECK), `${file} names ${CHECK}`);
    assert.ok(!generatedText(file).includes('history-guard-check'), `${file} names the check component`);
  }
  assert.ok(!expandEdges(contract).some((e) => e.from.name === CHECK || e.to.name === CHECK), 'no edge (incl. wildcards) expands to the check pods');
  assert.ok(!serviceWorkloads(contract).some((w) => w.name === CHECK));
  assert.deepEqual(secretScopes(contract)[NS], [...new Set(serviceWorkloads(contract).filter((w) => w.ns === NS).map((w) => w.serviceAccount))].sort());
});

test('R9: the sidecar-less check pods are a documented exception scoped to that workload only', () => {
  const refs = contract.exceptions.workloadInjection.map((x) => x.workload);
  assert.ok(refs.includes(`${NS}/${CHECK}`));
  assert.ok(!refs.includes(`${NS}/${OWNER}`), 'the products Deployment keeps its sidecar');
  const deployable = loadRepoDocs()
    .filter((d) => ['deploy/', 'k8s/platform/'].some((p) => d.file.startsWith(p)));
  assert.deepEqual(checkZeroTrust(deployable, contract).filter((e) => e.startsWith('R9')), []);
  const c = structuredClone(contract);
  c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== `${NS}/${CHECK}`);
  assert.ok(checkZeroTrust(deployable, c).some((e) => e.startsWith(`R9 ${NS}/${CHECK}`)));
});

const withoutCheck = () => {
  const c = structuredClone(contract);
  const n = c.namespaces.find((x) => x.name === NS);
  n.workloads = n.workloads.filter((w) => w.name !== CHECK);
  c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== `${NS}/${CHECK}`);
  return c;
};
const rules = (docs) => docs.map((d) => ({ name: d.metadata.name, ingress: d.spec.ingress, egress: d.spec.egress })).sort((a, b) => a.name.localeCompare(b.name));

test('no other pod gains or loses anything', () => {
  const now = render(contract);
  const before = render(withoutCheck());
  for (const file of Object.keys(now).filter((f) => f !== 'network-policies.yaml')) {
    assert.deepEqual(now[file], before[file], `${file} changed`);
  }
  const outside = (docs) => docs.filter((d) => d.metadata.namespace !== NS);
  assert.deepEqual(outside(now['network-policies.yaml']), outside(before['network-policies.yaml']), 'NetworkPolicies outside open-finance changed');
  const probes = [
    ...serviceWorkloads(contract).filter((w) => w.ns === NS).flatMap((w) => [
      apiPod(w.serviceAccount),
      { 'app.kubernetes.io/name': w.serviceAccount }, // chart without a component label
      { 'app.kubernetes.io/name': w.serviceAccount, 'app.kubernetes.io/component': 'db-migration' },
    ]),
    {}, // any other pod in the namespace
  ];
  for (const labels of probes) {
    for (const type of ['Ingress', 'Egress']) {
      assert.deepEqual(
        rules(selecting(now['network-policies.yaml'], NS, labels, type)),
        rules(selecting(before['network-policies.yaml'], NS, labels, type)),
        `${type} of ${JSON.stringify(labels)} changed`,
      );
    }
  }
});

test('a pod with the check labels in another namespace gets nothing an unlabelled pod there does not get', () => {
  for (const n of contract.namespaces.filter((x) => x.name !== NS)) {
    for (const type of ['Ingress', 'Egress']) {
      assert.deepEqual(names(selecting(netpols, n.name, checkPod, type)), names(selecting(netpols, n.name, {}, type)), `${n.name} ${type}`);
    }
    const ports = selecting(netpols, n.name, checkPod, 'Egress').flatMap((d) => (d.spec.egress || []).flatMap((r) => (r.ports || []).map((p) => p.port)));
    assert.ok(!ports.includes(5432), `${n.name}: check-labelled pod reaches Aurora`);
  }
});

test('renderer refuses a looser or meshed check workload', () => {
  const mutate = (fn) => {
    const c = structuredClone(contract);
    const n = c.namespaces.find((x) => x.name === NS);
    fn(n.workloads.find((w) => w.name === CHECK), c);
    return c;
  };
  assert.throws(() => render(mutate((w) => w.datastores.push('msk'))), /Aurora only/);
  assert.throws(() => render(mutate((w) => (w.selector = { 'app.kubernetes.io/name': OWNER }))), /selector must be exactly/);
  assert.throws(() => render(mutate((w) => (w.checks = 'atm-directory-service'))), /selector must be exactly/);
  assert.throws(() => render(mutate((w) => (w.checks = 'no-such-service'))), /checks must name/);
  assert.throws(() => render(mutate((w) => (w.sidecar = true))), /without a sidecar/);
  assert.throws(() => render(mutate((w) => (w.apiPrefix = '/open-finance/v1/guard'))), /no inbound/);
  assert.throws(
    () => render(mutate((w, c) => c.edges.push({ from: `${NS}/${CHECK}`, to: 'identity/keycloak', port: 8080, methods: ['GET'], paths: ['/realms/*'] }))),
    /no call edge/,
  );
  assert.doesNotThrow(() => render(contract));
});
