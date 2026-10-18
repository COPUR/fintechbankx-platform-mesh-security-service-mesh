// Screening facts computed by their owners (CRC plan 2026-10-18, owner's
// answers to the 10-08 cards): payments sends only ids and amounts, and the
// owners read what they need from the customer service.
//  - risk-decisioning-service reads GET /api/v1/customers/{id}/credit (score
//    and profile for loan eligibility);
//  - compliance-evidence-service reads GET /api/v1/customers/{id} (name and
//    KYC status for sanctions and PEP screening);
//  - loan-lifecycle-service calls risk POST /api/v1/risk/loan-eligibility,
//    which is service-only like POST /api/v1/risk/assess;
//  - payment-initiation-settlement-service calls risk POST /api/v1/risk/assess
//    and compliance POST /api/v1/compliance/screen (its adapters today) and
//    their v2 replacements, and nothing else on either service. v1 stays until
//    payments is on v2 (the cutover precondition "v1 flag off, callers on v2").
// No v2 path is routed at the gateway (the gateway routes /api/v1/risk and
// /api/v1/compliance only).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract, principal } from '../scripts/lib/contract.mjs';

const contract = loadContract();
const generated = (file) =>
  YAML.parseAllDocuments(readFileSync(join(repoRoot, 'deploy/kustomize/base/generated', file), 'utf8'))
    .map((d) => d.toJSON())
    .filter(Boolean);
const policies = generated('authorization-policies.yaml');
const netpols = generated('network-policies.yaml');
const sidecars = generated('sidecars.yaml');
const routing = generated('ingress-routing.yaml');

const P = (ns, sa) => principal(contract, ns, sa);
const GATEWAY = P('istio-ingress', 'istio-ingressgateway');
const LOAN = P('lending', 'loan-lifecycle-service');
const PAYMENTS = P('payments', 'payment-initiation-settlement-service');
const RISK = P('risk', 'risk-decisioning-service');
const COMPLIANCE = P('compliance', 'compliance-evidence-service');
const FIRST_PARTY = ['fintechbankx-web', 'fintechbankx-mobile', 'fintechbankx-staff-web'];

// Istio path forms used here: exact, "*" suffix (prefix), templates with {*} (one segment) / {**}.
function pathMatches(pattern, path) {
  if (pattern.includes('{')) {
    const re = pattern
      .split('/')
      .map((s) => (s === '{*}' ? '[^/]+' : s === '{**}' ? '.*' : s.replace(/[.+?^$()[\]\\|]/g, '\\$&')))
      .join('/');
    return new RegExp(`^${re}$`).test(path);
  }
  if (pattern.endsWith('*')) return path.startsWith(pattern.slice(0, -1));
  return pattern === path;
}
const opAllows = (op, port, method, path) =>
  (!op.ports || op.ports.includes(String(port))) &&
  (!op.methods || op.methods.includes(method)) &&
  (!op.paths || op.paths.some((p) => pathMatches(p, path))) &&
  !(op.notPaths || []).some((p) => pathMatches(p, path));
const whenHolds = (when, claims) =>
  (when || []).every((c) => {
    const m = /^request\.auth\.claims\[(.+)\]$/.exec(c.key);
    if (!m) throw new Error(`condition ${c.key} not modelled`);
    return c.values.includes(claims[m[1]]);
  });
/** Does an ALLOW policy in the callee namespace admit this request on its 8080 API port? */
function admits(ns, source, method, path, claims = {}) {
  return policies
    .filter((d) => d.metadata.namespace === ns && d.spec.action === 'ALLOW')
    .some((ap) =>
      ap.spec.rules.some((r) => {
        const fromOk = !r.from || r.from.some((f) => (f.source?.principals || []).includes(source));
        const toOk = !r.to || r.to.some((t) => opAllows(t.operation || {}, 8080, method, path));
        return fromOk && toOk && whenHolds(r.when, claims);
      }),
    );
}
const admitted = (ns, source, operations, claims) => operations.filter(([m, p]) => admits(ns, source, m, p, claims)).map(([m, p]) => `${m} ${p}`);

const CUSTOMER = '/api/v1/customers/CUST-7d1f';
const CUSTOMER_OPERATIONS = [
  ['GET', CUSTOMER],
  ['GET', `${CUSTOMER}/credit`],
  ['GET', `${CUSTOMER}/kyc-status`],
  ['POST', `${CUSTOMER}/credit/reserve`],
  ['POST', `${CUSTOMER}/credit/release`],
  ['PUT', CUSTOMER],
  ['POST', '/api/v1/customers'],
  ['GET', '/api/v1/customers'],
  ['GET', `${CUSTOMER}/`],
  ['GET', `${CUSTOMER}/credit/`],
];
const RISK_OPERATIONS = [
  ['POST', '/api/v1/risk/assess'],
  ['POST', '/api/v2/risk/assess'],
  ['POST', '/api/v1/risk/loan-eligibility'],
  ['GET', '/api/v1/risk/assessments/TX-1'],
  ['POST', '/api/v1/risk/loan-eligibility/'],
  ['POST', '/api/v2/risk/assess/'],
  ['GET', '/api/v2/risk/assess'],
  ['POST', '/api/v2/risk/loan-eligibility'],
];
const COMPLIANCE_OPERATIONS = [
  ['POST', '/api/v1/compliance/screen'],
  ['POST', '/api/v2/compliance/screen'],
  ['GET', '/api/v1/compliance/screenings/TX-1'],
  ['POST', '/api/v2/compliance/screen/'],
  ['GET', '/api/v2/compliance/screen'],
];

test('risk reads a customer credit profile and compliance reads a customer, nothing else', () => {
  assert.deepEqual(admitted('customer', RISK, CUSTOMER_OPERATIONS), [`GET ${CUSTOMER}/credit`]);
  assert.deepEqual(admitted('customer', COMPLIANCE, CUSTOMER_OPERATIONS), [`GET ${CUSTOMER}`]);
});

test('loan calls risk loan eligibility only; payments calls assess and screen (v1 and v2) only', () => {
  assert.deepEqual(admitted('risk', LOAN, RISK_OPERATIONS), ['POST /api/v1/risk/loan-eligibility']);
  assert.deepEqual(admitted('risk', PAYMENTS, RISK_OPERATIONS), ['POST /api/v1/risk/assess', 'POST /api/v2/risk/assess']);
  assert.deepEqual(admitted('compliance', PAYMENTS, COMPLIANCE_OPERATIONS), ['POST /api/v1/compliance/screen', 'POST /api/v2/compliance/screen']);
  assert.deepEqual(admitted('compliance', LOAN, COMPLIANCE_OPERATIONS), []);
  assert.deepEqual(admitted('risk', COMPLIANCE, RISK_OPERATIONS), []);
  assert.deepEqual(admitted('compliance', RISK, COMPLIANCE_OPERATIONS), []);
  // The payments rules are method- and path-scoped now that its adapters are known.
  for (const e of contract.edges.filter((x) => x.from === 'payments/payment-initiation-settlement-service' && /^(risk|compliance)\//.test(x.to))) {
    assert.equal(e.scope, undefined, `${e.to} is no longer port-only`);
    assert.deepEqual(e.methods, ['POST']);
  }
  assert.ok(!contract.gaps.some((g) => /\brisk\b|\bcompliance\b/.test(g.to)), 'risk and compliance are no gap of payments any more');
  // Initiation-settlement has no consent edge at all, so its remaining gap is payee verification only.
  assert.ok(!contract.edges.some((x) => x.from === 'payments/payment-initiation-settlement-service' && x.to.startsWith('open-finance/consent-')));
  const gap = contract.gaps.filter((g) => g.from === 'payments/payment-initiation-settlement-service').map((g) => g.to);
  assert.deepEqual(gap, ['open-finance payee verification (paths)']);
});

test('gateway: loan eligibility, assess and screen stay off the edge; no v2 route', () => {
  for (const azp of FIRST_PARTY) {
    for (const [m, p] of [...RISK_OPERATIONS.filter(([, x]) => !x.startsWith('/api/v1/risk/assessments'))]) {
      assert.ok(!admits('risk', GATEWAY, m, p, { azp }), `${azp} ${m} ${p}`);
    }
    for (const [m, p] of COMPLIANCE_OPERATIONS.filter(([, x]) => !x.startsWith('/api/v1/compliance/screenings'))) {
      assert.ok(!admits('compliance', GATEWAY, m, p, { azp }), `${azp} ${m} ${p}`);
    }
  }
  const api = routing.find((d) => d.kind === 'VirtualService' && d.metadata.name === 'fintechbankx-api');
  const prefixes = api.spec.http.flatMap((r) => (r.match || []).map((x) => x.uri?.prefix).filter(Boolean));
  assert.ok(!prefixes.some((p) => p.startsWith('/api/v2')), 'no /api/v2 route at the gateway');
});

const np = (ns, name) => netpols.find((d) => d.metadata.namespace === ns && d.metadata.name === name);
const notJob = [{ key: 'app.kubernetes.io/component', operator: 'NotIn', values: ['db-migration'] }];

test('NetworkPolicies: each caller reaches its callee on 8080, and the callee admits it', () => {
  for (const [ns, caller, toNs, callee] of [
    ['risk', 'risk-decisioning-service', 'customer', 'customer-profile-kyc-service'],
    ['compliance', 'compliance-evidence-service', 'customer', 'customer-profile-kyc-service'],
    ['lending', 'loan-lifecycle-service', 'risk', 'risk-decisioning-service'],
  ]) {
    const egress = np(ns, `allow-egress-${caller}-to-${toNs}`);
    assert.ok(egress, `${ns}/${caller} egress to ${toNs}`);
    assert.deepEqual(egress.spec.podSelector, { matchLabels: { 'app.kubernetes.io/name': caller }, matchExpressions: notJob });
    assert.deepEqual(egress.spec.egress, [
      { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': toNs } }, podSelector: { matchLabels: { 'app.kubernetes.io/name': callee } } }], ports: [{ protocol: 'TCP', port: 8080 }] },
    ]);
    const ingress = np(toNs, `allow-ingress-from-${ns}`);
    assert.ok(ingress, `${toNs} admits ${ns}`);
    const peers = ingress.spec.ingress.flatMap((r) => r.from.map((f) => [f.namespaceSelector.matchLabels['kubernetes.io/metadata.name'], f.podSelector.matchLabels['app.kubernetes.io/name']]));
    assert.ok(peers.some(([n, a]) => n === ns && a === caller), `${toNs} admits ${ns}/${caller}`);
    assert.deepEqual(ingress.spec.ingress.flatMap((r) => r.ports.map((p) => p.port)), [8080]);
    const sc = sidecars.find((d) => d.metadata.namespace === ns && d.metadata.name === 'default');
    assert.ok(sc.spec.egress[0].hosts.includes(`${toNs}/*`), `${ns} Sidecar lists ${toNs}/*`);
  }
  // Compliance and risk do not reach each other, and customer reaches neither.
  assert.equal(np('risk', 'allow-egress-risk-decisioning-service-to-compliance'), undefined);
  assert.equal(np('compliance', 'allow-egress-compliance-evidence-service-to-risk'), undefined);
  assert.equal(np('customer', 'allow-egress-customer-profile-kyc-service-to-risk'), undefined);
  assert.equal(np('customer', 'allow-egress-customer-profile-kyc-service-to-compliance'), undefined);
});
