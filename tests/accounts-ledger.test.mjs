// Core banking accounts ledger (neo-fintechbankx-corebanking-accounts-ledger-service
// PR #1, head 2db7a04, chart deploy/helm/accounts-ledger-service): namespace
// corebanking, workload accounts-ledger-service (svc-acc-accounts-ledger) and
// its callers. Its Flyway hook Job is covered with the other migration Jobs in
// tests/sidecarless-migration-job-egress.test.mjs.
//  - corebanking is a service namespace: injected, STRICT mTLS, default-deny
//    AuthorizationPolicy and NetworkPolicy, a JWT required on /api/**;
//  - the workload RequestAuthentication requires the realm issuer and aud
//    svc-acc-accounts-ledger, tokens from the Authorization header only;
//  - 8080 admits the ingress gateway and the four SERVICE_CALLERS only
//    (initiation/settlement, recurring mandates, bulk orchestration, loan
//    lifecycle), each on the (method, path) pairs it uses; request to pay
//    and every other principal get nothing;
//  - the gateway routes /api/v1/accounts and /api/v1/journal-entries like the
//    customer API (first-party azp): GET an account for the web, mobile and
//    staff clients, the staff operations for the staff client only, and never
//    POST /api/v1/journal-entries (service-only money movement);
//  - the API pods reach DNS, istiod, VPC endpoints, Aurora, MSK, Keycloak and
//    the OTel collector; the callers reach the ledger on 8080 and nothing else
//    in corebanking;
//  - ExternalSecrets in corebanking read <env>/accounts-ledger-service/ keys
//    only (the slug is the app.kubernetes.io/name label, not the context code).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract, principal, secretScopes, serviceWorkloads } from '../scripts/lib/contract.mjs';
import { checkZeroTrust, loadRepoDocs } from '../scripts/validation/validate-strict-mtls.mjs';

const contract = loadContract();
const NS = 'corebanking';
const SA = 'accounts-ledger-service';
const SERVICE_ID = 'svc-acc-accounts-ledger';
const generated = (file) =>
  YAML.parseAllDocuments(readFileSync(join(repoRoot, 'deploy/kustomize/base/generated', file), 'utf8'))
    .map((d) => d.toJSON())
    .filter(Boolean);
const docs = Object.fromEntries(
  [
    'namespaces.yaml', 'peer-authentication.yaml', 'request-authentication.yaml', 'authorization-policies.yaml',
    'destination-rules.yaml', 'sidecars.yaml', 'ingress-routing.yaml', 'network-policies.yaml', 'externalsecret-admission.yaml',
  ].map((f) => [f, generated(f)]),
);
const one = (file, kind, ns, name) => docs[file].find((d) => d.kind === kind && d.metadata.namespace === ns && d.metadata.name === name);

const P = (ns, sa) => principal(contract, ns, sa);
const GATEWAY = P('istio-ingress', 'istio-ingressgateway');
const INITIATION = P('payments', 'payment-initiation-settlement-service');
const MANDATES = P('payments', 'payment-recurring-mandates-service');
const BULK = P('payments', 'payment-bulk-orchestration-service');
const LOAN = P('lending', 'loan-lifecycle-service');
const RTP = P('payments', 'payment-request-to-pay-service');
const PROMETHEUS = P('observability', 'prometheus');
const FIRST_PARTY = ['fintechbankx-web', 'fintechbankx-mobile', 'fintechbankx-staff-web'];

// Ledger pod labels as the chart renders them (release "ci", image tag "ci"):
// selectorLabels + podLabels + app/version/squad (deployment.yaml:22-28,
// _helpers.tpl:13-21, values.yaml podLabels).
const API_POD = {
  'app.kubernetes.io/name': SA,
  'app.kubernetes.io/instance': 'ci',
  'app.kubernetes.io/component': 'service',
  'app.kubernetes.io/part-of': 'fintechbankx-corebanking',
  'fintechbankx.io/service-id': SERVICE_ID,
  'fintechbankx.io/app': 'app-acc-ledger',
  'sidecar.istio.io/inject': 'true',
  app: SA,
  version: 'ci',
  'fintechbankx.io/squad': 'corebanking',
};

/** Kubernetes label selector semantics (matchLabels AND matchExpressions). */
function selects(selector, labels) {
  for (const [k, v] of Object.entries(selector?.matchLabels || {})) if (labels[k] !== v) return false;
  for (const e of selector?.matchExpressions || []) {
    const has = Object.hasOwn(labels, e.key);
    const ok = { In: () => has && e.values.includes(labels[e.key]), NotIn: () => !has || !e.values.includes(labels[e.key]) }[e.operator];
    if (!ok) throw new Error(`unknown operator ${e.operator}`);
    if (!ok()) return false;
  }
  return true;
}

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

/** ALLOW AuthorizationPolicies of corebanking that apply to the ledger API pods. */
const ledgerAllows = () =>
  docs['authorization-policies.yaml'].filter(
    (d) => d.metadata.namespace === NS && d.spec.action === 'ALLOW' && (!d.spec.selector || selects(d.spec.selector, API_POD)),
  );
/** Does any ALLOW rule admit this request on the ledger sidecar? */
function admits(source, port, method, path, claims = {}) {
  return ledgerAllows().some((ap) =>
    ap.spec.rules.some((r) => {
      const fromOk = !r.from || r.from.some((f) => (f.source?.principals || []).includes(source));
      const toOk = !r.to || r.to.some((t) => opAllows(t.operation || {}, port, method, path));
      return fromOk && toOk && whenHolds(r.when, claims);
    }),
  );
}

const ACCOUNT = '/api/v1/accounts/ACC-0f8fad5b-d9cb-469f-a165-70867728950e';
const ENTRY = '/api/v1/journal-entries/JE-1';
// Every ledger operation (OpenAPI api/openapi/accounts-ledger.yaml, controllers AccountController / JournalEntryController).
const OPERATIONS = [
  ['GET', ACCOUNT],
  ['POST', '/api/v1/accounts'],
  ['POST', `${ACCOUNT}/freeze`],
  ['POST', `${ACCOUNT}/unfreeze`],
  ['POST', `${ACCOUNT}/close`],
  ['POST', '/api/v1/journal-entries'],
  ['GET', ENTRY],
];
const admitted = (source, claims) => OPERATIONS.filter(([m, p]) => admits(source, 8080, m, p, claims)).map(([m, p]) => `${m} ${p}`);

test('corebanking is an injected service namespace with STRICT mTLS and default-deny', () => {
  const ns = docs['namespaces.yaml'].find((d) => d.kind === 'Namespace' && d.metadata.name === NS);
  assert.ok(ns, 'Namespace corebanking is rendered');
  assert.deepEqual(ns.metadata.labels, {
    'fintechbankx.io/context': 'corebanking',
    'istio-injection': 'enabled',
    'fintechbankx.io/namespace-kind': 'service',
  });
  assert.deepEqual(one('peer-authentication.yaml', 'PeerAuthentication', NS, 'default').spec, { mtls: { mode: 'STRICT' } });
  assert.deepEqual(one('authorization-policies.yaml', 'AuthorizationPolicy', NS, 'default-deny').spec, {});
  assert.deepEqual(one('network-policies.yaml', 'NetworkPolicy', NS, 'default-deny-all').spec, { podSelector: {}, policyTypes: ['Ingress', 'Egress'] });
  const jwt = one('authorization-policies.yaml', 'AuthorizationPolicy', NS, 'require-jwt-for-api');
  assert.equal(jwt.spec.action, 'DENY');
  assert.deepEqual(jwt.spec.rules, [{ from: [{ source: { notRequestPrincipals: ['*'] } }], to: [{ operation: { paths: ['/api', '/api/*'] } }] }]);
  const sidecar = one('sidecars.yaml', 'Sidecar', NS, 'default');
  assert.deepEqual(sidecar.spec, { egress: [{ hosts: ['./*', 'identity/*', 'istio-system/*', 'observability/*'] }], outboundTrafficPolicy: { mode: 'REGISTRY_ONLY' } });
  const w = serviceWorkloads(contract).filter((x) => x.ns === NS);
  assert.deepEqual(w.map((x) => [x.serviceAccount, x.serviceId]), [[SA, SERVICE_ID]]);
  assert.deepEqual(w[0].datastores, ['aurora-postgresql', 'msk']);
});

test('the ledger RequestAuthentication requires aud svc-acc-accounts-ledger from the realm issuer, headers only', () => {
  const ras = docs['request-authentication.yaml'].filter((d) => d.metadata.namespace === NS);
  assert.deepEqual(ras.map((d) => d.metadata.name), [`keycloak-jwt-${SA}`], 'one RequestAuthentication in corebanking, none for the hook Job');
  const [ra] = ras;
  assert.deepEqual(ra.spec.selector, { matchLabels: { 'app.kubernetes.io/name': SA } });
  assert.equal(ra.spec.jwtRules.length, 1);
  const [rule] = ra.spec.jwtRules;
  assert.equal(rule.issuer, contract.identity.issuer);
  assert.equal(rule.jwksUri, contract.identity.jwksUri);
  assert.deepEqual(rule.audiences, [SERVICE_ID]);
  assert.deepEqual(rule.fromHeaders, contract.gateway.tokenLocations.fromHeaders);
  assert.equal(rule.fromParams, undefined);
  assert.equal(rule.forwardOriginalToken, true);
});

test('8080 admits only the ingress gateway and the four SERVICE_CALLERS', () => {
  const sources = new Set(
    ledgerAllows()
      .flatMap((ap) => ap.spec.rules)
      .filter((r) => r.to?.some((t) => !t.operation?.ports || t.operation.ports.includes('8080')))
      .flatMap((r) => (r.from || [{ source: { principals: ['<any>'] } }]).flatMap((f) => f.source.principals || ['<any>'])),
  );
  assert.deepEqual([...sources].sort(), [GATEWAY, LOAN, BULK, INITIATION, MANDATES].sort());
  // The management port: Prometheus and the namespace health rule only.
  for (const s of [GATEWAY, LOAN, BULK, INITIATION, MANDATES]) {
    assert.ok(!admits(s, 8081, 'GET', '/actuator/prometheus'), `${s} scrapes 8081`);
    assert.ok(!admits(s, 8081, 'GET', '/actuator/env'), `${s} reaches 8081`);
  }
  assert.ok(admits(PROMETHEUS, 8081, 'GET', '/actuator/prometheus'));
  assert.ok(!admits(PROMETHEUS, 8080, 'GET', ACCOUNT), 'Prometheus reaches the API');
  assert.ok(!admits(RTP, 8080, 'GET', ACCOUNT), 'request to pay is no SERVICE_CALLER');
});

test('each caller gets the ledger operations it uses, never the staff operations', () => {
  // Account reads: initiation/settlement (CoreBankingAccountHttpAdapter) and
  // recurring mandates (AccountsServiceHttpAdapter). Journal posting: the four
  // SERVICE_CALLERS (ledger values config.SERVICE_CALLERS).
  assert.deepEqual(admitted(INITIATION), [`GET ${ACCOUNT}`, 'POST /api/v1/journal-entries']);
  assert.deepEqual(admitted(MANDATES), [`GET ${ACCOUNT}`, 'POST /api/v1/journal-entries']);
  assert.deepEqual(admitted(BULK), ['POST /api/v1/journal-entries']);
  assert.deepEqual(admitted(LOAN), ['POST /api/v1/journal-entries']);
  assert.deepEqual(admitted(RTP), []);
  for (const s of [INITIATION, MANDATES, BULK, LOAN]) {
    for (const [m, p] of [['GET', '/api/v1/accounts'], ['POST', '/api/v1/journal-entries/'], ['PUT', '/api/v1/journal-entries'], ['DELETE', ACCOUNT], ['GET', '/internal/v1/x']]) {
      assert.ok(!admits(s, 8080, m, p), `${s} ${m} ${p}`);
    }
  }
  // East-west rules carry no azp condition (the ledger checks azp against SERVICE_CALLERS itself).
  for (const ap of ledgerAllows().filter((d) => d.metadata.name !== `allow-from-istio-ingress-istio-ingressgateway-to-${SA}`)) {
    for (const r of ap.spec.rules) assert.equal(r.when, undefined, ap.metadata.name);
  }
});

test('gateway: customers read their account, staff run the staff operations, nobody posts journal entries', () => {
  const api = docs['ingress-routing.yaml'].find((d) => d.kind === 'VirtualService' && d.metadata.name === 'fintechbankx-api');
  const route = api.spec.http.find((r) => r.name === SERVICE_ID);
  assert.ok(route, 'route svc-acc-accounts-ledger');
  assert.deepEqual(route.match, [{ uri: { prefix: '/api/v1/accounts' } }, { uri: { prefix: '/api/v1/journal-entries' } }]);
  assert.deepEqual(route.route, [{ destination: { host: `${SA}.${NS}.svc.cluster.local`, port: { number: 8080 } } }]);
  assert.deepEqual(route.headers.request.set, { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'API_HOST', 'x-forwarded-port': '443' });

  const as = (azp) => admitted(GATEWAY, { azp });
  for (const azp of ['fintechbankx-web', 'fintechbankx-mobile']) assert.deepEqual(as(azp), [`GET ${ACCOUNT}`], azp);
  assert.deepEqual(as('fintechbankx-staff-web'), [
    `GET ${ACCOUNT}`,
    'POST /api/v1/accounts',
    `POST ${ACCOUNT}/freeze`,
    `POST ${ACCOUNT}/unfreeze`,
    `POST ${ACCOUNT}/close`,
    `GET ${ENTRY}`,
  ]);
  // Service and TPP tokens through the edge, or none: nothing.
  for (const azp of ['svc-pay-initiation-settlement', 'svc-ln-loan-lifecycle', 'some-tpp', undefined]) assert.deepEqual(as(azp), [], String(azp));
  // Journal posting moves money: service-only, never from the edge.
  for (const azp of FIRST_PARTY) assert.ok(!admits(GATEWAY, 8080, 'POST', '/api/v1/journal-entries', { azp }), azp);
  for (const [m, p] of [['GET', '/api/v1/accounts'], ['PUT', ACCOUNT], ['DELETE', ACCOUNT], ['GET', `${ACCOUNT}/freeze`], ['POST', `${ACCOUNT}/freeze/x`]]) {
    for (const azp of FIRST_PARTY) assert.ok(!admits(GATEWAY, 8080, m, p, { azp }), `${azp} ${m} ${p}`);
  }
  const gw = one('authorization-policies.yaml', 'AuthorizationPolicy', NS, `allow-from-istio-ingress-istio-ingressgateway-to-${SA}`);
  for (const r of gw.spec.rules) {
    assert.equal(r.when?.length, 1, 'every gateway rule names its first-party clients');
    assert.equal(r.when[0].key, 'request.auth.claims[azp]');
    for (const v of r.when[0].values) assert.ok(FIRST_PARTY.includes(v), v);
    for (const t of r.to) assert.ok(t.operation.methods?.length && t.operation.paths?.length, 'method- and path-scoped');
  }
});

const netpols = docs['network-policies.yaml'];
const selecting = (ns, labels, type) =>
  netpols.filter((d) => d.metadata.namespace === ns && d.spec.policyTypes.includes(type) && selects(d.spec.podSelector, labels));
const names = (list) => list.map((d) => d.metadata.name).sort();
const np = (ns, name) => netpols.find((d) => d.metadata.namespace === ns && d.metadata.name === name);
const portsOf = (d) => d.spec.egress.flatMap((r) => r.ports.map((p) => p.port));

test('the ledger API pods reach DNS, istiod, VPC endpoints, Aurora, MSK, Keycloak and the collector only', () => {
  assert.deepEqual(names(selecting(NS, API_POD, 'Egress')), [
    `allow-egress-${SA}-to-identity`,
    `allow-egress-${SA}-to-observability`,
    'allow-egress-aurora',
    'allow-egress-dns',
    'allow-egress-istiod',
    'allow-egress-msk',
    'allow-egress-vpc-https',
    'default-deny-all',
  ]);
  assert.deepEqual(portsOf(np(NS, 'allow-egress-aurora')), [5432]);
  assert.deepEqual(portsOf(np(NS, 'allow-egress-msk')), [9098, 9094]);
  assert.deepEqual(np(NS, 'allow-egress-msk').spec.podSelector.matchExpressions, [
    { key: 'app.kubernetes.io/name', operator: 'In', values: [SA] },
    { key: 'app.kubernetes.io/component', operator: 'In', values: ['service'] },
  ]);
  const toIdentity = np(NS, `allow-egress-${SA}-to-identity`).spec.egress;
  assert.deepEqual(toIdentity.map((r) => [r.to[0].podSelector.matchLabels, r.ports.map((p) => p.port)]), [[{ 'app.kubernetes.io/name': 'keycloak' }, [8080]]]);
  const toObs = np(NS, `allow-egress-${SA}-to-observability`).spec.egress;
  assert.deepEqual(toObs.map((r) => r.ports.map((p) => p.port)), [[4317, 4318]]);
  // No DocumentDB or Redis in corebanking.
  assert.equal(np(NS, 'allow-egress-documentdb'), undefined);
  assert.equal(np(NS, 'allow-egress-redis'), undefined);
});

test('the ledger API pods accept the gateway, the callers and Prometheus only', () => {
  assert.deepEqual(names(selecting(NS, API_POD, 'Ingress')), [
    'allow-ingress-from-istio-ingress',
    'allow-ingress-from-lending',
    'allow-ingress-from-observability',
    'allow-ingress-from-payments',
    'allow-ingress-node-health',
    'allow-ingress-observability-scrape',
    'default-deny-all',
  ]);
  const peers = (name) =>
    np(NS, name)
      .spec.ingress.flatMap((r) => r.from.map((f) => [f.namespaceSelector.matchLabels['kubernetes.io/metadata.name'], f.podSelector.matchLabels]))
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const ports = (name) => np(NS, name).spec.ingress.flatMap((r) => r.ports.map((p) => p.port));
  assert.deepEqual(peers('allow-ingress-from-payments'), [
    ['payments', { 'app.kubernetes.io/name': 'payment-bulk-orchestration-service' }],
    ['payments', { 'app.kubernetes.io/name': 'payment-initiation-settlement-service' }],
    ['payments', { 'app.kubernetes.io/name': 'payment-recurring-mandates-service' }],
  ]);
  assert.deepEqual(ports('allow-ingress-from-payments'), [8080]);
  assert.deepEqual(peers('allow-ingress-from-lending'), [['lending', { 'app.kubernetes.io/name': 'loan-lifecycle-service' }]]);
  assert.deepEqual(ports('allow-ingress-from-lending'), [8080]);
  assert.deepEqual(peers('allow-ingress-from-istio-ingress'), [['istio-ingress', contract.gateway.selector]]);
  assert.deepEqual(ports('allow-ingress-from-istio-ingress'), [8080]);
  assert.deepEqual(peers('allow-ingress-from-observability'), [['observability', { 'app.kubernetes.io/name': 'prometheus' }]]);
  assert.deepEqual(ports('allow-ingress-from-observability'), [8081]);
  assert.deepEqual(np(NS, 'allow-ingress-observability-scrape').spec.ingress[0].ports.map((p) => p.port), [8081, 15020, 15090]);
});

test('the four callers reach the ledger on 8080 and nothing else in corebanking; request to pay does not', () => {
  const notJob = [{ key: 'app.kubernetes.io/component', operator: 'NotIn', values: ['db-migration'] }];
  const expect = [
    ['payments', 'payment-initiation-settlement-service'],
    ['payments', 'payment-recurring-mandates-service'],
    ['payments', 'payment-bulk-orchestration-service'],
    ['lending', 'loan-lifecycle-service'],
  ];
  for (const [ns, caller] of expect) {
    const d = np(ns, `allow-egress-${caller}-to-${NS}`);
    assert.ok(d, `${ns}/${caller} has egress to corebanking`);
    assert.deepEqual(d.spec.podSelector, { matchLabels: { 'app.kubernetes.io/name': caller }, matchExpressions: notJob });
    assert.deepEqual(d.spec.egress, [
      { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': NS } }, podSelector: { matchLabels: { 'app.kubernetes.io/name': SA } } }], ports: [{ protocol: 'TCP', port: 8080 }] },
    ]);
  }
  assert.equal(np('payments', `allow-egress-payment-request-to-pay-service-to-${NS}`), undefined);
  for (const ns of ['payments', 'lending', 'observability']) {
    assert.ok(one('sidecars.yaml', 'Sidecar', ns, 'default').spec.egress[0].hosts.includes(`${NS}/*`), `${ns} Sidecar lists corebanking/*`);
  }
  for (const ns of ['customer', 'risk', 'compliance', 'open-finance', 'identity']) {
    assert.ok(!one('sidecars.yaml', 'Sidecar', ns, 'default').spec.egress[0].hosts.includes(`${NS}/*`), `${ns} Sidecar lists corebanking/*`);
  }
  const dr = one('destination-rules.yaml', 'DestinationRule', NS, SA);
  assert.equal(dr.spec.host, `${SA}.${NS}.svc.cluster.local`);
  assert.equal(dr.spec.trafficPolicy.connectionPool.tcp.connectTimeout, '1s');
  assert.equal(dr.spec.trafficPolicy.loadBalancer.simple, 'LEAST_REQUEST');
});

test('the accounts gap of payments is closed by the ledger edges', () => {
  assert.ok(!contract.gaps.some((g) => /core-banking accounts/.test(g.to)), 'the accounts API is no gap any more');
  const edge = contract.edges.find((e) => e.from === 'payments/payment-initiation-settlement-service' && e.to === `${NS}/${SA}` && e.methods?.includes('GET'));
  assert.ok(edge, 'initiation/settlement reads accounts from the ledger');
  assert.deepEqual(edge.paths, ['/api/v1/accounts/{*}']);
  assert.match(edge.evidence, /CoreBankingAccountHttpAdapter/);
});

test('ExternalSecrets in corebanking read only <env>/accounts-ledger-service/ keys', () => {
  assert.deepEqual(secretScopes(contract)[NS], [SA]);
  const vap = docs['externalsecret-admission.yaml'].find((d) => d.kind === 'ValidatingAdmissionPolicy');
  const scopes = vap.spec.variables.find((v) => v.name === 'scopes').expression;
  assert.ok(scopes.includes(`'${NS}': ['${SA}']`), scopes);
  const deployable = loadRepoDocs().filter((d) => ['deploy/', 'k8s/platform/'].some((x) => d.file.startsWith(x)));
  // The service store admits corebanking by its namespace-kind label.
  const store = deployable.find((d) => d.doc.kind === 'ClusterSecretStore' && d.doc.metadata.name === contract.secrets.serviceStore).doc;
  const nsLabels = docs['namespaces.yaml'].find((d) => d.metadata.name === NS).metadata.labels;
  assert.ok(store.spec.conditions.some((c) => c.namespaceSelector && selects(c.namespaceSelector, nsLabels)));
  const es = (label, keys) => ({
    file: 'inline.yaml',
    index: 0,
    doc: {
      apiVersion: 'external-secrets.io/v1beta1',
      kind: 'ExternalSecret',
      metadata: { name: 'probe', namespace: NS, labels: { 'app.kubernetes.io/name': label } },
      spec: { secretStoreRef: { kind: 'ClusterSecretStore', name: 'aws-secrets-manager' }, data: keys.map((key, i) => ({ secretKey: `k${i}`, remoteRef: { key, property: 'password' } })) },
    },
  });
  const r10 = (d) => checkZeroTrust([...deployable, d], contract).filter((e) => e.startsWith('R10'));
  // The chart's runtime and migration secrets (values externalSecret / migration remoteSecretName).
  assert.deepEqual(r10(es(SA, ['ENVIRONMENT/accounts-ledger-service/db-app', 'ENVIRONMENT/accounts-ledger-service/db-migration'])), []);
  // The coordinator's "env/acc-accounts-ledger" form is not the platform rule <env>/<slug>/.
  assert.ok(r10(es(SA, ['ENVIRONMENT/acc-accounts-ledger/db-app'])).some((e) => e.includes('outside <env>/accounts-ledger-service/')));
  assert.ok(r10(es('acc-accounts-ledger', ['ENVIRONMENT/acc-accounts-ledger/db-app'])).some((e) => e.includes('app.kubernetes.io/name')));
  // The hook ServiceAccount is no slug: the migration ExternalSecret carries the service's name.
  assert.ok(r10(es(`${SA}-db-migration`, [`ENVIRONMENT/${SA}-db-migration/db-migration`])).some((e) => e.includes('app.kubernetes.io/name')));
});
