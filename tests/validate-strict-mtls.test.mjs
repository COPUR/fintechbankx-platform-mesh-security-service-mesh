// Tests for the strict-mTLS / zero-trust validator and the mesh contract.
// Every negative case mutates a copy of the real deployable manifests, so a
// rule that stops firing makes its test fail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  loadRepoDocs,
  checkMtlsModes,
  checkZeroTrust,
  checkGenerated,
  checkTelemetryTags,
  parseDocs,
} from '../scripts/validation/validate-strict-mtls.mjs';
import { loadContract, expandEdges, knownServiceAccounts, secretScopes } from '../scripts/lib/contract.mjs';

const contract = loadContract();
const all = loadRepoDocs();
const deployable = () =>
  structuredClone(all.filter((d) => d.file.startsWith('deploy/') || d.file.startsWith('k8s/platform/')));
const find = (docs, kind, ns, name) =>
  docs.find((d) => d.doc.kind === kind && d.doc.metadata?.namespace === ns && d.doc.metadata?.name === name);
const hasRule = (errors, rule, text) => errors.some((e) => e.startsWith(rule) && e.includes(text));

test('repository manifests pass every rule', async () => {
  assert.deepEqual(checkMtlsModes(all, contract), []);
  assert.deepEqual(checkZeroTrust(deployable(), contract), []);
  assert.deepEqual(await checkGenerated(), []);
});

test('R1 rejects a PERMISSIVE PeerAuthentication', () => {
  const docs = parseDocs(
    'apiVersion: security.istio.io/v1\nkind: PeerAuthentication\nmetadata: {name: x, namespace: lending}\nspec: {mtls: {mode: PERMISSIVE}}\n',
    'inline.yaml',
  );
  assert.ok(hasRule(checkMtlsModes(docs, contract), 'R1', 'PERMISSIVE'));
});

test('R1 rejects DISABLE on a port-level override', () => {
  const docs = parseDocs(
    'apiVersion: security.istio.io/v1\nkind: PeerAuthentication\nmetadata: {name: x, namespace: risk}\n' +
      'spec: {mtls: {mode: STRICT}, portLevelMtls: {"8081": {mode: DISABLE}}}\n',
    'inline.yaml',
  );
  assert.ok(hasRule(checkMtlsModes(docs, contract), 'R1', 'DISABLE'));
});

test('R1 accepts a weak mode only in a documented exception namespace', () => {
  const docs = parseDocs(
    'apiVersion: security.istio.io/v1\nkind: PeerAuthentication\nmetadata: {name: x, namespace: legacy}\nspec: {mtls: {mode: PERMISSIVE}}\n',
    'inline.yaml',
  );
  const excepted = structuredClone(contract);
  excepted.exceptions.peerAuthentication = [{ namespace: 'legacy', reason: 'test' }];
  assert.deepEqual(checkMtlsModes(docs, excepted), []);
  assert.equal(checkMtlsModes(docs, contract).length, 1);
});

test('R1 rejects a DestinationRule that disables TLS for an in-mesh host', () => {
  const docs = parseDocs(
    'apiVersion: networking.istio.io/v1\nkind: DestinationRule\nmetadata: {name: x, namespace: customer}\n' +
      'spec: {host: customer-profile-kyc-service.customer.svc.cluster.local, trafficPolicy: {tls: {mode: DISABLE}}}\n',
    'inline.yaml',
  );
  assert.ok(hasRule(checkMtlsModes(docs, contract), 'R1', 'disables TLS'));
});

test('R2 requires the mesh-wide STRICT PeerAuthentication', () => {
  const docs = deployable();
  find(docs, 'PeerAuthentication', 'istio-system', 'default').doc.spec.mtls.mode = 'UNSET';
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R2', 'STRICT'));
});

test('R3 fails when a service namespace loses its default-deny AuthorizationPolicy', () => {
  const docs = deployable().filter(
    (d) => !(d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === 'risk' && d.doc.metadata.name === 'default-deny'),
  );
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R3', 'namespace risk has no default-deny AuthorizationPolicy'));
});

test('R3 fails when a namespace loses its default-deny NetworkPolicy', () => {
  const docs = deployable();
  find(docs, 'NetworkPolicy', 'payments', 'default-deny-all').doc.spec.policyTypes = ['Ingress'];
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R3', 'namespace payments has no default-deny NetworkPolicy'));
});

test('R4 rejects a principal that is not a contract service account', () => {
  const docs = deployable();
  const ap = find(docs, 'AuthorizationPolicy', 'customer', 'allow-from-lending-loan-lifecycle-service-to-customer-profile-kyc-service');
  ap.doc.spec.rules[0].from[0].source.principals = ['cluster.local/ns/lending/sa/default'];
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R4', 'cluster.local/ns/lending/sa/default'));
});

test('R5 rejects an allow-all rule', () => {
  const docs = deployable();
  find(docs, 'AuthorizationPolicy', 'lending', 'allow-health-endpoints').doc.spec.rules = [{}];
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R5', 'allows everything'));
});

test('R6 rejects sidecar injection on a namespace the contract keeps out of the mesh', () => {
  const docs = deployable();
  const ns = docs.find((d) => d.doc.kind === 'Namespace' && d.doc.metadata.name === 'external-secrets');
  ns.doc.metadata.labels['istio-injection'] = 'enabled';
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R6', 'external-secrets must not be injected'));
});

test('R7 requires the workload service id as JWT audience', () => {
  const docs = deployable();
  delete find(docs, 'RequestAuthentication', 'lending', 'keycloak-jwt-loan-lifecycle-service').doc.spec.jwtRules[0].audiences;
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R7', 'svc-ln-loan-lifecycle'));
});

test('R7 requires a JWT on /api/** in every Keycloak namespace', () => {
  const docs = deployable().filter(
    (d) => !(d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === 'compliance' && d.doc.metadata.name === 'require-jwt-for-api'),
  );
  assert.ok(hasRule(checkZeroTrust(docs, contract), 'R7', 'namespace compliance has no DENY policy'));
});

test('contract: every edge endpoint is a known service account', () => {
  const known = knownServiceAccounts(contract);
  for (const e of expandEdges(contract)) {
    assert.ok(known.has(`${e.from.ns}/${e.from.sa}`), `unknown caller ${e.from.ns}/${e.from.sa}`);
    assert.ok(known.has(`${e.to.ns}/${e.to.sa}`), `unknown callee ${e.to.ns}/${e.to.sa}`);
  }
});

test('contract: recorded gaps are not allowed by any policy', () => {
  const docs = deployable();
  const text = JSON.stringify(docs.map((d) => d.doc));
  assert.ok(contract.gaps.some((g) => g.to.startsWith('core-banking')));
  assert.ok(!text.includes('core-banking'), 'no manifest may route or allow traffic to core-banking yet');
  const paymentEgress = docs.filter(
    (d) => d.doc.kind === 'NetworkPolicy' && d.doc.metadata.namespace === 'payments' && /^allow-egress-.+-to-/.test(d.doc.metadata.name),
  );
  const targets = new Set(paymentEgress.map((d) => d.doc.metadata.name.replace(/^.*-to-/, '')));
  assert.deepEqual([...targets].sort(), ['compliance', 'customer', 'identity', 'observability', 'open-finance', 'risk']);
});

test('contract: payments reads only the customer KYC status, with GET', () => {
  const edges = expandEdges(contract).filter(
    (e) => e.from.sa === 'payment-initiation-settlement-service' && e.to.sa === 'customer-profile-kyc-service',
  );
  assert.deepEqual(edges.map((e) => [e.methods, e.paths]), [[['GET'], ['/api/v1/customers/{*}/kyc-status']]]);
});

test('contract: east-west service edges are exactly the confirmed ones and scoped', () => {
  const svcNs = new Set(['lending', 'payments', 'customer', 'risk', 'compliance', 'open-finance']);
  const eastWest = expandEdges(contract).filter((e) => svcNs.has(e.from.ns) && svcNs.has(e.to.ns));
  assert.deepEqual([...new Set(eastWest.map((e) => `${e.from.ns}/${e.from.sa}->${e.to.ns}/${e.to.sa}`))].sort(), [
    'lending/loan-lifecycle-service->customer/customer-profile-kyc-service',
    'payments/payment-bulk-orchestration-service->open-finance/consent-authorization-service',
    'payments/payment-initiation-settlement-service->compliance/compliance-evidence-service',
    'payments/payment-initiation-settlement-service->customer/customer-profile-kyc-service',
    'payments/payment-initiation-settlement-service->open-finance/payee-verification-service',
    'payments/payment-initiation-settlement-service->risk/risk-decisioning-service',
    'payments/payment-recurring-mandates-service->open-finance/consent-authorization-service',
  ]);
  for (const e of eastWest) {
    assert.ok(
      (e.methods?.length && e.paths?.length) || e.scope === 'port-only',
      'east-west edges must name methods and paths or be marked scope: port-only',
    );
    assert.equal(e.port, 8080);
  }
});

test('contract: datastore egress is scoped to the workloads that declare the store', () => {
  const docs = deployable();
  const np = (ns, name) =>
    docs.find((d) => d.doc.kind === 'NetworkPolicy' && d.doc.metadata.namespace === ns && d.doc.metadata.name === name)?.doc;
  const selected = (doc) => doc.spec.podSelector.matchExpressions[0].values;
  const dataServices = ['banking-metadata-service', 'business-financial-data-service', 'personal-financial-data-service'];
  assert.deepEqual(selected(np('open-finance', 'allow-egress-documentdb')), dataServices);
  assert.deepEqual(selected(np('open-finance', 'allow-egress-redis')), dataServices);
  assert.deepEqual(np('open-finance', 'allow-egress-documentdb').spec.egress[0].ports, [{ protocol: 'TCP', port: 27017 }]);
  assert.deepEqual(np('open-finance', 'allow-egress-redis').spec.egress[0].ports, [{ protocol: 'TCP', port: 6379 }]);
  assert.deepEqual(selected(np('open-finance', 'allow-egress-aurora')), [
    'atm-directory-service', 'consent-authorization-service', 'open-products-catalog-service', 'payee-verification-service',
  ]);
  assert.deepEqual(selected(np('open-finance', 'allow-egress-msk')), [
    'banking-metadata-service', 'business-financial-data-service', 'consent-authorization-service',
    'payee-verification-service', 'personal-financial-data-service',
  ]);
  // Every payment workload owns an Aurora database and an outbox relay to MSK.
  for (const name of ['allow-egress-aurora', 'allow-egress-msk']) {
    assert.deepEqual(selected(np('payments', name)), [
      'payment-bulk-orchestration-service', 'payment-initiation-settlement-service',
      'payment-recurring-mandates-service', 'payment-request-to-pay-service',
    ]);
  }
  for (const ns of ['lending', 'payments', 'customer', 'risk', 'compliance']) {
    assert.equal(np(ns, 'allow-egress-documentdb'), undefined);
    assert.equal(np(ns, 'allow-egress-redis'), undefined);
  }
});

test('contract: open-finance keeps its documented token exception and is still default-deny', () => {
  const docs = deployable();
  const inOf = (kind) => docs.filter((d) => d.doc.kind === kind && d.doc.metadata.namespace === 'open-finance').map((d) => d.doc);
  assert.equal(inOf('RequestAuthentication').length, 0);
  assert.ok(inOf('AuthorizationPolicy').some((p) => p.metadata.name === 'default-deny'));
  const callers = new Set(
    inOf('AuthorizationPolicy')
      .filter((p) => p.spec.action === 'ALLOW')
      .flatMap((p) => p.spec.rules.flatMap((r) => (r.from || []).flatMap((f) => f.source.principals || []))),
  );
  assert.deepEqual([...callers].sort(), [
    'cluster.local/ns/istio-ingress/sa/istio-ingressgateway',
    'cluster.local/ns/observability/sa/prometheus',
    'cluster.local/ns/payments/sa/payment-bulk-orchestration-service',
    'cluster.local/ns/payments/sa/payment-initiation-settlement-service',
    'cluster.local/ns/payments/sa/payment-recurring-mandates-service',
  ]);
});

test('R9: a workload without a sidecar needs a documented exception', () => {
  const c = structuredClone(contract);
  c.exceptions.workloadInjection = c.exceptions.workloadInjection.filter((x) => x.workload !== 'observability/kube-state-metrics');
  const errors = checkZeroTrust(deployable(), c);
  assert.ok(errors.some((e) => e.startsWith('R9 observability/kube-state-metrics')), errors.join('\n'));
  assert.deepEqual(checkZeroTrust(deployable(), contract), []);
});

test('observability: chart selectors, shared service accounts and no principals for sidecar-less pods', () => {
  const docs = deployable();
  const ap = (ns, name) => docs.find((d) => d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === ns && d.doc.metadata.name === name)?.doc;
  // otel pods are labelled by the chart, not by service account.
  assert.deepEqual(ap('observability', 'allow-from-observability-otel-collector-to-otel-gateway').spec.selector.matchLabels, {
    'app.kubernetes.io/name': 'opentelemetry-collector', 'app.kubernetes.io/instance': 'otel-gateway',
  });
  // Tempo metrics-generator writes to Prometheus with the shared tempo principal.
  const mg = ap('observability', 'allow-from-observability-tempo-to-prometheus');
  assert.deepEqual(mg.spec.rules[0].from[0].source.principals, ['cluster.local/ns/observability/sa/tempo']);
  assert.deepEqual(mg.spec.rules[0].to[0].operation, { ports: ['9090'], methods: ['POST'], paths: ['/api/v1/write'] });
  // Sidecar-less workloads: never a principal, never an AuthorizationPolicy target.
  const text = JSON.stringify(docs.filter((d) => d.doc.kind === 'AuthorizationPolicy').map((d) => d.doc));
  assert.ok(!text.includes('kube-state-metrics') && !text.includes('kube-prometheus-stack-operator'));
  // Every meshed workload, the gateway included, may send OTLP / Envoy spans to the agent.
  const callers = docs
    .filter((d) => d.doc.kind === 'AuthorizationPolicy' && /-to-otel-collector$/.test(d.doc.metadata.name))
    .flatMap((d) => d.doc.spec.rules.flatMap((r) => r.from[0].source.principals));
  for (const p of ['istio-ingress/sa/istio-ingressgateway', 'identity/sa/keycloak', 'lending/sa/loan-lifecycle-service', 'open-finance/sa/atm-directory-service']) {
    assert.ok(callers.includes(`cluster.local/ns/${p}`), p);
  }
});

test('identity: realm import, JGroups ports and management scrape', () => {
  const docs = deployable();
  const ops = (name) =>
    docs.find((d) => d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === 'identity' && d.doc.metadata.name === name)
      .doc.spec.rules.map((r) => r.to[0].operation);
  assert.deepEqual(ops('allow-from-identity-keycloak-to-keycloak').map((o) => o.ports[0]).sort(), ['57800', '7800']);
  assert.deepEqual(ops('allow-from-identity-keycloak-realm-import-to-keycloak'), [{ ports: ['8080'], paths: ['/', '/admin/*', '/realms/*'] }]);
  assert.deepEqual(ops('allow-from-observability-prometheus-to-keycloak'), [{ ports: ['9000'], methods: ['GET'], paths: ['/metrics', '/health', '/health/*'] }]);
  assert.deepEqual(ops('allow-from-observability-grafana-to-keycloak')[0].ports, ['8080']);
});

test('gateway: every public route overwrites the forwarded headers (DPoP htu)', () => {
  const vss = deployable().filter((d) => d.doc.kind === 'VirtualService' && d.doc.metadata.namespace === 'istio-ingress');
  assert.ok(vss.length >= 2);
  for (const { doc } of vss) {
    const host = doc.spec.hosts[0];
    for (const route of doc.spec.http) {
      assert.deepEqual(
        route.headers?.request?.set,
        { 'x-forwarded-proto': 'https', 'x-forwarded-host': host, 'x-forwarded-port': '443' },
        `${doc.metadata.name}/${route.name}`,
      );
      assert.deepEqual(route.headers.request.remove, ['forwarded', 'x-forwarded-prefix'], `${doc.metadata.name}/${route.name}`);
    }
  }
});

test('gateway: service-only operations are not reachable from the ingress gateway', () => {
  const docs = deployable();
  const gwOps = (ns, name) =>
    docs
      .find((d) => d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === ns && d.doc.metadata.name === name)
      .doc.spec.rules.map((r) => r.to[0].operation);
  // /credit and below is excluded; GET /credit comes back through a GET-only rule (tests/customer-edge.test.mjs).
  const customer = gwOps('customer', 'allow-from-istio-ingress-istio-ingressgateway-to-customer-profile-kyc-service');
  assert.deepEqual(customer[0].notPaths, ['/api/v1/customers/{*}/credit', '/api/v1/customers/{*}/credit/', '/api/v1/customers/{*}/credit/{**}']);
  assert.deepEqual(customer[1], { ports: ['8080'], methods: ['GET'], paths: ['/api/v1/customers/{*}/credit'] });
  assert.deepEqual(gwOps('risk', 'allow-from-istio-ingress-istio-ingressgateway-to-risk-decisioning-service')[0].notPaths, ['/api/v1/risk/assess', '/api/v1/risk/assess/*']);
  assert.deepEqual(gwOps('compliance', 'allow-from-istio-ingress-istio-ingressgateway-to-compliance-evidence-service')[0].notPaths, ['/api/v1/compliance/screen', '/api/v1/compliance/screen/*']);
  const admin = gwOps('identity', 'allow-from-customer-customer-profile-kyc-service-to-keycloak');
  assert.ok(admin.some((o) => o.methods?.includes('PUT') && o.paths.includes('/admin/realms/fintechbankx/users/*')));
});

test('gateway: TPP payment APIs and the consent authorization flow are routed and allowed', () => {
  const docs = deployable();
  const api = docs.find((d) => d.doc.kind === 'VirtualService' && d.doc.metadata.name === 'fintechbankx-api').doc;
  const prefixes = (id) => api.spec.http.find((r) => r.name === id).match.map((m) => m.uri.prefix);
  assert.deepEqual(prefixes('svc-of-consent-authorization'), ['/open-finance/v1/consents', '/oauth2', '/api/v1/consents']);
  assert.deepEqual(prefixes('svc-pay-recurring-mandates'), ['/open-finance/v1/vrp']);
  assert.deepEqual(prefixes('svc-pay-bulk-orchestration'), ['/open-finance/v1/file-payments']);
  const paths = (ns, name) =>
    docs
      .find((d) => d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === ns && d.doc.metadata.name === name)
      .doc.spec.rules.flatMap((r) => r.to.flatMap((t) => t.operation.paths || []));
  const consent = paths('open-finance', 'allow-from-istio-ingress-istio-ingressgateway-to-consent-authorization-service');
  for (const p of ['/oauth2/authorize', '/oauth2/token', '/api/v1/consents', '/api/v1/consents/{*}/authorize', '/api/v1/consents/{*}/revoke']) assert.ok(consent.includes(p), p);
  assert.ok(!consent.includes('/api/v1/consents/*'), 'service view GET /api/v1/consents/{id} stays in-cluster');
  assert.ok(paths('payments', 'allow-from-istio-ingress-istio-ingressgateway-to-payment-recurring-mandates-service').includes('/open-finance/v1/vrp/payments/*'));
  assert.ok(paths('payments', 'allow-from-istio-ingress-istio-ingressgateway-to-payment-bulk-orchestration-service').includes('/open-finance/v1/file-payments/*'));
});

test('gateway: request-to-pay TPP paths, open-data rate limit and the RDS CA bundle', () => {
  const docs = deployable();
  const api = docs.find((d) => d.doc.kind === 'VirtualService' && d.doc.metadata.name === 'fintechbankx-api').doc;
  // Request to pay is routed only by the runbook's exact cut-over rules
  // (tests/rtp-cutover.test.mjs), never by prefix; R3 is absent while the cohort is empty.
  assert.equal(api.spec.http.find((r) => r.name === 'svc-pay-request-to-pay'), undefined);
  assert.deepEqual(api.spec.http.slice(0, 3).map((r) => r.name), ['rtp-cutover-r1', 'rtp-cutover-r2', 'rtp-cutover-r4']);
  for (const r of api.spec.http.slice(0, 3)) for (const m of r.match) assert.ok(m.uri.regex && !m.uri.prefix, r.name);
  const ef = docs.find((d) => d.doc.kind === 'EnvoyFilter' && d.doc.metadata.name === 'anonymous-open-data-rate-limit').doc;
  const limited = ef.spec.configPatches.filter((p) => p.applyTo === 'HTTP_ROUTE').map((p) => p.match.routeConfiguration.vhost.route.name);
  assert.deepEqual(limited, ['svc-of-open-products-catalog', 'svc-of-atm-directory', 'svc-of-banking-metadata']);
  const routeNames = new Set(api.spec.http.map((r) => r.name));
  for (const r of limited) assert.ok(routeNames.has(r), `rate-limited route ${r} exists on the gateway`);
  const bundle = docs.find((d) => d.doc.kind === 'Bundle' && d.doc.metadata.name === 'rds-ca-bundle').doc;
  assert.equal(bundle.spec.target.configMap.key, 'global-bundle.pem');
  assert.deepEqual(bundle.spec.sources, [{ configMap: { name: 'amazon-rds-ca-source', key: 'global-bundle.pem' } }]);
});

// Cartesian (method, path) pairs an ALLOW rule admits; a rule without methods admits every method ('*').
const pairsOf = (op) => (op.methods || ['*']).flatMap((m) => (op.paths || ['*']).map((p) => `${m} ${p}`));

test('consent: the gateway allows exactly the documented (method, path) pairs', () => {
  const docs = deployable();
  const ap = docs.find(
    (d) => d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === 'open-finance' &&
      d.doc.metadata.name === 'allow-from-istio-ingress-istio-ingressgateway-to-consent-authorization-service',
  ).doc;
  const pairs = ap.spec.rules.flatMap((r) => r.to.flatMap((t) => pairsOf(t.operation))).sort();
  assert.deepEqual(pairs, [
    '* /open-finance/v1/consents',
    '* /open-finance/v1/consents/*',
    'GET /api/v1/consents',
    'GET /oauth2/authorize',
    'PATCH /api/v1/consents/{*}/revoke',
    'POST /api/v1/consents/{*}/authorize',
    'POST /oauth2/token',
  ]);
  for (const bad of ['POST /oauth2/authorize', 'GET /oauth2/token', 'PATCH /api/v1/consents/{*}/authorize', 'POST /api/v1/consents/{*}/revoke']) {
    assert.ok(!pairs.includes(bad), `${bad} must not be allowed`);
  }
});

test('consent: the in-cluster GET /api/v1/consents/{id} view is open to bulk and recurring mandates only', () => {
  const docs = deployable();
  const callers = docs
    .filter((d) => d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === 'open-finance' && /-to-consent-authorization-service$/.test(d.doc.metadata.name))
    .flatMap((d) => d.doc.spec.rules)
    .filter((r) => r.to.some((t) => (t.operation.paths || []).includes('/api/v1/consents/*')))
    .flatMap((r) => r.from.flatMap((f) => f.source.principals));
  assert.deepEqual(callers.sort(), [
    'cluster.local/ns/payments/sa/payment-bulk-orchestration-service',
    'cluster.local/ns/payments/sa/payment-recurring-mandates-service',
  ]);
});

test('consent: every rule into consent-auth names its paths (no port-only access to /internal/v1)', () => {
  const docs = deployable();
  const rules = docs
    .filter((d) => d.doc.kind === 'AuthorizationPolicy' && d.doc.metadata.namespace === 'open-finance' && /-to-consent-authorization-service$/.test(d.doc.metadata.name))
    .flatMap((d) => d.doc.spec.rules);
  assert.ok(rules.length > 0);
  for (const r of rules) {
    assert.ok(r.to?.every((t) => (t.operation.paths || []).length > 0), JSON.stringify(r.from));
  }
});

// ------------------------------------------------------------------ secrets (R10)
// These tests check the manifests' structure (store conditions, which store
// each ExternalSecret uses, the admission policy's match and expressions) and
// the validator's static ExternalSecret check. The CEL of the
// ValidatingAdmissionPolicy is executed with cel-go in
// tests/externalsecret-admission-cel.test.mjs.
const SVC_STORE = 'aws-secrets-manager';
const PF_STORE = 'aws-secrets-manager-platform';
const store = (docs, name) => docs.find((d) => d.doc.kind === 'ClusterSecretStore' && d.doc.metadata.name === name);
const externalSecret = (ns, { store: s = SVC_STORE, label, keys = [], dataFrom } = {}) => ({
  file: 'inline.yaml',
  index: 0,
  doc: {
    apiVersion: 'external-secrets.io/v1beta1',
    kind: 'ExternalSecret',
    metadata: { name: 'probe', namespace: ns, ...(label ? { labels: { 'app.kubernetes.io/name': label } } : {}) },
    spec: {
      secretStoreRef: { kind: 'ClusterSecretStore', name: s },
      data: keys.map((key, i) => ({ secretKey: `k${i}`, remoteRef: { key, property: 'password' } })),
      ...(dataFrom ? { dataFrom } : {}),
    },
  },
});
const r10 = (docs) => checkZeroTrust(docs, contract).filter((e) => e.startsWith('R10'));

test('R10 the service store is limited by conditions to service namespaces', () => {
  const docs = deployable();
  assert.deepEqual(store(docs, SVC_STORE).doc.spec.conditions, [
    { namespaceSelector: { matchLabels: { 'fintechbankx.io/namespace-kind': 'service' } } },
    { namespaces: ['observability'] },
  ]);
  delete store(docs, SVC_STORE).doc.spec.conditions;
  assert.ok(hasRule(r10(docs), 'R10', `${SVC_STORE} has no spec.conditions`), r10(docs).join('\n'));

  const widened = deployable();
  store(widened, SVC_STORE).doc.spec.conditions.push({ namespaces: ['cert-manager'] });
  assert.ok(hasRule(r10(widened), 'R10', 'cert-manager'), r10(widened).join('\n'));

  const open = deployable();
  store(open, SVC_STORE).doc.spec.conditions.push({ namespaceSelector: {} });
  assert.ok(hasRule(r10(open), 'R10', 'condition'), r10(open).join('\n'));
});

test('R10 the platform store is limited to cert-manager, istio-ingress and identity, with its own service account', () => {
  const docs = deployable();
  const pf = store(docs, PF_STORE).doc;
  assert.deepEqual(pf.spec.conditions, [{ namespaces: ['cert-manager', 'istio-ingress', 'identity'] }]);
  assert.equal(pf.spec.provider.aws.auth.jwt.serviceAccountRef.name, 'external-secrets-platform');
  assert.equal(store(docs, SVC_STORE).doc.spec.provider.aws.auth.jwt.serviceAccountRef.name, 'external-secrets');

  const widened = deployable();
  store(widened, PF_STORE).doc.spec.conditions[0].namespaces.push('payments');
  assert.ok(hasRule(r10(widened), 'R10', 'payments'), r10(widened).join('\n'));

  const selector = deployable();
  store(selector, PF_STORE).doc.spec.conditions.push({ namespaceSelector: { matchLabels: { 'fintechbankx.io/namespace-kind': 'platform' } } });
  assert.ok(hasRule(r10(selector), 'R10', 'namespaceSelector'), r10(selector).join('\n'));

  const shared = deployable();
  store(shared, PF_STORE).doc.spec.provider.aws.auth.jwt.serviceAccountRef.name = 'external-secrets';
  assert.ok(hasRule(r10(shared), 'R10', 'own service account'), r10(shared).join('\n'));
});

test('R10 platform ExternalSecrets in this repo use the platform store', () => {
  const docs = deployable();
  const es = docs.filter((d) => d.doc.kind === 'ExternalSecret').map((d) => d.doc);
  assert.deepEqual(es.map((d) => `${d.metadata.namespace}/${d.metadata.name}`).sort(), [
    'cert-manager/corporate-directory-ca-source',
    'cert-manager/fintechbankx-internal-ca-keypair',
    'istio-ingress/fintechbankx-ingress-tls',
  ]);
  for (const d of es) assert.equal(d.spec.secretStoreRef.name, PF_STORE, d.metadata.name);
  find(docs, 'ExternalSecret', 'cert-manager', 'fintechbankx-internal-ca-keypair').doc.spec.secretStoreRef.name = SVC_STORE;
  assert.ok(hasRule(r10(docs), 'R10', 'fintechbankx-internal-ca-keypair'), r10(docs).join('\n'));
});

test('R10 rejects a service-namespace ExternalSecret on the platform store or outside its slug', () => {
  const ok = externalSecret('payments', {
    label: 'payment-bulk-orchestration-service',
    keys: ['ENVIRONMENT/payment-bulk-orchestration-service/db-app', 'ENVIRONMENT/payment-bulk-orchestration-service/oidc-client'],
  });
  assert.deepEqual(r10([...deployable(), ok]), []);

  const onPlatformStore = structuredClone(ok);
  onPlatformStore.doc.spec.secretStoreRef.name = PF_STORE;
  assert.ok(hasRule(r10([...deployable(), onPlatformStore]), 'R10', PF_STORE));

  const platformKey = externalSecret('payments', { label: 'payment-bulk-orchestration-service', keys: ['ENVIRONMENT/platform/internal-ca'] });
  assert.ok(hasRule(r10([...deployable(), platformKey]), 'R10', 'ENVIRONMENT/platform/internal-ca'));

  // Same namespace, another service's slug: payments hosts four services.
  const neighbour = externalSecret('payments', { label: 'payment-bulk-orchestration-service', keys: ['ENVIRONMENT/payment-initiation-settlement-service/db-app'] });
  assert.ok(hasRule(r10([...deployable(), neighbour]), 'R10', 'payment-initiation-settlement-service/db-app'));

  const foreignLabel = externalSecret('payments', { label: 'loan-lifecycle-service', keys: ['ENVIRONMENT/loan-lifecycle-service/db-app'] });
  assert.ok(hasRule(r10([...deployable(), foreignLabel]), 'R10', 'app.kubernetes.io/name'));

  const unlabelled = externalSecret('payments', { keys: ['ENVIRONMENT/payment-bulk-orchestration-service/db-app'] });
  assert.ok(hasRule(r10([...deployable(), unlabelled]), 'R10', 'app.kubernetes.io/name'));

  const find_ = externalSecret('lending', { label: 'loan-lifecycle-service', dataFrom: [{ find: { name: { regexp: '.*' } } }] });
  assert.ok(hasRule(r10([...deployable(), find_]), 'R10', 'find'));

  const extract = externalSecret('lending', { label: 'loan-lifecycle-service', dataFrom: [{ extract: { key: 'ENVIRONMENT/identity-keycloak/bootstrap-admin-client' } }] });
  assert.ok(hasRule(r10([...deployable(), extract]), 'R10', 'identity-keycloak'));
});

test('externalsecret admission policy: match, bindings and expressions', () => {
  const docs = deployable();
  const vap = docs.find((d) => d.doc.kind === 'ValidatingAdmissionPolicy' && d.doc.metadata.name === 'fintechbankx-externalsecret-scope').doc;
  const binding = docs.find((d) => d.doc.kind === 'ValidatingAdmissionPolicyBinding').doc;
  assert.equal(vap.apiVersion, 'admissionregistration.k8s.io/v1');
  assert.equal(vap.spec.failurePolicy, 'Fail');
  assert.deepEqual(vap.spec.matchConstraints.resourceRules, [
    { apiGroups: ['external-secrets.io'], apiVersions: ['*'], operations: ['CREATE', 'UPDATE'], resources: ['externalsecrets'] },
  ]);
  assert.deepEqual(vap.spec.matchConstraints.namespaceSelector.matchExpressions, [
    { key: 'fintechbankx.io/namespace-kind', operator: 'Exists' },
    { key: 'kubernetes.io/metadata.name', operator: 'NotIn', values: ['cert-manager', 'istio-ingress', 'identity'] },
  ]);
  assert.equal(binding.apiVersion, 'admissionregistration.k8s.io/v1');
  assert.equal(binding.spec.policyName, vap.metadata.name);
  assert.deepEqual(binding.spec.validationActions, ['Deny']);
  const v = Object.fromEntries(vap.spec.variables.map((x) => [x.name, x.expression]));
  assert.equal(v.env, "'ENVIRONMENT'", 'the overlay substitutes the environment');
  // The slug map is the contract's: payments holds four services.
  const scopes = secretScopes(contract);
  assert.deepEqual(scopes.payments, [
    'payment-bulk-orchestration-service', 'payment-initiation-settlement-service',
    'payment-recurring-mandates-service', 'payment-request-to-pay-service',
  ]);
  for (const [ns, slugs] of Object.entries(scopes)) {
    assert.ok(v.scopes.includes(`'${ns}': [${slugs.map((x) => `'${x}'`).join(', ')}]`), ns);
    for (const p of contract.secrets.platformKeyPrefixes) assert.ok(!slugs.includes(p), `${ns} may not read ${p}/`);
  }
  assert.match(v.slug, /object\.metadata\.labels\['app\.kubernetes\.io\/name'\]/);
  assert.match(v.serviceNamespace, /namespaceObject\.metadata\.labels\['fintechbankx\.io\/namespace-kind'\] == 'service'/);
  assert.match(v.keys, /remoteRef\.key/);
  assert.match(v.keys, /extract\.key/);
  const exprs = vap.spec.validations.map((x) => x.expression).join('\n');
  assert.match(exprs, /secretStoreRef\.name == 'aws-secrets-manager'/);
  assert.match(exprs, /!has\(f\.find\)/);
  assert.match(exprs, /!has\(d\.sourceRef\)/);
  assert.match(exprs, /!has\(f\.sourceRef\)/);
  assert.match(exprs, /variables\.keys\.all\(k, variables\.prefixes\.exists\(p, k\.startsWith\(p\)\)\)/);
  for (const x of vap.spec.validations) assert.ok(x.message || x.messageExpression, x.expression);
});

test('R10 fails when the admission policy or its Deny binding is missing', () => {
  const noPolicy = deployable().filter((d) => d.doc.kind !== 'ValidatingAdmissionPolicy');
  assert.ok(hasRule(r10(noPolicy), 'R10', 'ValidatingAdmissionPolicy'));
  const audit = deployable();
  audit.find((d) => d.doc.kind === 'ValidatingAdmissionPolicyBinding').doc.spec.validationActions = ['Audit'];
  assert.ok(hasRule(r10(audit), 'R10', 'Deny'));
});

// ------------------------------------------------------------------ R11
// consent-authorization-service serves /internal/v1 (never routed) and the
// token endpoint: a port-only ALLOW would reach both. No service may be
// reached on /internal/* through any ALLOW path pattern.
const r11 = (docs) => checkZeroTrust(docs, contract).filter((e) => e.startsWith('R11'));
const consentPolicy = (docs, caller) =>
  find(docs, 'AuthorizationPolicy', 'open-finance', `allow-from-${caller}-to-consent-authorization-service`).doc;

test('R11 rejects an ALLOW into consent-authorization-service without paths', () => {
  assert.deepEqual(r11(deployable()), []);
  const portOnly = deployable();
  delete consentPolicy(portOnly, 'payments-payment-bulk-orchestration-service').spec.rules[0].to[0].operation.paths;
  assert.ok(hasRule(r11(portOnly), 'R11', 'consent-authorization-service without paths'), r11(portOnly).join('\n'));

  const fromOnly = deployable();
  delete consentPolicy(fromOnly, 'payments-payment-recurring-mandates-service').spec.rules[0].to;
  assert.ok(hasRule(r11(fromOnly), 'R11', 'consent-authorization-service without paths'), r11(fromOnly).join('\n'));

  // A selector-less ALLOW in open-finance also applies to consent-auth.
  const nsWide = deployable();
  nsWide.push({
    file: 'inline.yaml', index: 0,
    doc: {
      apiVersion: 'security.istio.io/v1', kind: 'AuthorizationPolicy', metadata: { name: 'ns-wide', namespace: 'open-finance' },
      spec: { action: 'ALLOW', rules: [{ from: [{ source: { principals: ['cluster.local/ns/payments/sa/payment-initiation-settlement-service'] } }], to: [{ operation: { ports: ['8080'] } }] }] },
    },
  });
  assert.ok(hasRule(r11(nsWide), 'R11', 'ns-wide'), r11(nsWide).join('\n'));
});

test('R11 rejects any ALLOW path pattern that covers /internal/* on any service', () => {
  for (const p of ['/internal/*', '/internal/v1/consents', '/internal', '/*', '*', '/int*', '*/consents', '/{*}/v1/x', '/{**}', '/internal/{**}']) {
    const docs = deployable();
    find(docs, 'AuthorizationPolicy', 'risk', 'allow-from-payments-payment-initiation-settlement-service-to-risk-decisioning-service')
      .doc.spec.rules[0].to[0].operation.paths = [p];
    assert.ok(hasRule(r11(docs), 'R11', `covers /internal/*`), `${p}: ${r11(docs).join('\n')}`);
  }
  for (const p of ['/api/v1/risk/*', '/internals', '/v1/internal/x', '/api/{*}/internal']) {
    const docs = deployable();
    find(docs, 'AuthorizationPolicy', 'risk', 'allow-from-payments-payment-initiation-settlement-service-to-risk-decisioning-service')
      .doc.spec.rules[0].to[0].operation.paths = [p];
    assert.deepEqual(r11(docs), [], p);
  }
  // An explicit /internal/* exclusion makes a broad pattern acceptable.
  const excluded = deployable();
  Object.assign(
    find(excluded, 'AuthorizationPolicy', 'risk', 'allow-from-payments-payment-initiation-settlement-service-to-risk-decisioning-service').doc.spec.rules[0].to[0].operation,
    { paths: ['/*'], notPaths: ['/internal/*'] },
  );
  assert.deepEqual(r11(excluded), []);
});

// ------------------------------------------------------------------ R12
// Customer and account identifiers never become metric labels, span tags or
// access-log fields through an Istio Telemetry resource (cardinality and PII).
const telemetry = (spec) =>
  parseDocs(YAML_TELEMETRY_HEADER + JSON.stringify(spec) + '\n', 'inline.yaml');
const YAML_TELEMETRY_HEADER = 'apiVersion: telemetry.istio.io/v1\nkind: Telemetry\nmetadata: {name: t, namespace: lending}\nspec: ';

test('R12 no Telemetry anywhere in the repo tags customer or account identifiers', () => {
  assert.deepEqual(checkTelemetryTags(all), []);
});

test('R12 rejects customer/account identifiers in metric tags, span tags and access-log filters', () => {
  const bad = [
    { metrics: [{ overrides: [{ tagOverrides: { banking_customer_id: { value: '%{DEPLOYMENT_NAME}' } } }] }] },
    { metrics: [{ overrides: [{ tagOverrides: { request_actor: { value: 'request.headers["x-customer-id"]' } } }] }] },
    { metrics: [{ overrides: [{ tagOverrides: { acct: { value: 'request.headers["x-account-number"]' } } }] }] },
    { tracing: [{ customTags: { customer_id: { header: { name: 'x-request-id' } } } }] },
    { tracing: [{ customTags: { owner: { header: { name: 'x-account-id' } } } }] },
    { tracing: [{ customTags: { payer: { literal: { value: 'iban' } } } }] },
    { accessLogging: [{ filter: { expression: 'request.headers["x-customer-id"] != ""' } }] },
  ];
  for (const spec of bad) {
    assert.ok(hasRule(checkTelemetryTags(telemetry(spec)), 'R12', 'Telemetry/lending/t'), JSON.stringify(spec));
  }
  const ok = [
    { metrics: [{ overrides: [{ tagOverrides: { source_service_account: { value: 'source.principal' } } }] }] },
    { tracing: [{ customTags: { cell: { environment: { name: 'CELL_ID' } } } }] },
  ];
  for (const spec of ok) assert.deepEqual(checkTelemetryTags(telemetry(spec)), [], JSON.stringify(spec));
});

test('contract: cross-namespace egress is per calling workload, not per namespace pair', () => {
  const docs = deployable();
  const nps = docs.filter((d) => d.doc.kind === 'NetworkPolicy').map((d) => d.doc);
  const np = (ns, name) => nps.find((d) => d.metadata.namespace === ns && d.metadata.name === name);
  const nsNames = new Set(contract.namespaces.map((n) => n.name));
  // No namespace-wide egress to another contract namespace.
  for (const d of nps) {
    const m = /^allow-egress-(?:.+-)?to-(.+)$/.exec(d.metadata.name);
    if (!m || !nsNames.has(m[1]) || m[1] === d.metadata.namespace) continue;
    assert.ok(Object.keys(d.spec.podSelector).length > 0, `${d.metadata.namespace}/${d.metadata.name} selects every pod`);
  }
  for (const ns of ['payments', 'lending', 'open-finance', 'istio-ingress']) {
    for (const t of contract.namespaces.map((n) => n.name)) assert.equal(np(ns, `allow-egress-to-${t}`), undefined, `${ns} -> ${t}`);
  }
  const callees = (d) => d.spec.egress.map((r) => [r.to.map((t) => t.podSelector.matchLabels['app.kubernetes.io/name']).join(','), r.ports.map((p) => p.port).join(',')]);
  const sel = (name) => ({ 'app.kubernetes.io/name': name });

  const bulk = np('payments', 'allow-egress-payment-bulk-orchestration-service-to-open-finance');
  assert.deepEqual(bulk.spec.podSelector, { matchLabels: sel('payment-bulk-orchestration-service') });
  assert.deepEqual(callees(bulk), [['consent-authorization-service', '8080']]);
  const mandates = np('payments', 'allow-egress-payment-recurring-mandates-service-to-open-finance');
  assert.deepEqual(callees(mandates), [['consent-authorization-service', '8080']]);
  const initiation = (t) => np('payments', `allow-egress-payment-initiation-settlement-service-to-${t}`);
  assert.deepEqual(callees(initiation('open-finance')), [['payee-verification-service', '8080']]);
  assert.deepEqual(callees(initiation('risk')), [['risk-decisioning-service', '8080']]);
  assert.deepEqual(callees(initiation('compliance')), [['compliance-evidence-service', '8080']]);
  assert.deepEqual(callees(initiation('customer')), [['customer-profile-kyc-service', '8080']]);
  // request-to-pay has no east-west edge, so no egress into another service namespace.
  for (const t of ['open-finance', 'customer', 'risk', 'compliance']) {
    assert.equal(np('payments', `allow-egress-payment-request-to-pay-service-to-${t}`), undefined, t);
  }
  const loan = np('lending', 'allow-egress-loan-lifecycle-service-to-customer');
  assert.deepEqual(loan.spec.podSelector, { matchLabels: sel('loan-lifecycle-service') });
  assert.deepEqual(callees(loan), [['customer-profile-kyc-service', '8080']]);
  // The callee side still admits only the calling workloads.
  const ingress = np('open-finance', 'allow-ingress-from-payments');
  assert.deepEqual(
    ingress.spec.ingress[0].from.map((f) => f.podSelector.matchLabels['app.kubernetes.io/name']).sort(),
    ['payment-bulk-orchestration-service', 'payment-initiation-settlement-service', 'payment-recurring-mandates-service'],
  );
});
