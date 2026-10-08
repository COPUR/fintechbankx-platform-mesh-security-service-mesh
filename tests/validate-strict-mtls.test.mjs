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
  parseDocs,
} from '../scripts/validation/validate-strict-mtls.mjs';
import { loadContract, expandEdges, knownServiceAccounts } from '../scripts/lib/contract.mjs';

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
    (d) => d.doc.kind === 'NetworkPolicy' && d.doc.metadata.namespace === 'payments' && /allow-egress-to-/.test(d.doc.metadata.name),
  );
  assert.deepEqual(paymentEgress.map((d) => d.doc.metadata.name).sort(), ['allow-egress-to-compliance', 'allow-egress-to-identity', 'allow-egress-to-observability', 'allow-egress-to-open-finance', 'allow-egress-to-risk']);
});

test('contract: east-west service edges are exactly the confirmed ones and scoped', () => {
  const svcNs = new Set(['lending', 'payments', 'customer', 'risk', 'compliance', 'open-finance']);
  const eastWest = expandEdges(contract).filter((e) => svcNs.has(e.from.ns) && svcNs.has(e.to.ns));
  assert.deepEqual([...new Set(eastWest.map((e) => `${e.from.ns}/${e.from.sa}->${e.to.ns}/${e.to.sa}`))].sort(), [
    'lending/loan-lifecycle-service->customer/customer-profile-kyc-service',
    'payments/payment-bulk-orchestration-service->open-finance/consent-authorization-service',
    'payments/payment-initiation-settlement-service->compliance/compliance-evidence-service',
    'payments/payment-initiation-settlement-service->open-finance/consent-authorization-service',
    'payments/payment-initiation-settlement-service->open-finance/payee-verification-service',
    'payments/payment-initiation-settlement-service->risk/risk-decisioning-service',
    'payments/payment-recurring-mandates-service->open-finance/consent-authorization-service',
    'payments/payment-request-to-pay-service->open-finance/consent-authorization-service',
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
  // Unconfirmed payment workloads get no datastore egress.
  for (const name of ['allow-egress-aurora', 'allow-egress-msk']) {
    assert.deepEqual(selected(np('payments', name)), ['payment-initiation-settlement-service']);
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
    'cluster.local/ns/payments/sa/payment-request-to-pay-service',
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
  assert.deepEqual(gwOps('customer', 'allow-from-istio-ingress-istio-ingressgateway-to-customer-profile-kyc-service')[0].notPaths, [
    '/api/v1/customers/{*}/credit/reserve',
    '/api/v1/customers/{*}/credit/release',
  ]);
  assert.deepEqual(gwOps('risk', 'allow-from-istio-ingress-istio-ingressgateway-to-risk-decisioning-service')[0].notPaths, ['/api/v1/risk/assess']);
  assert.deepEqual(gwOps('compliance', 'allow-from-istio-ingress-istio-ingressgateway-to-compliance-evidence-service')[0].notPaths, ['/api/v1/compliance/screen']);
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
  assert.deepEqual(
    api.spec.http.find((r) => r.name === 'svc-pay-request-to-pay').match.map((m) => m.uri.prefix),
    ['/open-finance/v1/par', '/open-finance/v1/payment-consents'],
  );
  const ef = docs.find((d) => d.doc.kind === 'EnvoyFilter' && d.doc.metadata.name === 'anonymous-open-data-rate-limit').doc;
  const limited = ef.spec.configPatches.filter((p) => p.applyTo === 'HTTP_ROUTE').map((p) => p.match.routeConfiguration.vhost.route.name);
  assert.deepEqual(limited, ['svc-of-open-products-catalog', 'svc-of-atm-directory', 'svc-of-banking-metadata']);
  const routeNames = new Set(api.spec.http.map((r) => r.name));
  for (const r of limited) assert.ok(routeNames.has(r), `rate-limited route ${r} exists on the gateway`);
  const bundle = docs.find((d) => d.doc.kind === 'Bundle' && d.doc.metadata.name === 'rds-ca-bundle').doc;
  assert.equal(bundle.spec.target.configMap.key, 'global-bundle.pem');
  assert.deepEqual(bundle.spec.sources, [{ configMap: { name: 'amazon-rds-ca-source', key: 'global-bundle.pem' } }]);
});
