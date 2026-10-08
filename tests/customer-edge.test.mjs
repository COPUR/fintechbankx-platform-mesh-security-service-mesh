// Gateway -> customer-profile-kyc-service (customer thread and identity
// review 2026-10-08).
//  - GET /api/v1/customers/{id}/credit is public (CUSTOMER self-read, BANKER,
//    ADMIN); every other method on /credit, and POST credit/reserve|release
//    (loan-lifecycle only), stay off the gateway.
//  - Only first-party clients reach the customer API from the edge:
//    request.auth.claims[azp] in fintechbankx-web, fintechbankx-mobile
//    (customers) and fintechbankx-staff-web (staff).
//  - request.auth comes from the RequestAuthentication of the workload that
//    evaluates the rule, i.e. the customer sidecar's keycloak-jwt-customer-
//    profile-kyc-service (aud svc-cus-profile-kyc); the gateway validates the
//    same token first and forwards it (forwardOriginalToken).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const contract = loadContract();
const AZP = { key: 'request.auth.claims[azp]', values: ['fintechbankx-web', 'fintechbankx-mobile', 'fintechbankx-staff-web'] };
const POLICY = 'allow-from-istio-ingress-istio-ingressgateway-to-customer-profile-kyc-service';
const files = render(contract);
const gatewayToCustomer = () => files['authorization-policies.yaml'].find((p) => p.metadata.namespace === 'customer' && p.metadata.name === POLICY);

// Minimal Istio matcher for the path forms used here: exact, "*" suffix
// (prefix match), and templates with {*} (one segment) / {**} (rest, >= 0
// segments). Enough to show which (method, path) pairs a rule admits.
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
const opAllows = (op, method, path) =>
  (!op.methods || op.methods.includes(method)) &&
  (!op.paths || op.paths.some((p) => pathMatches(p, path))) &&
  !(op.notPaths || []).some((p) => pathMatches(p, path));
const gatewayAllows = (method, path) => gatewayToCustomer().spec.rules.some((r) => r.to.some((t) => opAllows(t.operation, method, path)));

test('gateway: GET /credit only; reserve, release and other /credit methods stay off the edge', () => {
  assert.ok(gatewayAllows('GET', '/api/v1/customers/c-1/credit'));
  assert.ok(gatewayAllows('GET', '/api/v1/customers/c-1/kyc-status'));
  assert.ok(gatewayAllows('POST', '/api/v1/customers'));
  assert.ok(gatewayAllows('PUT', '/api/v1/customers/c-1/identity-link'));
  for (const [m, p] of [
    ['POST', '/api/v1/customers/c-1/credit'],
    ['PUT', '/api/v1/customers/c-1/credit'],
    ['DELETE', '/api/v1/customers/c-1/credit'],
    ['GET', '/api/v1/customers/c-1/credit/'],
    ['POST', '/api/v1/customers/c-1/credit/reserve'],
    ['POST', '/api/v1/customers/c-1/credit/release'],
    ['POST', '/api/v1/customers/c-1/credit/reserve/'],
    ['GET', '/api/v1/customers/c-1/credit/reserve'],
  ]) {
    assert.ok(!gatewayAllows(m, p), `${m} ${p} must not be allowed from the gateway`);
  }
});

test('gateway: every rule into the customer service requires a first-party azp', () => {
  const rules = gatewayToCustomer().spec.rules;
  assert.equal(rules.length, 2);
  for (const r of rules) assert.deepEqual(r.when, [AZP]);
  // The loan-lifecycle rules (service token, azp svc-ln-loan-lifecycle) carry no azp condition.
  const loan = files['authorization-policies.yaml'].find(
    (p) => p.metadata.namespace === 'customer' && p.metadata.name === 'allow-from-lending-loan-lifecycle-service-to-customer-profile-kyc-service',
  );
  for (const r of loan.spec.rules) assert.equal(r.when, undefined);
});

test('request.auth for the azp condition comes from the customer workload RequestAuthentication', () => {
  const ras = files['request-authentication.yaml'];
  const customer = ras.find((r) => r.metadata.namespace === 'customer' && r.metadata.name === 'keycloak-jwt-customer-profile-kyc-service');
  assert.deepEqual(customer.spec.selector.matchLabels, { 'app.kubernetes.io/name': 'customer-profile-kyc-service' });
  assert.deepEqual(customer.spec.jwtRules[0].audiences, ['svc-cus-profile-kyc']);
  const gw = ras.find((r) => r.metadata.namespace === 'istio-ingress');
  assert.equal(gw.spec.jwtRules[0].forwardOriginalToken, true, 'the gateway forwards the token to the customer sidecar');
  assert.equal(gw.spec.jwtRules[0].issuer, customer.spec.jwtRules[0].issuer);
});

test('renderer: a request.auth condition needs a RequestAuthentication on the callee', () => {
  const c = structuredClone(contract);
  c.edges.push({
    from: 'istio-ingress/istio-ingressgateway',
    to: 'open-finance/atm-directory-service',
    port: 8080,
    paths: ['/x'],
    when: [AZP],
  });
  assert.throws(() => render(c), /open-finance\/atm-directory-service: request\.auth\.claims\[azp\] \(request\.auth\) needs a RequestAuthentication/);
});
