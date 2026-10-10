// Request-to-pay cut-over at the ingress gateway (RUNBOOK-EXTRACT-pay-request-to-pay,
// request-to-pay PR #14 d6049d7, section 3). Rules evaluated in this order,
// anchored, no prefix routes:
//   R1 GET  /open-finance/v1/payment-consents/CONS-RTP2-<36>            -> request-to-pay, always
//      POST /open-finance/v1/payment-consents/CONS-RTP2-<36>/(accept|reject)
//   R2 the same three operations with any other id                      -> monolith
//   R3 POST /open-finance/v1/par, token azp in rtp-cutover-cohort         -> request-to-pay
//   R4 POST /open-finance/v1/par                                          -> monolith
// Phases move only R3's cohort. Nothing else on these paths is routed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const contract = loadContract();
const RTP = 'payment-request-to-pay-service.payments.svc.cluster.local';
const LEGACY = 'LEGACY_OPEN_FINANCE_HOST';
const ID2 = 'CONS-RTP2-3f2b8c1e-9d4a-4c6b-8e2f-0a1b2c3d4e5f';
const ID1 = 'CONS-RTP-3f2b8c1e-9d4a-4c6b-8e2f-0a1b2c3d4e5f';

const withCohort = (clients) => {
  const c = structuredClone(contract);
  c.gateway.cutovers.find((x) => x.name === 'rtp-cutover').cohort.clients = clients;
  return c;
};
const apiRoutes = (c = contract) =>
  render(c)['ingress-routing.yaml'].find((d) => d.kind === 'VirtualService' && d.metadata.name === 'fintechbankx-api').spec.http;

// Envoy route selection for the match forms the renderer uses: first route
// whose any match entry matches. uri exact/prefix/regex (RE2 full match on the
// path without query string), method exact, @request.auth.claims.<c> exact
// (claims of a token the gateway RequestAuthentication validated).
function stringMatch(m, v) {
  if (v === undefined) return false;
  if ('exact' in m) return m.exact === v;
  if ('prefix' in m) return v.startsWith(m.prefix);
  if ('regex' in m) return new RegExp(`^(?:${m.regex})$`).test(v);
  throw new Error(`unsupported match ${JSON.stringify(m)}`);
}
function route(routes, method, rawPath, claims = {}) {
  const path = rawPath.split('?')[0];
  for (const r of routes) {
    const hit = (r.match || [{}]).some((m) => {
      if (m.uri && !stringMatch(m.uri, path)) return false;
      if (m.method && !stringMatch(m.method, method)) return false;
      for (const [h, hm] of Object.entries(m.headers || {})) {
        const claim = h.startsWith('@request.auth.claims.') ? claims[h.slice('@request.auth.claims.'.length)] : undefined;
        if (!stringMatch(hm, claim)) return false;
      }
      return true;
    });
    if (hit) return { name: r.name, host: r.route[0].destination.host, headers: r.headers };
  }
  return null;
}

test('R1: follow-ups for CONS-RTP2- ids always reach request-to-pay, whoever calls', () => {
  for (const routes of [apiRoutes(), apiRoutes(withCohort(['tpp-pilot']))]) {
    for (const claims of [{}, { azp: 'tpp-pilot' }, { azp: 'tpp-other' }]) {
      assert.equal(route(routes, 'GET', `/open-finance/v1/payment-consents/${ID2}`, claims)?.host, RTP);
      assert.equal(route(routes, 'POST', `/open-finance/v1/payment-consents/${ID2}/accept`, claims)?.host, RTP);
      assert.equal(route(routes, 'POST', `/open-finance/v1/payment-consents/${ID2}/reject`, claims)?.host, RTP);
      assert.equal(route(routes, 'GET', `/open-finance/v1/payment-consents/${ID2}?x=1`, claims)?.host, RTP, 'query string is not part of the match');
    }
  }
});

test('R2: follow-ups for any other id reach the monolith', () => {
  const routes = apiRoutes(withCohort(['tpp-pilot']));
  for (const claims of [{}, { azp: 'tpp-pilot' }]) {
    assert.equal(route(routes, 'GET', `/open-finance/v1/payment-consents/${ID1}`, claims)?.host, LEGACY);
    assert.equal(route(routes, 'POST', `/open-finance/v1/payment-consents/${ID1}/accept`, claims)?.host, LEGACY);
    assert.equal(route(routes, 'POST', `/open-finance/v1/payment-consents/${ID1}/reject`, claims)?.host, LEGACY);
    // A malformed RtP2 id is not ours: upper-case hex, short uuid.
    assert.equal(route(routes, 'GET', `/open-finance/v1/payment-consents/${ID2.toUpperCase()}`, claims)?.host, LEGACY);
    assert.equal(route(routes, 'GET', '/open-finance/v1/payment-consents/CONS-RTP2-123', claims)?.host, LEGACY);
  }
});

test('R3/R4: creates go to request-to-pay only for a TPP in rtp-cutover-cohort', () => {
  const routes = apiRoutes(withCohort(['tpp-pilot', 'tpp-batch-1']));
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', { azp: 'tpp-pilot' })?.host, RTP);
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', { azp: 'tpp-batch-1' })?.host, RTP);
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', { azp: 'tpp-other' })?.host, LEGACY);
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', { azp: 'tpp-pilot-2' })?.host, LEGACY, 'exact client id, no prefix');
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', {})?.host, LEGACY, 'no validated token: monolith');
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', { client_id: 'tpp-pilot' })?.host, LEGACY, 'the cohort is keyed on azp');
});

test('step 2: the committed cohort is empty, so every create stays on the monolith and R3 is not rendered', () => {
  const cut = contract.gateway.cutovers.find((x) => x.name === 'rtp-cutover');
  assert.equal(cut.cohort.name, 'rtp-cutover-cohort');
  assert.deepEqual(cut.cohort.clients, []);
  const routes = apiRoutes();
  assert.ok(!routes.some((r) => r.name === 'rtp-cutover-r3'), 'an Istio route with no match entries matches every request');
  for (const r of routes) assert.ok(Array.isArray(r.match) && r.match.length > 0, `${r.name} must have match entries`);
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', { azp: 'tpp-pilot' })?.host, LEGACY);
});

test('nothing else on the request-to-pay paths is routed (no prefix routes)', () => {
  const routes = apiRoutes(withCohort(['tpp-pilot']));
  for (const [m, p] of [
    ['GET', '/open-finance/v1/par'],
    ['POST', '/open-finance/v1/par/'],
    ['POST', '/open-finance/v1/par/x'],
    ['GET', '/open-finance/v1/payment-consents'],
    ['POST', '/open-finance/v1/payment-consents'],
    ['DELETE', `/open-finance/v1/payment-consents/${ID2}`],
    ['POST', `/open-finance/v1/payment-consents/${ID2}`],
    ['GET', `/open-finance/v1/payment-consents/${ID2}/accept`],
    ['POST', `/open-finance/v1/payment-consents/${ID2}/accept/`],
    ['POST', `/open-finance/v1/payment-consents/${ID2}/cancel`],
    ['POST', `/open-finance/v1/payment-consents/${ID2}/accept/x`],
    ['GET', `/open-finance/v1/payment-consents/${ID1}/x`],
  ]) {
    assert.equal(route(routes, m, p, { azp: 'tpp-pilot' }), null, `${m} ${p} must not be routed`);
  }
  for (const r of routes) {
    if (r.route[0].destination.host !== RTP) continue;
    for (const m of r.match) assert.ok(!m.uri.prefix, `${r.name}: request-to-pay is never routed by prefix`);
  }
  // The sibling VRP consent API keeps its own prefix route.
  assert.equal(route(routes, 'GET', '/open-finance/v1/vrp/payment-consents/x')?.host, 'payment-recurring-mandates-service.payments.svc.cluster.local');
});

test('rules are evaluated R1, R2, R3, R4, before every other API route', () => {
  const names = apiRoutes(withCohort(['tpp-pilot'])).map((r) => r.name);
  assert.deepEqual(names.slice(0, 4), ['rtp-cutover-r1', 'rtp-cutover-r2', 'rtp-cutover-r3', 'rtp-cutover-r4']);
});

test('every cut-over route overwrites the forwarded headers (DPoP htu origin)', () => {
  for (const r of apiRoutes(withCohort(['tpp-pilot'])).filter((x) => x.name.startsWith('rtp-cutover-'))) {
    assert.deepEqual(r.headers.request.set, { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'API_HOST', 'x-forwarded-port': '443' }, r.name);
    assert.deepEqual(r.headers.request.remove, ['forwarded', 'x-forwarded-prefix'], r.name);
  }
});

test('the gateway validates DPoP-scheme tokens too, so R3 can read azp', () => {
  const gw = render(contract)['request-authentication.yaml'].find((d) => d.metadata.namespace === 'istio-ingress');
  const [rule] = gw.spec.jwtRules;
  assert.deepEqual(rule.fromHeaders, [
    { name: 'Authorization', prefix: 'Bearer ' },
    { name: 'Authorization', prefix: 'DPoP ' },
  ]);
  assert.equal(rule.fromParams, undefined, 'no query-parameter token: R3 must not route on a token from the URL');
  assert.equal(rule.fromCookies, undefined);
  assert.ok(rule.fromHeaders.length > 0, 'with no explicit location Istio falls back to its defaults, query access_token included');
  assert.equal(rule.forwardOriginalToken, true, 'the service checks the DPoP binding itself');
  assert.equal(rule.audiences, undefined, 'the gateway checks the issuer only');
});

// Token extraction at the gateway (Istio RequestAuthentication -> Envoy
// jwt_authn): only the configured locations are read; with none configured
// Istio uses its defaults (Authorization "Bearer ", query access_token). A
// token found nowhere is a missing token (allowed, no request.auth claims).
// Tokens are modelled as their already-validated claims.
function gatewayClaims(c, { headers = {}, query = {} }) {
  const gw = render(c)['request-authentication.yaml'].find((d) => d.metadata.namespace === 'istio-ingress');
  const [rule] = gw.spec.jwtRules;
  const explicit = rule.fromHeaders || rule.fromParams || rule.fromCookies;
  const fromHeaders = explicit ? rule.fromHeaders || [] : [{ name: 'Authorization', prefix: 'Bearer ' }];
  const fromParams = explicit ? rule.fromParams || [] : ['access_token'];
  for (const h of fromHeaders) {
    const v = headers[h.name];
    if (v && v.scheme === h.prefix) return v.claims;
  }
  for (const q of fromParams) if (query[q]) return query[q];
  return {};
}

test('R3: a token in the access_token query parameter is not validated, so it never selects the cohort route', () => {
  const c = withCohort(['tpp-pilot']);
  const routes = apiRoutes(c);
  const pilot = { azp: 'tpp-pilot' };
  const viaQuery = gatewayClaims(c, { query: { access_token: pilot } });
  assert.equal(route(routes, 'POST', '/open-finance/v1/par?access_token=x', viaQuery)?.host, LEGACY, 'query token: R4, monolith');
  // Control: the same token in the Authorization header reaches R3.
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', gatewayClaims(c, { headers: { Authorization: { scheme: 'DPoP ', claims: pilot } } }))?.host, RTP);
  assert.equal(route(routes, 'POST', '/open-finance/v1/par', gatewayClaims(c, { headers: { Authorization: { scheme: 'Bearer ', claims: pilot } } }))?.host, RTP);
});

test('a cohort rule refuses gateway token locations that read the URL or fall back to Istio defaults', () => {
  for (const locations of [
    { ...contract.gateway.tokenLocations, fromParams: ['access_token'] },
    { ...contract.gateway.tokenLocations, fromCookies: ['token'] },
    {},
    undefined,
  ]) {
    const c = withCohort(['tpp-pilot']);
    c.gateway.tokenLocations = locations;
    assert.throws(() => render(c), /tokenLocations/, JSON.stringify(locations));
    // An empty cohort renders no R3, so nothing routes on claims yet.
    const empty = structuredClone(contract);
    empty.gateway.tokenLocations = locations;
    assert.doesNotThrow(() => render(empty));
  }
});

test('cohort entries are literal client ids: no wildcard, no regex, no service or channel client', () => {
  for (const bad of ['*', 'tpp-*', 'tpp.+', '', 'svc-pay-request-to-pay', 'fintechbankx-web']) {
    assert.throws(() => render(withCohort([bad])), /rtp-cutover-cohort/, JSON.stringify(bad));
  }
});

test('the monolith backend is one explicit host, TLS-originated, visible to the gateway only', () => {
  const files = render(contract);
  const se = files['service-entries.yaml'].find((d) => d.metadata.name === 'legacy-open-finance');
  assert.equal(se.metadata.namespace, 'istio-ingress');
  assert.deepEqual(se.spec.exportTo, ['.']);
  assert.deepEqual(se.spec.hosts, [LEGACY]);
  assert.equal(se.spec.location, 'MESH_EXTERNAL');
  assert.equal(se.spec.resolution, 'DNS');
  assert.deepEqual(se.spec.ports, [{ number: 80, name: 'http-legacy', protocol: 'HTTP', targetPort: 443 }]);
  const dr = files['destination-rules.yaml'].find((d) => d.metadata.name === 'legacy-open-finance');
  assert.equal(dr.metadata.namespace, 'istio-ingress');
  assert.deepEqual(dr.spec.exportTo, ['.']);
  assert.equal(dr.spec.host, LEGACY);
  const tls = dr.spec.trafficPolicy.portLevelSettings[0];
  assert.equal(tls.port.number, 80);
  assert.equal(tls.tls.mode, 'SIMPLE');
  assert.equal(tls.tls.sni, LEGACY);
  assert.deepEqual(tls.tls.subjectAltNames, [LEGACY]);
});

// Authorization at the request-to-pay sidecar (defence in depth behind the
// routes): only the ingress gateway, only the four operations, port 8080.
function pathMatches(pattern, path) {
  if (pattern.includes('{')) {
    const re = pattern.split('/').map((seg) => (seg === '{*}' ? '[^/]+' : seg === '{**}' ? '.*' : seg.replace(/[.+?^$()[\]\\|]/g, '\\$&'))).join('/');
    return new RegExp(`^${re}$`).test(path);
  }
  if (pattern.endsWith('*')) return path.startsWith(pattern.slice(0, -1));
  return pattern === path;
}
const rtpPolicies = () => render(contract)['authorization-policies.yaml'].filter(
  (p) => p.metadata.namespace === 'payments' && p.spec.action === 'ALLOW' && p.spec.selector?.matchLabels?.['app.kubernetes.io/name'] === 'payment-request-to-pay-service',
);
const allowed = (principal, port, method, path) => rtpPolicies().some((p) => p.spec.rules.some((r) =>
  r.from.some((f) => f.source.principals.includes(principal)) &&
  r.to.some(({ operation: op }) => op.ports.includes(String(port)) && (!op.methods || op.methods.includes(method)) && (!op.paths || op.paths.some((x) => pathMatches(x, path))))));
const GW = 'cluster.local/ns/istio-ingress/sa/istio-ingressgateway';

test('gateway -> request-to-pay: exactly the four operations, method by method', () => {
  assert.ok(allowed(GW, 8080, 'POST', '/open-finance/v1/par'));
  assert.ok(allowed(GW, 8080, 'GET', `/open-finance/v1/payment-consents/${ID2}`));
  assert.ok(allowed(GW, 8080, 'POST', `/open-finance/v1/payment-consents/${ID2}/accept`));
  assert.ok(allowed(GW, 8080, 'POST', `/open-finance/v1/payment-consents/${ID2}/reject`));
  for (const [m, p] of [
    ['GET', '/open-finance/v1/par'],
    ['DELETE', `/open-finance/v1/payment-consents/${ID2}`],
    ['POST', `/open-finance/v1/payment-consents/${ID2}`],
    ['GET', `/open-finance/v1/payment-consents/${ID2}/accept`],
    ['POST', `/open-finance/v1/payment-consents/${ID2}/cancel`],
    ['GET', '/open-finance/v1/payment-consents'],
    ['GET', '/actuator/prometheus'],
  ]) assert.ok(!allowed(GW, 8080, m, p), `${m} ${p}`);
  assert.ok(!allowed(GW, 8081, 'GET', '/actuator/health'), 'the management port is never public');
});

test('forwarded-header origin: on 8080 only the gateway principal reaches request-to-pay', () => {
  const principals = new Set();
  for (const p of rtpPolicies()) for (const r of p.spec.rules) {
    if (r.to.some(({ operation: op }) => !op.ports || op.ports.includes('8080'))) for (const f of r.from) f.source.principals.forEach((x) => principals.add(x));
  }
  assert.deepEqual([...principals], [GW]);
  // No selector-less ALLOW in payments opens 8080 to anyone else.
  const nsWide = render(contract)['authorization-policies.yaml'].filter((p) => p.metadata.namespace === 'payments' && p.spec.action === 'ALLOW' && !p.spec.selector);
  for (const p of nsWide) for (const r of p.spec.rules) for (const t of r.to) assert.ok(!(t.operation.ports || []).includes('8080'), p.metadata.name);
});
