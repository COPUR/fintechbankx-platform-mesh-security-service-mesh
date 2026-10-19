// Every RequestAuthentication (gateway and workloads) names its token
// locations explicitly, headers only. With no location Istio falls back to
// its defaults, which include the query parameter access_token: a token in
// the URL leaks into access logs and caches (review 5478494656).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseAllDocuments } from 'yaml';
import { loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const GENERATED = new URL('../deploy/kustomize/base/generated/request-authentication.yaml', import.meta.url);

const headerOnly = (doc) => {
  const where = `${doc.metadata.namespace}/${doc.metadata.name}`;
  assert.ok(doc.spec.jwtRules.length > 0, `${where}: no jwtRules`);
  for (const rule of doc.spec.jwtRules) {
    assert.ok(Array.isArray(rule.fromHeaders) && rule.fromHeaders.length > 0, `${where}: no explicit fromHeaders (Istio defaults include ?access_token)`);
    assert.equal(rule.fromParams, undefined, `${where}: fromParams accepts tokens from the URL`);
    assert.equal(rule.fromCookies, undefined, `${where}: fromCookies`);
    for (const h of rule.fromHeaders) assert.equal(h.name, 'Authorization', `${where}: unexpected token header ${h.name}`);
  }
};

test('committed RequestAuthentications read tokens from Authorization headers only', () => {
  const docs = parseAllDocuments(readFileSync(GENERATED, 'utf8')).map((d) => d.toJS()).filter(Boolean);
  const ras = docs.filter((d) => d.kind === 'RequestAuthentication');
  assert.ok(ras.length > 1, 'gateway and workload RequestAuthentications rendered');
  ras.forEach(headerOnly);
});

test('rendered workload RequestAuthentications use the contract token locations', () => {
  const contract = loadContract();
  const ras = render(contract)['request-authentication.yaml'].filter((d) => d.kind === 'RequestAuthentication');
  const workloads = ras.filter((d) => d.metadata.namespace !== contract.gateway.namespace);
  assert.ok(workloads.length > 0);
  for (const d of workloads) {
    assert.deepEqual(d.spec.jwtRules[0].fromHeaders, contract.gateway.tokenLocations.fromHeaders, `${d.metadata.namespace}/${d.metadata.name}`);
  }
  ras.forEach(headerOnly);
});

test('renderer refuses query-parameter or implicit token locations', () => {
  const withParams = structuredClone(loadContract());
  withParams.gateway.tokenLocations.fromParams = ['access_token'];
  assert.throws(() => render(withParams), /tokenLocations/);
  const implicit = structuredClone(loadContract());
  delete implicit.gateway.tokenLocations;
  assert.throws(() => render(implicit), /tokenLocations/);
});
