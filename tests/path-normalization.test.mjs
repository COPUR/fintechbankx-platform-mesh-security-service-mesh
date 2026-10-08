// Path normalization and the gateway's notPaths exclusions.
//
// The gateway ALLOW rules exclude service-only operations with notPaths
// (customer credit reserve/release, risk assess, compliance screen). An
// exclusion is only as good as the path Envoy compares it with:
//  - "//" variants (/api/v1/risk//assess) are collapsed by
//    meshConfig.pathNormalization MERGE_SLASHES before routing and before the
//    RBAC filter evaluates AuthorizationPolicy, so they hit the exclusion.
//  - Trailing-slash and sub-path variants (/api/v1/risk/assess/) are NOT
//    rewritten by any Istio normalization mode, so the renderer adds a
//    companion exclusion for each notPath: "<path>/*" for a literal path,
//    "<template>/" and "<template>/{**}" for a path template.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const istiod = YAML.parse(readFileSync(join(repoRoot, 'deploy/istio/helm/istiod.values.yaml'), 'utf8'));
const contract = loadContract();

test('istiod merges duplicate slashes before AuthorizationPolicy evaluation', () => {
  assert.deepEqual(istiod.meshConfig.pathNormalization, { normalization: 'MERGE_SLASHES' });
  for (const env of ['dev', 'staging', 'prod']) {
    const o = YAML.parse(readFileSync(join(repoRoot, `deploy/istio/helm/env/${env}/istiod.values.yaml`), 'utf8')) || {};
    assert.equal(o.meshConfig?.pathNormalization, undefined, `${env} must not override pathNormalization`);
  }
});

const gatewayRules = () =>
  render(contract)['authorization-policies.yaml']
    .filter((p) => p.spec?.action === 'ALLOW' && /^allow-from-istio-ingress-istio-ingressgateway-to-/.test(p.metadata.name))
    .flatMap((p) => p.spec.rules.map((r) => ({ policy: `${p.metadata.namespace}/${p.metadata.name}`, op: r.to[0].operation })));

test('every gateway notPath also excludes its trailing-slash and sub-path variants', () => {
  const withNotPaths = gatewayRules().filter((r) => r.op.notPaths);
  assert.ok(withNotPaths.length >= 3, 'customer, risk and compliance carry exclusions');
  for (const { policy, op } of withNotPaths) {
    const base = op.notPaths.filter((p) => !p.endsWith('/') && !p.endsWith('/*') && !p.endsWith('/{**}'));
    assert.ok(base.length > 0, policy);
    for (const p of base) {
      const companions = p.includes('{') ? [`${p}/`, `${p}/{**}`] : [`${p}/*`];
      for (const c of companions) assert.ok(op.notPaths.includes(c), `${policy}: ${p} needs companion ${c}`);
    }
  }
});

test('risk assess and compliance screen stay excluded in every slash variant', () => {
  const ops = Object.fromEntries(gatewayRules().map((r) => [r.policy.split('/')[0], r.op]));
  assert.deepEqual(ops.risk.notPaths, ['/api/v1/risk/assess', '/api/v1/risk/assess/*']);
  assert.deepEqual(ops.compliance.notPaths, ['/api/v1/compliance/screen', '/api/v1/compliance/screen/*']);
});
