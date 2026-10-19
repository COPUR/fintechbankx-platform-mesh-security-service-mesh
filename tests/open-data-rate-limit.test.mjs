// Anonymous open-data rate limit (EnvoyFilter anonymous-open-data-rate-limit).
//
// The bucket is per gateway pod and per route, shared by every client: Envoy's
// local rate limit in Istio 1.24.3 (Envoy 1.32) has no per-value (dynamic)
// descriptors (max_dynamic_descriptors is an unknown field to istioctl
// 1.24.3), and the NLB does not pass the client address to the gateway
// (preserve_client_ip.enabled=false, no proxy protocol). The effective
// cluster-wide limit is therefore the per-pod rate x the gateway replica
// count, which the filter documents per environment.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const contract = loadContract();
const values = (p) => YAML.parse(readFileSync(join(repoRoot, 'deploy/istio/helm', p), 'utf8')) || {};
const filter = () => render(contract)['ingress-routing.yaml'].find((d) => d.kind === 'EnvoyFilter' && d.metadata.name === 'anonymous-open-data-rate-limit');

function replicaRange(env) {
  const base = values('gateway.values.yaml').autoscaling;
  const o = values(`env/${env}/gateway.values.yaml`).autoscaling || {};
  return [o.minReplicas ?? base.minReplicas, o.maxReplicas ?? base.maxReplicas];
}

test('the documented gateway replica ranges match the Helm values', () => {
  const rl = contract.gateway.anonymousRateLimit;
  for (const env of ['dev', 'staging', 'prod']) assert.deepEqual(rl.gatewayReplicas[env], replicaRange(env), env);
});

test('the filter documents its effective limit as per-pod rate x gateway replicas', () => {
  const rl = contract.gateway.anonymousRateLimit;
  const ann = filter().metadata.annotations['fintechbankx.io/effective-limit'];
  const perPod = rl.tokensPerFill; // per fillInterval (1s)
  assert.equal(rl.fillInterval, '1s');
  assert.match(ann, new RegExp(`^per gateway pod and route, shared by all clients: ${perPod} req/s, burst ${rl.maxTokens}; `));
  for (const env of ['dev', 'staging', 'prod']) {
    const [min, max] = replicaRange(env);
    assert.ok(ann.includes(`${env} ${min}-${max} pods = ${perPod * min}-${perPod * max} req/s`), `${env}: ${ann}`);
  }
});

test('the per-route buckets stay shared (no per-client descriptors on Envoy 1.32)', () => {
  for (const p of filter().spec.configPatches.filter((x) => x.applyTo === 'HTTP_ROUTE')) {
    const cfg = p.patch.value.typed_per_filter_config['envoy.filters.http.local_ratelimit'];
    assert.equal(cfg.descriptors, undefined);
    assert.equal(cfg.max_dynamic_descriptors, undefined);
    assert.deepEqual(cfg.token_bucket, { max_tokens: 100, tokens_per_fill: 50, fill_interval: '1s' });
  }
});
