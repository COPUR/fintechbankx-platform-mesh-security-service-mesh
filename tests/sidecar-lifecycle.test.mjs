// Pod shutdown and client addresses at the edge (request-to-pay PR #14 review).
//  - Native sidecars (Kubernetes 1.29+ restartable init containers; EKS runs
//    1.31): the proxy outlives the application container, so a service's
//    graceful shutdown (outbox relay sends to MSK through the sidecar,
//    in-flight requests) is not cut off by the default 5 s Envoy drain.
//  - The gateway trusts no proxy in front of it (numTrustedProxies 0): the NLB
//    passes no client address (no proxy protocol, preserve_client_ip off), so
//    any X-Forwarded-For a client sends must not be treated as trusted hops.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot } from '../scripts/lib/contract.mjs';

const values = (p) => YAML.parse(readFileSync(join(repoRoot, 'deploy/istio/helm', p), 'utf8')) || {};

test('istiod injects native sidecars in every environment', () => {
  assert.equal(values('istiod.values.yaml').env?.ENABLE_NATIVE_SIDECARS, 'true');
  for (const env of ['dev', 'staging', 'prod']) {
    const o = values(`env/${env}/istiod.values.yaml`);
    assert.notEqual(o.env?.ENABLE_NATIVE_SIDECARS, 'false', env);
  }
});

test('the gateway pins numTrustedProxies 0', () => {
  const cfg = JSON.parse(values('gateway.values.yaml').podAnnotations['proxy.istio.io/config']);
  assert.deepEqual(cfg.gatewayTopology, { numTrustedProxies: 0 });
  for (const env of ['dev', 'staging', 'prod']) {
    assert.equal(values(`env/${env}/gateway.values.yaml`).podAnnotations?.['proxy.istio.io/config'], undefined, `${env} must not override it`);
  }
});
