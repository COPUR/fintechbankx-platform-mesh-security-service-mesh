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

// With native sidecars a Job completes inside the mesh (db-migration Jobs,
// keycloak-realm-import), so "a sidecar keeps a Job from completing" is never
// a valid reason to run a workload without one. A sidecar-less workload's
// exception must say why it is actually needed, or that it is the owner's
// choice pending review.
const JOB_COMPLETION_CLAIM =
  /\bjobs?\b[^.;]*\b(never (finish|complete)|from (finishing|completing))\b|\b(keeps?|stops?|prevents?|blocks?)\b[^.;]*\bjobs?\b[^.;]*\b(finish|complet)/i;

test('no sidecar exception rests on Jobs not completing with a sidecar', () => {
  const contract = YAML.parse(readFileSync(join(repoRoot, 'contracts/mesh-contract.yaml'), 'utf8'));
  const reasons = [...(contract.exceptions.injection || []), ...(contract.exceptions.workloadInjection || [])];
  for (const x of reasons) {
    assert.doesNotMatch(x.reason, JOB_COMPLETION_CLAIM, x.namespace || x.workload);
  }
  const doc = readFileSync(join(repoRoot, 'docs/mesh/DEPLOYABLE_MESH_BASELINE.md'), 'utf8');
  for (const line of doc.split(/\n\s*\n/)) {
    assert.doesNotMatch(line.replace(/\s+/g, ' '), JOB_COMPLETION_CLAIM, line.slice(0, 120));
  }
});
