// Mesh access log (meshConfig.accessLogFormat, JSON encoding): enough to
// trace and debug a request, nothing that identifies the client or leaks
// request data. Paths are logged without the query string (query parameters
// can carry identifiers and OAuth codes); the client address
// (x-forwarded-for, downstream remote address) and credentials are never
// logged.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot } from '../scripts/lib/contract.mjs';

const values = (p) => YAML.parse(readFileSync(join(repoRoot, 'deploy/istio/helm', p), 'utf8')) || {};
const mesh = values('istiod.values.yaml').meshConfig;

test('access log is JSON with the debugging and correlation fields', () => {
  assert.equal(mesh.accessLogFile, '/dev/stdout');
  assert.equal(mesh.accessLogEncoding, 'JSON');
  const fmt = JSON.parse(mesh.accessLogFormat);
  assert.equal(fmt.method, '%REQ(:METHOD)%');
  assert.equal(fmt.path, '%REQ_WITHOUT_QUERY(X-ENVOY-ORIGINAL-PATH?:PATH)%');
  assert.equal(fmt.response_code, '%RESPONSE_CODE%');
  assert.equal(fmt.response_flags, '%RESPONSE_FLAGS%');
  assert.equal(fmt.duration, '%DURATION%');
  assert.equal(fmt.upstream_cluster, '%UPSTREAM_CLUSTER%');
  assert.equal(fmt.x_request_id, '%REQ(X-REQUEST-ID)%');
  assert.equal(fmt.traceparent, '%REQ(TRACEPARENT)%');
  assert.equal(fmt.x_fapi_interaction_id, '%REQ(X-FAPI-INTERACTION-ID)%');
});

test('access log has no query string, client address or credentials', () => {
  const fmt = JSON.parse(mesh.accessLogFormat);
  const ops = Object.values(fmt).join(' ');
  // Every path operator strips the query.
  for (const m of ops.matchAll(/%(\w+)\(([^)]*)\)%/g)) {
    if (/PATH/i.test(m[2])) assert.equal(m[1], 'REQ_WITHOUT_QUERY', m[0]);
  }
  for (const banned of [
    'X-FORWARDED-FOR', 'DOWNSTREAM_REMOTE_ADDRESS', 'DOWNSTREAM_DIRECT_REMOTE_ADDRESS', 'DOWNSTREAM_REMOTE_PORT',
    'AUTHORIZATION', 'DPOP', 'COOKIE', 'USER-AGENT', 'X-ENVOY-EXTERNAL-ADDRESS', 'X-REAL-IP', 'FORWARDED',
  ]) {
    assert.ok(!ops.toUpperCase().includes(banned), `${banned} must not be logged`);
  }
  for (const env of ['dev', 'staging', 'prod']) {
    const o = values(`env/${env}/istiod.values.yaml`).meshConfig || {};
    for (const k of ['accessLogFormat', 'accessLogEncoding', 'accessLogFile']) assert.equal(o[k], undefined, `${env} overrides ${k}`);
  }
});
