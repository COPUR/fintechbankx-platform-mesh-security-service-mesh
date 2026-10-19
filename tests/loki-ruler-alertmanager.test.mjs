// Loki ruler -> Alertmanager (observability repo deploy/values/loki.yaml:
// ruler.alertmanager_url http://kube-prometheus-stack-alertmanager...:9093,
// ruler runs in the SimpleScalable backend pods; chart loki 6.16.0 / Loki
// 3.1.1, service account loki shared by every Loki component).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';

const files = render(loadContract());
const LOKI = 'cluster.local/ns/observability/sa/loki';

test('Alertmanager admits POST /api/v2/alerts on 9093 from the loki principal', () => {
  const p = files['authorization-policies.yaml'].find(
    (d) => d.metadata.namespace === 'observability' && d.metadata.name === 'allow-from-observability-loki-to-alertmanager',
  );
  assert.ok(p, 'AuthorizationPolicy allow-from-observability-loki-to-alertmanager missing');
  assert.deepEqual(p.spec.selector.matchLabels, { 'app.kubernetes.io/name': 'alertmanager' });
  assert.deepEqual(p.spec.rules, [
    { from: [{ source: { principals: [LOKI] } }], to: [{ operation: { ports: ['9093'], methods: ['POST'], paths: ['/api/v2/alerts'] } }] },
  ]);
});

test('only the backend pods (the ruler) get the NetworkPolicy path to Alertmanager 9093', () => {
  const np = files['network-policies.yaml'];
  const egress = np.find((d) => d.metadata.namespace === 'observability' && d.metadata.name === 'allow-egress-loki-backend-to-alertmanager-9093');
  assert.ok(egress, 'egress NetworkPolicy missing');
  assert.deepEqual(egress.spec.podSelector.matchLabels, { 'app.kubernetes.io/name': 'loki', 'app.kubernetes.io/component': 'backend' });
  assert.deepEqual(egress.spec.egress, [{ to: [{ podSelector: { matchLabels: { 'app.kubernetes.io/name': 'alertmanager' } } }], ports: [{ protocol: 'TCP', port: 9093 }] }]);
  const ingress = np.find((d) => d.metadata.namespace === 'observability' && d.metadata.name === 'allow-ingress-loki-backend-to-alertmanager-9093');
  assert.deepEqual(ingress.spec.ingress, [{ from: [{ podSelector: { matchLabels: { 'app.kubernetes.io/name': 'loki', 'app.kubernetes.io/component': 'backend' } } }], ports: [{ protocol: 'TCP', port: 9093 }] }]);
});
