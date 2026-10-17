// Workload admission in kind: service namespaces (generated/workload-admission.yaml).
// The deploy Role (generated/deploy-rbac.yaml) lets a service's pipeline create
// Deployments, Jobs, CronJobs and Services and write ConfigMaps in its namespace.
// RBAC cannot look inside those objects, so three ValidatingAdmissionPolicies do:
//   fintechbankx-service-pod-security: no privileged container, host namespace,
//     hostPath volume or hostPort, and no added capability except the istio-init
//     init container's NET_ADMIN and NET_RAW (Istio runs without CNI);
//   fintechbankx-service-service-type: ClusterIP Services only, no externalIPs;
//   fintechbankx-deploy-trust-anchors: the fintechbankx:deploy:* groups may not
//     create, update or delete the trust-anchor ConfigMaps platform controllers
//     keep in every service namespace.
// The CEL runs with cel-go (tests/cel); without Go those tests are skipped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { repoRoot, loadContract } from '../scripts/lib/contract.mjs';
import { render } from '../scripts/generate/render-mesh-policies.mjs';
import { evaluate, skip } from './cel/evaluate.mjs';

const ADM = 'admissionregistration.k8s.io/v1';
const docs = render(loadContract())['workload-admission.yaml'];
const policy = (name) => {
  const p = docs.find((d) => d.kind === 'ValidatingAdmissionPolicy' && d.metadata.name === name);
  assert.ok(p, `policy ${name}`);
  return p;
};
const SERVICE_NS_SELECTOR = { matchLabels: { 'fintechbankx.io/namespace-kind': 'service' } };
const TRUST_ANCHORS = ['fintechbankx-internal-ca', 'istio-ca-root-cert', 'kube-root-ca.crt', 'rds-ca-bundle'];

test('three Deny-bound, fail-closed policies; the base kustomization lists the file', () => {
  const names = ['fintechbankx-service-pod-security', 'fintechbankx-service-service-type', 'fintechbankx-deploy-trust-anchors'];
  assert.deepEqual(docs.filter((d) => d.kind === 'ValidatingAdmissionPolicy').map((d) => d.metadata.name).sort(), [...names].sort());
  for (const name of names) {
    const p = policy(name);
    assert.equal(p.apiVersion, ADM);
    assert.equal(p.spec.failurePolicy, 'Fail', name);
    const b = docs.find((d) => d.kind === 'ValidatingAdmissionPolicyBinding' && d.spec.policyName === name);
    assert.ok(b, `${name} binding`);
    assert.deepEqual(b.spec.validationActions, ['Deny'], name);
    assert.equal(b.spec.matchResources, undefined, `${name}: the binding does not narrow the policy`);
  }
  assert.equal(docs.length, 6);
  const k = YAML.parse(readFileSync(join(repoRoot, 'deploy/kustomize/base/kustomization.yaml'), 'utf8'));
  assert.ok(k.resources.includes('generated/workload-admission.yaml'));
});

test('pod security covers Pods and every pod-template kind in kind: service namespaces', () => {
  const { matchConstraints } = policy('fintechbankx-service-pod-security').spec;
  assert.deepEqual(matchConstraints.namespaceSelector, SERVICE_NS_SELECTOR);
  const covered = matchConstraints.resourceRules.flatMap((r) => r.resources.map((res) => `${r.apiGroups.join()}/${res}:${r.operations.join()}`)).sort();
  assert.deepEqual(covered, [
    '/pods:CREATE,UPDATE',
    'apps/daemonsets:CREATE,UPDATE',
    'apps/deployments:CREATE,UPDATE',
    'apps/replicasets:CREATE,UPDATE',
    'apps/statefulsets:CREATE,UPDATE',
    'batch/cronjobs:CREATE,UPDATE',
    'batch/jobs:CREATE,UPDATE',
  ]);
});

test('Service type covers Services in kind: service namespaces', () => {
  const { matchConstraints } = policy('fintechbankx-service-service-type').spec;
  assert.deepEqual(matchConstraints.namespaceSelector, SERVICE_NS_SELECTOR);
  assert.deepEqual(matchConstraints.resourceRules, [
    { apiGroups: [''], apiVersions: ['v1'], operations: ['CREATE', 'UPDATE'], resources: ['services'] },
  ]);
});

test('trust anchors: every trust-manager Bundle that reaches service namespaces is protected, plus istiod and kube-root CAs', () => {
  const { matchConstraints } = policy('fintechbankx-deploy-trust-anchors').spec;
  assert.deepEqual(matchConstraints.namespaceSelector, SERVICE_NS_SELECTOR);
  assert.equal(matchConstraints.resourceRules.length, 1);
  const [rule] = matchConstraints.resourceRules;
  assert.deepEqual(rule.operations, ['CREATE', 'UPDATE', 'DELETE']);
  assert.deepEqual([...rule.resourceNames].sort(), TRUST_ANCHORS);
  const dir = join(repoRoot, 'k8s/platform/cert-manager');
  const bundles = readdirSync(dir)
    .filter((f) => f.endsWith('.yaml'))
    .flatMap((f) => YAML.parseAllDocuments(readFileSync(join(dir, f), 'utf8')).map((d) => d.toJSON()))
    .filter((d) => d?.kind === 'Bundle')
    .filter((d) => (d.spec.target.namespaceSelector?.matchExpressions || []).some((e) => e.values?.includes('service')));
  assert.ok(bundles.length >= 2);
  for (const b of bundles) assert.ok(rule.resourceNames.includes(b.metadata.name), `Bundle ${b.metadata.name} target ConfigMap`);
});

// ------------------------------------------------------------------ CEL cases
const nsObject = { metadata: { name: 'payments', labels: { 'kubernetes.io/metadata.name': 'payments', 'fintechbankx.io/namespace-kind': 'service' } } };
const request = (group, kind, operation = 'CREATE', extra = {}) => ({
  namespace: 'payments',
  operation,
  kind: { group, version: 'v1', kind },
  userInfo: { username: 'deploy', groups: ['fintechbankx:deploy:payments', 'system:authenticated'] },
  ...extra,
});
const APP = {
  name: 'app',
  image: 'acct.dkr.ecr.me-central-1.amazonaws.com/fintechbankx/svc@sha256:' + 'a'.repeat(64),
  ports: [{ name: 'http', containerPort: 8080 }],
  securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true, capabilities: { drop: ['ALL'] } },
};
// What the Istio 1.24 injector adds without CNI.
const ISTIO_INIT = {
  name: 'istio-init',
  image: 'docker.io/istio/proxyv2:1.24.3',
  securityContext: { allowPrivilegeEscalation: false, privileged: false, capabilities: { add: ['NET_ADMIN', 'NET_RAW'], drop: ['ALL'] }, runAsUser: 0, runAsNonRoot: false },
};
const ISTIO_PROXY = {
  name: 'istio-proxy',
  image: 'docker.io/istio/proxyv2:1.24.3',
  ports: [{ name: 'http-envoy-prom', containerPort: 15090 }],
  securityContext: { allowPrivilegeEscalation: false, privileged: false, capabilities: { drop: ['ALL'] }, runAsUser: 1337, runAsNonRoot: true },
};
const podSpec = (patch = {}) => ({ serviceAccountName: 'payment-bulk-orchestration-service', containers: [structuredClone(APP)], ...patch });
const workload = (name, kind, spec) => {
  const group = kind === 'Pod' ? '' : ['Job', 'CronJob'].includes(kind) ? 'batch' : 'apps';
  let body;
  if (kind === 'Pod') body = spec;
  else if (kind === 'CronJob') body = { schedule: '*/5 * * * *', jobTemplate: { spec: { template: { spec } } } };
  else body = { template: { metadata: { labels: { app: name } }, spec } };
  return {
    name,
    request: request(group, kind),
    namespaceObject: nsObject,
    object: { apiVersion: group ? `${group}/v1` : 'v1', kind, metadata: { name, namespace: 'payments' }, spec: body },
  };
};
const withApp = (securityContext) => [{ ...structuredClone(APP), securityContext }];

const podCases = [
  workload('chart-deployment', 'Deployment', podSpec()),
  workload('chart-job', 'Job', podSpec({ restartPolicy: 'Never' })),
  workload('chart-cronjob', 'CronJob', podSpec({ restartPolicy: 'Never' })),
  workload('injected-pod', 'Pod', podSpec({ initContainers: [structuredClone(ISTIO_INIT)], containers: [structuredClone(APP), structuredClone(ISTIO_PROXY)] })),
  workload('explicit-false', 'Deployment', podSpec({ hostNetwork: false, hostPID: false, hostIPC: false, containers: withApp({ privileged: false }) })),
  workload('privileged-deployment', 'Deployment', podSpec({ containers: withApp({ privileged: true }) })),
  workload('privileged-cronjob', 'CronJob', podSpec({ containers: withApp({ privileged: true }) })),
  workload('privileged-init', 'Job', podSpec({ initContainers: [{ name: 'setup', image: 'x', securityContext: { privileged: true } }] })),
  workload('privileged-ephemeral', 'Pod', podSpec({ ephemeralContainers: [{ name: 'debug', image: 'x', securityContext: { privileged: true } }] })),
  workload('host-path', 'Job', podSpec({ volumes: [{ name: 'root', hostPath: { path: '/' } }] })),
  workload('host-network', 'Deployment', podSpec({ hostNetwork: true })),
  workload('host-pid', 'StatefulSet', podSpec({ hostPID: true })),
  workload('host-ipc', 'DaemonSet', podSpec({ hostIPC: true })),
  workload('host-port', 'ReplicaSet', podSpec({ containers: [{ ...structuredClone(APP), ports: [{ containerPort: 8080, hostPort: 8080 }] }] })),
  workload('cap-sys-admin', 'Deployment', podSpec({ containers: withApp({ capabilities: { add: ['SYS_ADMIN'] } }) })),
  workload('cap-net-admin-app', 'Deployment', podSpec({ containers: withApp({ capabilities: { add: ['NET_ADMIN'] } }) })),
  workload('istio-init-named-app', 'Pod', podSpec({ containers: [{ ...structuredClone(ISTIO_INIT) }] })),
  workload('istio-init-sys-admin', 'Pod', podSpec({ initContainers: [{ ...structuredClone(ISTIO_INIT), securityContext: { capabilities: { add: ['NET_ADMIN', 'SYS_ADMIN'] } } }] })),
  workload('other-init-net-admin', 'Job', podSpec({ initContainers: [{ name: 'setup', image: 'x', securityContext: { capabilities: { add: ['NET_ADMIN'] } } }] })),
];

test('CEL pod security: chart workloads and injected pods are admitted; node-level settings are refused', { skip }, () => {
  const r = evaluate(policy('fintechbankx-service-pod-security').spec, podCases);
  const allowed = Object.entries(r).filter(([, v]) => v.allowed).map(([k]) => k).sort();
  assert.deepEqual(allowed, ['chart-cronjob', 'chart-deployment', 'chart-job', 'explicit-false', 'injected-pod'], JSON.stringify(r, null, 1));
  const msg = (name) => r[name].messages.join(' | ');
  for (const n of ['privileged-deployment', 'privileged-cronjob']) assert.match(msg(n), /privileged containers are not allowed in service namespaces: app$/, n);
  assert.match(msg('privileged-init'), /privileged containers .*: setup$/);
  assert.match(msg('privileged-ephemeral'), /privileged containers .*: debug$/);
  assert.match(msg('host-path'), /hostPath volumes are not allowed in service namespaces: root$/);
  for (const n of ['host-network', 'host-pid', 'host-ipc']) assert.match(msg(n), /hostNetwork, hostPID and hostIPC are not allowed/, n);
  assert.match(msg('host-port'), /hostPort is not allowed in service namespaces: app$/);
  for (const n of ['cap-sys-admin', 'cap-net-admin-app', 'istio-init-named-app']) assert.match(msg(n), /containers may not add capabilities/, n);
  for (const n of ['istio-init-sys-admin', 'other-init-net-admin']) {
    assert.match(msg(n), /only the istio-init init container may add capabilities, and only NET_ADMIN and NET_RAW/, n);
  }
});

const svc = (name, spec, operation = 'CREATE') => ({
  name,
  request: request('', 'Service', operation),
  namespaceObject: nsObject,
  object: { apiVersion: 'v1', kind: 'Service', metadata: { name, namespace: 'payments' }, spec: { ports: [{ port: 8080 }], ...spec } },
});
const serviceCases = [
  svc('chart-clusterip', { type: 'ClusterIP', selector: { app: 'x' } }),
  svc('default-type', { selector: { app: 'x' } }),
  svc('headless', { type: 'ClusterIP', clusterIP: 'None' }),
  svc('empty-external-ips', { type: 'ClusterIP', externalIPs: [] }),
  svc('load-balancer', { type: 'LoadBalancer' }),
  svc('node-port', { type: 'NodePort' }, 'UPDATE'),
  svc('external-name', { type: 'ExternalName', externalName: 'example.org' }),
  svc('external-ips', { type: 'ClusterIP', externalIPs: ['10.0.12.34'] }),
];

test('CEL Service type: ClusterIP only and no externalIPs', { skip }, () => {
  const r = evaluate(policy('fintechbankx-service-service-type').spec, serviceCases);
  const allowed = Object.entries(r).filter(([, v]) => v.allowed).map(([k]) => k).sort();
  assert.deepEqual(allowed, ['chart-clusterip', 'default-type', 'empty-external-ips', 'headless'], JSON.stringify(r, null, 1));
  for (const n of ['load-balancer', 'node-port', 'external-name']) {
    assert.match(r[n].messages.join(' | '), /Services in service namespaces must be type ClusterIP; got /, n);
  }
  assert.deepEqual(r['external-ips'].messages, ['spec.externalIPs is not allowed in service namespaces (kube-proxy would route those IPs cluster-wide)']);
});

const cm = (name, operation, groups) => ({
  name: `${name}:${operation}:${groups[0]}`,
  request: request('', 'ConfigMap', operation, { name, userInfo: { username: 'x', groups } }),
  namespaceObject: nsObject,
  object: operation === 'DELETE' ? null : { apiVersion: 'v1', kind: 'ConfigMap', metadata: { name, namespace: 'payments' }, data: { 'ca.crt': 'attacker' } },
});
const DEPLOY = ['fintechbankx:deploy:payments', 'system:authenticated'];
const TRUST_MANAGER = ['system:serviceaccounts', 'system:serviceaccounts:cert-manager', 'system:authenticated'];
const anchorCases = [
  cm('rds-ca-bundle', 'UPDATE', DEPLOY),
  cm('fintechbankx-internal-ca', 'DELETE', DEPLOY),
  cm('istio-ca-root-cert', 'CREATE', ['fintechbankx:deploy:open-finance', 'system:authenticated']),
  cm('kube-root-ca.crt', 'UPDATE', DEPLOY),
  cm('rds-ca-bundle', 'UPDATE', TRUST_MANAGER),
  cm('fintechbankx-internal-ca', 'DELETE', TRUST_MANAGER),
];

test('CEL trust anchors: deploy groups are refused, platform controllers are not', { skip }, () => {
  const r = evaluate(policy('fintechbankx-deploy-trust-anchors').spec, anchorCases);
  const allowed = Object.entries(r).filter(([, v]) => v.allowed).map(([k]) => k).sort();
  assert.deepEqual(allowed, [
    'fintechbankx-internal-ca:DELETE:system:serviceaccounts',
    'rds-ca-bundle:UPDATE:system:serviceaccounts',
  ], JSON.stringify(r, null, 1));
  assert.deepEqual(r['rds-ca-bundle:UPDATE:fintechbankx:deploy:payments'].messages, [
    'ConfigMap rds-ca-bundle is a trust anchor kept by a platform controller; the fintechbankx:deploy:* groups may not create, update or delete it',
  ]);
});
