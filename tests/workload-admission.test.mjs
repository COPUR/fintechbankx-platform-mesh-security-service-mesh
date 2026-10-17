// Workload admission in kind: service namespaces (generated/workload-admission.yaml).
// The deploy Role (generated/deploy-rbac.yaml) lets a service's pipeline create
// Deployments, Jobs, CronJobs and Services and write ConfigMaps in its namespace.
// RBAC cannot look inside those objects, so three ValidatingAdmissionPolicies do:
//   fintechbankx-service-pod-security: no privileged container, host namespace,
//     hostPath volume or hostPort, and no added capability except the istio-init
//     init container's NET_ADMIN and NET_RAW (Istio runs without CNI), and only
//     when it runs the Istio proxyv2 image the mesh installs; plus the other Pod
//     Security baseline controls (seccomp, AppArmor, SELinux, procMount, sysctls,
//     Windows HostProcess);
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
// What Istio 1.24.3's injection template (istiod chart files/injection-template.yaml)
// renders with this mesh's values (deploy/istio/helm: hub docker.io/istio, tag 1.24.3,
// no CNI, global.proxy.privileged false, ENABLE_NATIVE_SIDECARS "true"): istio-init,
// then istio-proxy as a native sidecar (an init container with restartPolicy Always).
// Neither container sets seccomp, AppArmor, SELinux, procMount or windowsOptions, and
// the pod gets no securityContext from the injector.
const ISTIO_IMAGE = 'docker.io/istio/proxyv2:1.24.3';
const ISTIO_INIT = {
  name: 'istio-init',
  image: ISTIO_IMAGE,
  args: ['istio-iptables', '-p', '15001', '-z', '15006', '-u', '1337', '-m', 'REDIRECT', '-i', '*', '-x', '', '-b', '*', '-d', '15090,15021,15020', '--log_output_level=default:info', '--log_as_json'],
  securityContext: {
    allowPrivilegeEscalation: false,
    privileged: false,
    capabilities: { add: ['NET_ADMIN', 'NET_RAW'], drop: ['ALL'] },
    readOnlyRootFilesystem: false,
    runAsGroup: 0,
    runAsNonRoot: false,
    runAsUser: 0,
  },
};
const ISTIO_PROXY = {
  name: 'istio-proxy',
  image: ISTIO_IMAGE,
  args: ['proxy', 'sidecar', '--domain', '$(POD_NAMESPACE).svc.cluster.local'],
  ports: [{ name: 'http-envoy-prom', containerPort: 15090, protocol: 'TCP' }],
  securityContext: {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ['ALL'] },
    privileged: false,
    readOnlyRootFilesystem: true,
    runAsGroup: 1337,
    runAsNonRoot: true,
    runAsUser: 1337,
  },
};
const NATIVE_PROXY = { ...structuredClone(ISTIO_PROXY), restartPolicy: 'Always' };
const INJECTED_ANNOTATIONS = {
  'istio.io/rev': 'default',
  'kubectl.kubernetes.io/default-container': 'app',
  'kubectl.kubernetes.io/default-logs-container': 'app',
  'prometheus.io/path': '/stats/prometheus',
  'prometheus.io/port': '15020',
  'prometheus.io/scrape': 'true',
  'sidecar.istio.io/status': '{"initContainers":["istio-init","istio-proxy"],"containers":null,"volumes":["workload-socket","istio-envoy","istio-data","istio-podinfo","istio-token","istiod-ca-cert"],"imagePullSecrets":null,"revision":"default"}',
};
const podSpec = (patch = {}) => ({ serviceAccountName: 'payment-bulk-orchestration-service', containers: [structuredClone(APP)], ...patch });
const workload = (name, kind, spec, annotations) => {
  const group = kind === 'Pod' ? '' : ['Job', 'CronJob'].includes(kind) ? 'batch' : 'apps';
  const ann = annotations ? { annotations } : {};
  let body;
  if (kind === 'Pod') body = spec;
  else if (kind === 'CronJob') body = { schedule: '*/5 * * * *', jobTemplate: { spec: { template: { metadata: { ...ann }, spec } } } };
  else body = { template: { metadata: { labels: { app: name }, ...ann }, spec } };
  return {
    name,
    request: request(group, kind),
    namespaceObject: nsObject,
    object: { apiVersion: group ? `${group}/v1` : 'v1', kind, metadata: { name, namespace: 'payments', ...(kind === 'Pod' ? ann : {}) }, spec: body },
  };
};
const withApp = (securityContext) => [{ ...structuredClone(APP), securityContext }];

const podCases = [
  workload('chart-deployment', 'Deployment', podSpec()),
  workload('chart-job', 'Job', podSpec({ restartPolicy: 'Never' })),
  workload('chart-cronjob', 'CronJob', podSpec({ restartPolicy: 'Never' })),
  workload('injected-pod', 'Pod', podSpec({ initContainers: [structuredClone(ISTIO_INIT)], containers: [structuredClone(APP), structuredClone(ISTIO_PROXY)] }), INJECTED_ANNOTATIONS),
  workload('injected-native', 'Pod', podSpec({ initContainers: [structuredClone(ISTIO_INIT), structuredClone(NATIVE_PROXY)] }), INJECTED_ANNOTATIONS),
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
  // istio-init's exception holds only for the proxyv2 repository the mesh installs; a pod
  // annotation sidecar.istio.io/proxyImage can point the injected istio-init elsewhere.
  workload('istio-init-digest', 'Pod', podSpec({ initContainers: [{ ...structuredClone(ISTIO_INIT), image: `docker.io/istio/proxyv2@sha256:${'b'.repeat(64)}` }, structuredClone(NATIVE_PROXY)] })),
  workload('istio-init-tag-digest', 'Pod', podSpec({ initContainers: [{ ...structuredClone(ISTIO_INIT), image: `docker.io/istio/proxyv2:1.24.3-distroless@sha256:${'b'.repeat(64)}` }] })),
  workload('istio-init-other-image', 'Pod', podSpec({ initContainers: [{ ...structuredClone(ISTIO_INIT), image: 'registry.example/tools/netshoot:1' }] })),
  workload('istio-init-lookalike-repo', 'Deployment', podSpec({ initContainers: [{ ...structuredClone(ISTIO_INIT), image: 'docker.io/istio/proxyv2-debug:1.24.3' }] })),
  workload('istio-init-other-registry', 'Pod', podSpec({ initContainers: [{ ...structuredClone(ISTIO_INIT), image: 'evil.example/docker.io/istio/proxyv2:1.24.3' }] })),
  workload('istio-init-no-image', 'Deployment', podSpec({ initContainers: [{ ...structuredClone(ISTIO_INIT), image: undefined }] })),
];

test('CEL pod security: chart workloads and injected pods are admitted; node-level settings are refused', { skip }, () => {
  const r = evaluate(policy('fintechbankx-service-pod-security').spec, podCases);
  const allowed = Object.entries(r).filter(([, v]) => v.allowed).map(([k]) => k).sort();
  assert.deepEqual(
    allowed,
    ['chart-cronjob', 'chart-deployment', 'chart-job', 'explicit-false', 'injected-native', 'injected-pod', 'istio-init-digest', 'istio-init-tag-digest'],
    JSON.stringify(r, null, 1),
  );
  const msg = (name) => r[name].messages.join(' | ');
  for (const n of ['privileged-deployment', 'privileged-cronjob']) assert.match(msg(n), /privileged containers are not allowed in service namespaces: app$/, n);
  assert.match(msg('privileged-init'), /privileged containers .*: setup$/);
  assert.match(msg('privileged-ephemeral'), /privileged containers .*: debug$/);
  assert.match(msg('host-path'), /hostPath volumes are not allowed in service namespaces: root$/);
  for (const n of ['host-network', 'host-pid', 'host-ipc']) assert.match(msg(n), /hostNetwork, hostPID and hostIPC are not allowed/, n);
  assert.match(msg('host-port'), /hostPort is not allowed in service namespaces: app$/);
  for (const n of ['cap-sys-admin', 'cap-net-admin-app', 'istio-init-named-app']) assert.match(msg(n), /containers may not add capabilities/, n);
  for (const n of ['istio-init-sys-admin', 'other-init-net-admin', 'istio-init-other-image', 'istio-init-lookalike-repo', 'istio-init-other-registry', 'istio-init-no-image']) {
    assert.match(
      msg(n),
      /only the istio-init init container running docker\.io\/istio\/proxyv2 may add capabilities, and only NET_ADMIN and NET_RAW: (istio-init|setup)$/,
      n,
    );
  }
});

test('the istio-init exception names the proxyv2 repository deploy/istio installs', () => {
  const values = YAML.parse(readFileSync(join(repoRoot, 'deploy/istio/helm/istiod.values.yaml'), 'utf8'));
  const repo = `${values.global.hub}/${values.global.proxy_init?.image ?? 'proxyv2'}`;
  assert.equal(repo, 'docker.io/istio/proxyv2');
  // CEL source: a single-quoted string with '\\.' for a literal dot.
  const text = policy('fintechbankx-service-pod-security').spec.validations.map((v) => v.expression).join('\n');
  assert.ok(text.includes(`c.image.matches('^${repo.replace(/\./g, '\\\\.')}(`), 'the image pattern is built from the installed hub and image name');
});

// The rest of Pod Security baseline (Kubernetes Pod Security Standards), at pod and
// container level wherever baseline checks both. The injected pods above set none of
// these fields and stay admitted.
const SAFE_SYSCTLS = [
  'kernel.shm_rmid_forced',
  'net.ipv4.ip_local_port_range',
  'net.ipv4.ip_unprivileged_port_start',
  'net.ipv4.tcp_syncookies',
  'net.ipv4.ping_group_range',
  'net.ipv4.ip_local_reserved_ports',
  'net.ipv4.tcp_keepalive_time',
  'net.ipv4.tcp_fin_timeout',
  'net.ipv4.tcp_keepalive_intvl',
  'net.ipv4.tcp_keepalive_probes',
];
const withAppSc = (patch) => [{ ...structuredClone(APP), securityContext: { ...structuredClone(APP.securityContext), ...patch } }];
const baselineCases = [
  workload(
    'baseline-allowed-values',
    'Deployment',
    podSpec({
      securityContext: {
        seccompProfile: { type: 'RuntimeDefault' },
        appArmorProfile: { type: 'Localhost', localhostProfile: 'fbx' },
        seLinuxOptions: { type: 'container_t', level: 's0:c123,c456' },
        sysctls: SAFE_SYSCTLS.map((name) => ({ name, value: '1' })),
        windowsOptions: { hostProcess: false },
      },
      initContainers: [{ name: 'setup', image: 'x', securityContext: { seLinuxOptions: { type: 'container_init_t' }, seccompProfile: { type: 'Localhost', localhostProfile: 'p.json' } } }],
      containers: withAppSc({ appArmorProfile: { type: 'RuntimeDefault' }, procMount: 'Default', seLinuxOptions: { type: '' }, windowsOptions: { hostProcess: false } }),
    }),
    { 'container.apparmor.security.beta.kubernetes.io/app': 'runtime/default', 'container.apparmor.security.beta.kubernetes.io/setup': 'localhost/fbx' },
  ),
  workload('selinux-kvm-and-engine', 'Job', podSpec({ securityContext: { seLinuxOptions: { type: 'container_kvm_t' } }, containers: withAppSc({ seLinuxOptions: { type: 'container_engine_t' } }) })),
  workload('seccomp-unconfined-pod', 'Deployment', podSpec({ securityContext: { seccompProfile: { type: 'Unconfined' } } })),
  workload('seccomp-unconfined-container', 'CronJob', podSpec({ containers: withAppSc({ seccompProfile: { type: 'Unconfined' } }) })),
  workload('seccomp-unconfined-init', 'Job', podSpec({ initContainers: [{ name: 'setup', image: 'x', securityContext: { seccompProfile: { type: 'Unconfined' } } }] })),
  workload('apparmor-unconfined-pod', 'Pod', podSpec({ securityContext: { appArmorProfile: { type: 'Unconfined' } } })),
  workload('apparmor-unconfined-container', 'StatefulSet', podSpec({ containers: withAppSc({ appArmorProfile: { type: 'Unconfined' } }) })),
  workload('apparmor-annotation-template', 'Deployment', podSpec(), { 'container.apparmor.security.beta.kubernetes.io/app': 'unconfined' }),
  workload('apparmor-annotation-cronjob', 'CronJob', podSpec(), { 'container.apparmor.security.beta.kubernetes.io/app': 'unconfined' }),
  workload('apparmor-annotation-pod', 'Pod', podSpec(), { 'container.apparmor.security.beta.kubernetes.io/app': 'docker/default' }),
  workload('selinux-type-pod', 'Deployment', podSpec({ securityContext: { seLinuxOptions: { type: 'spc_t' } } })),
  workload('selinux-type-container', 'DaemonSet', podSpec({ containers: withAppSc({ seLinuxOptions: { type: 'unconfined_t' } }) })),
  workload('selinux-user', 'Job', podSpec({ securityContext: { seLinuxOptions: { user: 'system_u' } } })),
  workload('selinux-role', 'ReplicaSet', podSpec({ containers: withAppSc({ seLinuxOptions: { role: 'system_r' } }) })),
  workload('procmount-unmasked', 'Deployment', podSpec({ containers: withAppSc({ procMount: 'Unmasked' }) })),
  workload('sysctl-unsafe', 'Deployment', podSpec({ securityContext: { sysctls: [{ name: 'net.ipv4.tcp_syncookies', value: '1' }, { name: 'kernel.msgmax', value: '65536' }] } })),
  workload('hostprocess-pod', 'Pod', podSpec({ securityContext: { windowsOptions: { hostProcess: true } } })),
  workload('hostprocess-container', 'Job', podSpec({ containers: withAppSc({ windowsOptions: { hostProcess: true } }) })),
];

test('CEL pod security: the other Pod Security baseline controls, at pod and container level', { skip }, () => {
  const r = evaluate(policy('fintechbankx-service-pod-security').spec, baselineCases);
  const allowed = Object.entries(r).filter(([, v]) => v.allowed).map(([k]) => k).sort();
  assert.deepEqual(allowed, ['baseline-allowed-values', 'selinux-kvm-and-engine'], JSON.stringify(r, null, 1));
  const msg = (name) => r[name].messages.join(' | ');
  assert.match(msg('seccomp-unconfined-pod'), /seccompProfile\.type must be RuntimeDefault or Localhost in service namespaces: pod$/);
  assert.match(msg('seccomp-unconfined-container'), /seccompProfile\.type must be RuntimeDefault or Localhost in service namespaces: app$/);
  assert.match(msg('seccomp-unconfined-init'), /seccompProfile\.type must be RuntimeDefault or Localhost in service namespaces: setup$/);
  assert.match(msg('apparmor-unconfined-pod'), /appArmorProfile\.type must be RuntimeDefault or Localhost in service namespaces: pod$/);
  assert.match(msg('apparmor-unconfined-container'), /appArmorProfile\.type must be RuntimeDefault or Localhost in service namespaces: app$/);
  for (const n of ['apparmor-annotation-template', 'apparmor-annotation-cronjob', 'apparmor-annotation-pod']) {
    assert.match(msg(n), /AppArmor annotations must be runtime\/default or localhost\/<profile> in service namespaces: container\.apparmor\.security\.beta\.kubernetes\.io\/app$/, n);
  }
  const selinux = /seLinuxOptions may set type only to container_t, container_init_t, container_kvm_t or container_engine_t, and no user or role, in service namespaces: /;
  for (const [n, who] of [['selinux-type-pod', 'pod'], ['selinux-type-container', 'app'], ['selinux-user', 'pod'], ['selinux-role', 'app']]) {
    assert.match(msg(n), new RegExp(selinux.source + who + '$'), n);
  }
  assert.match(msg('procmount-unmasked'), /procMount must be Default in service namespaces: app$/);
  assert.equal(msg('sysctl-unsafe'), 'sysctls outside the Pod Security baseline safe set are not allowed in service namespaces: kernel.msgmax');
  assert.match(msg('hostprocess-pod'), /Windows HostProcess is not allowed in service namespaces: pod$/);
  assert.match(msg('hostprocess-container'), /Windows HostProcess is not allowed in service namespaces: app$/);
  for (const [n, v] of Object.entries(r)) if (!v.allowed) assert.equal(v.messages.length, 1, `${n}: one control fails: ${v.messages}`);
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
