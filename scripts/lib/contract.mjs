// Shared helpers: load the mesh contract and expand its edges.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const contractPath = join(repoRoot, 'contracts', 'mesh-contract.yaml');

export function loadContract(path = contractPath) {
  return YAML.parse(readFileSync(path, 'utf8'));
}

export function principal(contract, ns, sa) {
  return `${contract.istio.trustDomain}/ns/${ns}/sa/${sa}`;
}

export function serviceNamespaces(contract) {
  return contract.namespaces.filter((n) => n.kind === 'service');
}

export function injectedNamespaces(contract) {
  return contract.namespaces.filter((n) => !n.injection || n.injection === 'enabled');
}

/** Every workload that lives in a `kind: service` namespace. */
export function serviceWorkloads(contract) {
  return serviceNamespaces(contract).flatMap((n) =>
    (n.workloads || []).map((w) => ({ ns: n.name, ...w })),
  );
}

/** All known service accounts as `ns/sa` strings. */
export function knownServiceAccounts(contract) {
  const out = new Set();
  for (const n of contract.namespaces) {
    for (const w of n.workloads || []) out.add(`${n.name}/${w.serviceAccount}`);
  }
  out.add(`${contract.gateway.namespace}/${contract.gateway.serviceAccount}`);
  return out;
}

/** Principals that can actually be presented: workloads with a sidecar, and the gateway. */
export function knownPrincipals(contract) {
  const meshed = new Set();
  for (const n of contract.namespaces) {
    for (const w of n.workloads || []) if (w.sidecar !== false) meshed.add(`${n.name}/${w.serviceAccount}`);
  }
  meshed.add(`${contract.gateway.namespace}/${contract.gateway.serviceAccount}`);
  return new Set(
    [...meshed].map((s) => {
      const [ns, sa] = s.split('/');
      return principal(contract, ns, sa);
    }),
  );
}

/**
 * Resolve a workload reference `ns/name` to its identity and pod selector.
 * `name` is the workload's `name` (defaults to its service account). Several
 * workloads may share one service account (Tempo, Loki components); the
 * SPIFFE principal comes from the service account, the pod selector from the
 * workload's `selector` (default app.kubernetes.io/name=<service account>).
 */
export function resolveWorkload(contract, ns, name) {
  if (ns === contract.gateway.namespace && name === contract.gateway.serviceAccount) {
    return {
      ns, sa: name, name, selector: contract.gateway.selector, sidecar: true,
      service: null, destinationRule: false,
    };
  }
  const n = contract.namespaces.find((x) => x.name === ns);
  const w = (n?.workloads || []).find((x) => (x.name || x.serviceAccount) === name);
  if (!w) return { ns, sa: name, name, selector: { 'app.kubernetes.io/name': name }, sidecar: true, service: name };
  return {
    ns,
    sa: w.serviceAccount,
    name: w.name || w.serviceAccount,
    selector: w.selector || { 'app.kubernetes.io/name': w.serviceAccount },
    sidecar: w.sidecar !== false,
    service: w.service === undefined ? w.serviceAccount : w.service,
    destinationRule: w.destinationRule !== false,
  };
}

function expandEndpoint(contract, ref) {
  if (ref === '*/service-workloads') {
    return serviceWorkloads(contract).map((w) => resolveWorkload(contract, w.ns, w.name || w.serviceAccount));
  }
  // Every workload that carries an Istio sidecar, in every injected namespace,
  // plus the ingress gateway (Envoy tracing and OTLP from platform components).
  if (ref === '*/mesh-workloads') {
    const out = [resolveWorkload(contract, contract.gateway.namespace, contract.gateway.serviceAccount)];
    for (const n of injectedNamespaces(contract)) {
      for (const w of n.workloads || []) {
        const r = resolveWorkload(contract, n.name, w.name || w.serviceAccount);
        if (r.sidecar && !out.some((o) => o.ns === r.ns && o.sa === r.sa)) out.push(r);
      }
    }
    return out;
  }
  const [ns, name] = ref.split('/');
  return [resolveWorkload(contract, ns, name)];
}

/** Expand wildcard edges (and multi-port edges) into concrete caller -> callee pairs. */
export function expandEdges(contract) {
  const out = [];
  for (const e of contract.edges) {
    const ports = e.ports || [e.port];
    for (const from of expandEndpoint(contract, e.from)) {
      for (const to of expandEndpoint(contract, e.to)) {
        for (const port of ports) {
          out.push({
            from,
            to,
            port,
            methods: e.methods,
            paths: e.paths,
            notPaths: e.notPaths,
            scope: e.scope,
            evidence: e.evidence,
          });
        }
      }
    }
  }
  return out;
}

export function isException(contract, kind, ns) {
  return (contract.exceptions?.[kind] || []).some((x) => x.namespace === ns);
}

/**
 * Namespaces governed by the ExternalSecret admission policy and the key
 * slugs each may read (<env>/<slug>/...). Service namespaces: their workloads'
 * service accounts (= service slug). Shared platform namespaces: the slugs
 * listed under secrets.sharedStoreNamespaces.
 */
export function secretScopes(contract) {
  const out = {};
  for (const n of serviceNamespaces(contract)) {
    out[n.name] = [...new Set((n.workloads || []).map((w) => w.serviceAccount))].sort();
  }
  for (const [ns, slugs] of Object.entries(contract.secrets?.sharedStoreNamespaces || {})) {
    out[ns] = [...slugs].sort();
  }
  return out;
}
