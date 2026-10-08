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

export function knownPrincipals(contract) {
  return new Set(
    [...knownServiceAccounts(contract)].map((s) => {
      const [ns, sa] = s.split('/');
      return principal(contract, ns, sa);
    }),
  );
}

function expandEndpoint(contract, ref) {
  if (ref === '*/service-workloads') {
    return serviceWorkloads(contract).map((w) => ({ ns: w.ns, sa: w.serviceAccount }));
  }
  const [ns, sa] = ref.split('/');
  return [{ ns, sa }];
}

/** Expand wildcard edges into concrete caller -> callee pairs. */
export function expandEdges(contract) {
  const out = [];
  for (const e of contract.edges) {
    for (const from of expandEndpoint(contract, e.from)) {
      for (const to of expandEndpoint(contract, e.to)) {
        out.push({
          from,
          to,
          port: e.port,
          methods: e.methods,
          paths: e.paths,
          scope: e.scope,
          evidence: e.evidence,
        });
      }
    }
  }
  return out;
}

export function isException(contract, kind, ns) {
  return (contract.exceptions?.[kind] || []).some((x) => x.namespace === ns);
}
