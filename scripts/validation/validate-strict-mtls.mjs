#!/usr/bin/env node
// Strict-mTLS and zero-trust validator for the mesh repo.
//
//   node scripts/validation/validate-strict-mtls.mjs            # repo sources
//   node scripts/validation/validate-strict-mtls.mjs --rendered build/prod.yaml
//
// Rules (contracts/mesh-contract.yaml is the reference):
//  R1 no PeerAuthentication PERMISSIVE/DISABLE (incl. portLevelMtls) outside
//     exceptions.peerAuthentication; no in-mesh DestinationRule tls DISABLE.
//  R2 a selector-less PeerAuthentication in istio-system is STRICT.
//  R3 every service namespace (and every injected namespace) has a default-deny
//     AuthorizationPolicy; every namespace not excepted has a default-deny
//     NetworkPolicy.
//  R4 every principal in an AuthorizationPolicy is a known SA from the contract;
//     every source namespace is a known namespace.
//  R5 no ALLOW rule without `from` and `to` (allow-all).
//  R6 namespace labels: istio-injection matches the contract, context label set.
//  R7 every service workload has a RequestAuthentication with its service id
//     as audience, and its namespace a DENY policy for /api/** without JWT
//     (unless exceptions.requestAuthentication).
//  R8 generated manifests match the contract rendering.
// R1 applies to every YAML file in the repo (including legacy folders);
// R2-R7 apply to the deployable set (deploy/, k8s/platform/) or a rendered file.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import YAML from 'yaml';
import {
  repoRoot,
  loadContract,
  knownPrincipals,
  serviceNamespaces,
  injectedNamespaces,
  isException,
} from '../lib/contract.mjs';

const SKIP_DIRS = new Set(['.git', 'node_modules', 'build', '.gradle']);
const DEPLOYABLE = ['deploy/', 'k8s/platform/'];

export function walkYaml(root = repoRoot) {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.ya?ml$/.test(name)) out.push(p);
    }
  };
  walk(root);
  return out.sort();
}

/** Parse a multi-document YAML text into [{doc, file, index}], skipping non-objects. */
export function parseDocs(text, file) {
  return YAML.parseAllDocuments(text)
    .map((d, index) => ({ doc: d.toJS(), file, index }))
    .filter((d) => d.doc && typeof d.doc === 'object' && d.doc.kind);
}

const where = (d) => `${d.file}#${d.index} ${d.doc.kind}/${d.doc.metadata?.namespace ?? '-'}/${d.doc.metadata?.name ?? '-'}`;
const isEmpty = (o) => o == null || (typeof o === 'object' && Object.keys(o).length === 0);
const WEAK = new Set(['PERMISSIVE', 'DISABLE']);

/** R1 - applies to every manifest. */
export function checkMtlsModes(docs, contract) {
  const errors = [];
  for (const d of docs) {
    const { kind, spec = {}, metadata = {} } = d.doc;
    if (kind === 'PeerAuthentication') {
      const modes = [spec.mtls?.mode, ...Object.values(spec.portLevelMtls || {}).map((p) => p?.mode)];
      for (const m of modes) {
        if (m && WEAK.has(m) && !isException(contract, 'peerAuthentication', metadata.namespace)) {
          errors.push(`R1 ${where(d)}: mTLS mode ${m} is not allowed (no documented exception)`);
        }
      }
    }
    if (kind === 'DestinationRule') {
      const host = String(spec.host || '');
      const inMesh = host.endsWith('.local') || !host.includes('.');
      const tlsModes = [
        spec.trafficPolicy?.tls?.mode,
        ...(spec.trafficPolicy?.portLevelSettings || []).map((p) => p?.tls?.mode),
        ...(spec.subsets || []).map((s) => s?.trafficPolicy?.tls?.mode),
      ];
      if (inMesh && tlsModes.includes('DISABLE')) {
        errors.push(`R1 ${where(d)}: DestinationRule disables TLS for in-mesh host ${host}`);
      }
    }
  }
  return errors;
}

/** R2-R7 - apply to the deployable set. */
export function checkZeroTrust(docs, contract) {
  const errors = [];
  const byKind = (k) => docs.filter((d) => d.doc.kind === k);
  const nsOf = (d) => d.doc.metadata?.namespace;

  // R2
  const meshWide = byKind('PeerAuthentication').filter(
    (d) => nsOf(d) === 'istio-system' && isEmpty(d.doc.spec?.selector),
  );
  if (meshWide.length === 0 || !meshWide.every((d) => d.doc.spec?.mtls?.mode === 'STRICT')) {
    errors.push('R2 mesh-wide PeerAuthentication in istio-system must exist and be STRICT');
  }

  // R3
  const aps = byKind('AuthorizationPolicy');
  const required = new Set([...serviceNamespaces(contract), ...injectedNamespaces(contract)].map((n) => n.name));
  for (const ns of required) {
    if (!aps.some((d) => nsOf(d) === ns && isEmpty(d.doc.spec))) {
      errors.push(`R3 namespace ${ns} has no default-deny AuthorizationPolicy (empty spec)`);
    }
  }
  const nps = byKind('NetworkPolicy');
  for (const n of contract.namespaces) {
    if (isException(contract, 'networkPolicyDefaultDeny', n.name)) continue;
    const ok = nps.some((d) => {
      const s = d.doc.spec || {};
      return (
        nsOf(d) === n.name &&
        isEmpty(s.podSelector) &&
        (s.policyTypes || []).includes('Ingress') &&
        (s.policyTypes || []).includes('Egress') &&
        isEmpty(s.ingress) &&
        isEmpty(s.egress)
      );
    });
    if (!ok) errors.push(`R3 namespace ${n.name} has no default-deny NetworkPolicy`);
  }

  // R4 + R5
  const principals = knownPrincipals(contract);
  const namespaces = new Set(contract.namespaces.map((n) => n.name));
  for (const d of aps) {
    const spec = d.doc.spec || {};
    if (isEmpty(spec)) continue;
    const action = spec.action || 'ALLOW';
    for (const rule of spec.rules || []) {
      if (action === 'ALLOW' && isEmpty(rule) ) {
        errors.push(`R5 ${where(d)}: ALLOW rule with neither from nor to allows everything`);
      }
      for (const f of rule.from || []) {
        const src = f.source || {};
        for (const p of [...(src.principals || []), ...(src.notPrincipals || [])]) {
          if (!principals.has(p)) errors.push(`R4 ${where(d)}: principal ${p} is not a known service account`);
        }
        for (const ns of [...(src.namespaces || []), ...(src.notNamespaces || [])]) {
          if (!namespaces.has(ns)) errors.push(`R4 ${where(d)}: namespace ${ns} is not in the contract`);
        }
      }
    }
    if (action === 'ALLOW' && (spec.rules || []).length === 0) {
      // ALLOW with no rules matches nothing (= deny); only legal as default-deny with empty spec.
      errors.push(`R5 ${where(d)}: ALLOW policy without rules; use an empty spec for default-deny`);
    }
  }

  // R6
  const nsDocs = new Map(byKind('Namespace').map((d) => [d.doc.metadata.name, d]));
  for (const n of contract.namespaces) {
    const d = nsDocs.get(n.name);
    if (!d) {
      errors.push(`R6 namespace ${n.name} is not declared`);
      continue;
    }
    const labels = d.doc.metadata.labels || {};
    const injected = !n.injection || n.injection === 'enabled';
    if (injected && labels['istio-injection'] !== 'enabled') {
      errors.push(`R6 namespace ${n.name} must carry istio-injection=enabled`);
    }
    if (!injected) {
      if (labels['istio-injection'] === 'enabled') errors.push(`R6 namespace ${n.name} must not be injected`);
      if (!isException(contract, 'injection', n.name)) {
        errors.push(`R6 namespace ${n.name} is not injected but has no documented exception`);
      }
    }
    if (labels['fintechbankx.io/context'] !== n.context) {
      errors.push(`R6 namespace ${n.name} must carry fintechbankx.io/context=${n.context}`);
    }
  }

  // R7
  const ras = byKind('RequestAuthentication');
  for (const n of serviceNamespaces(contract)) {
    if (isException(contract, 'requestAuthentication', n.name)) continue;
    for (const w of n.workloads || []) {
      const ok = ras.some(
        (d) =>
          nsOf(d) === n.name &&
          d.doc.spec?.selector?.matchLabels?.['app.kubernetes.io/name'] === w.serviceAccount &&
          (d.doc.spec?.jwtRules || []).every((r) => (r.audiences || []).includes(w.serviceId) && r.issuer),
      );
      if (!ok) errors.push(`R7 ${n.name}/${w.serviceAccount} has no RequestAuthentication requiring aud ${w.serviceId}`);
    }
    const deny = aps.some(
      (d) =>
        nsOf(d) === n.name &&
        d.doc.spec?.action === 'DENY' &&
        (d.doc.spec.rules || []).some(
          (r) =>
            (r.from || []).some((f) => (f.source?.notRequestPrincipals || []).includes('*')) &&
            (r.to || []).some((t) => (t.operation?.paths || []).includes('/api/*')),
        ),
    );
    if (!deny) errors.push(`R7 namespace ${n.name} has no DENY policy for /api/* without a JWT`);
  }
  return errors;
}

/** R8 */
export async function checkGenerated() {
  const { render, toText, outDir } = await import('../generate/render-mesh-policies.mjs');
  const errors = [];
  for (const [file, docs] of Object.entries(render())) {
    const path = join(outDir, file);
    let current = '';
    try {
      current = readFileSync(path, 'utf8');
    } catch {
      /* missing */
    }
    if (current !== toText(docs)) errors.push(`R8 ${relative(repoRoot, path)} is out of date; run npm run generate`);
  }
  return errors;
}

export function loadRepoDocs(root = repoRoot) {
  return walkYaml(root).flatMap((f) => parseDocs(readFileSync(f, 'utf8'), relative(root, f)));
}

async function main() {
  const contract = loadContract();
  const idx = process.argv.indexOf('--rendered');
  let errors = [];
  if (idx > 0) {
    const file = process.argv[idx + 1];
    const docs = parseDocs(readFileSync(file, 'utf8'), file);
    errors = [...checkMtlsModes(docs, contract), ...checkZeroTrust(docs, contract)];
    console.log(`checked ${docs.length} rendered documents from ${file}`);
  } else {
    const all = loadRepoDocs();
    const deployable = all.filter((d) => DEPLOYABLE.some((p) => d.file.startsWith(p)));
    errors = [...checkMtlsModes(all, contract), ...checkZeroTrust(deployable, contract), ...(await checkGenerated())];
    console.log(`checked ${all.length} documents (${deployable.length} deployable)`);
  }
  if (errors.length) {
    for (const e of errors) console.error(`FAIL ${e}`);
    console.error(`${errors.length} strict-mTLS / zero-trust violation(s)`);
    process.exit(1);
  }
  console.log('strict mTLS and zero-trust rules: OK');
}

if (import.meta.url === `file://${process.argv[1]}`) main();
