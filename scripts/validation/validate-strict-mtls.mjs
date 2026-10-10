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
//  R9 every workload declared without a sidecar is listed in
//     exceptions.workloadInjection.
//  R10 secret scoping (contract `secrets`): the service ClusterSecretStore has
//     conditions selecting only service namespaces and the shared namespaces;
//     the platform store names only the platform-store namespaces and uses its
//     own ESO service account; ExternalSecrets in platform-store namespaces use
//     the platform store; any other ExternalSecret uses the service store and
//     reads only <env>/<slug>/ keys (service namespaces: slug = its
//     app.kubernetes.io/name label, one of the namespace's service accounts);
//     the ValidatingAdmissionPolicy enforcing this at admission exists with a
//     Deny binding. Static checks only; tests/externalsecret-admission-
//     cel.test.mjs evaluates the policy's CEL with cel-go.
//  R11 no ALLOW rule into open-finance/consent-authorization-service without
//     paths (port-only or from-only rules reach /internal/v1 and
//     /oauth2/token), including selector-less ALLOWs in open-finance; and no
//     ALLOW path pattern on any workload covers /internal/* unless the same
//     operation excludes /internal/* in notPaths.
//  R12 no Istio Telemetry tags metrics or spans, or filters access logs, on
//     customer or account identifiers (tag names, header names, values,
//     expressions): PII and unbounded label cardinality.
// R1 and R12 apply to every YAML file in the repo (including legacy folders);
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
  secretScopes,
  isMigrationJob,
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

// customer / account / IBAN / PSU identifiers; "service_account" and
// "serviceaccount" are workload identities, not customer data.
const IDENTIFIER = /customer|(?<!service[_-]?)account|\biban\b|iban[_-]|psu[_-]?id/i;

/** R12 - applies to every manifest. */
export function checkTelemetryTags(docs) {
  const errors = [];
  for (const d of docs.filter((x) => x.doc.kind === 'Telemetry')) {
    const spec = d.doc.spec || {};
    const found = [];
    for (const m of spec.metrics || []) {
      for (const o of m.overrides || []) {
        for (const [tag, v] of Object.entries(o.tagOverrides || {})) found.push([`metrics tag ${tag}`, tag, JSON.stringify(v)]);
      }
    }
    for (const t of spec.tracing || []) {
      for (const [tag, v] of Object.entries(t.customTags || {})) found.push([`tracing tag ${tag}`, tag, JSON.stringify(v)]);
    }
    for (const a of spec.accessLogging || []) {
      if (a.filter?.expression) found.push(['accessLogging filter', '', a.filter.expression]);
    }
    for (const [what, ...texts] of found) {
      if (texts.some((t) => IDENTIFIER.test(t))) {
        errors.push(`R12 ${where(d)}: ${what} uses a customer or account identifier`);
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
      if (isMigrationJob(w)) continue; // no inbound traffic
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
  errors.push(...checkSecretScoping(docs, contract));
  errors.push(...checkInternalPaths(aps));

  // R9
  const excepted = new Set((contract.exceptions?.workloadInjection || []).map((x) => x.workload));
  for (const n of contract.namespaces) {
    for (const w of n.workloads || []) {
      const ref = `${n.name}/${w.name || w.serviceAccount}`;
      if (w.sidecar === false && !excepted.has(ref)) {
        errors.push(`R9 ${ref} runs without a sidecar but has no exceptions.workloadInjection entry`);
      }
    }
  }
  return errors;
}

// Workloads whose every ALLOW rule must name its paths.
const PATH_SCOPED_CALLEES = [{ ns: 'open-finance', name: 'consent-authorization-service' }];

/** Can an Istio path pattern match a path under /internal/? */
export function coversInternal(p) {
  if (p.startsWith('*')) return true; // "*" or suffix match: any prefix
  if (p.includes('{')) {
    const first = p.split('/')[1];
    return first === 'internal' || first === '{*}' || first === '{**}';
  }
  if (p.endsWith('*')) {
    const prefix = p.slice(0, -1);
    return '/internal/'.startsWith(prefix) || prefix.startsWith('/internal/');
  }
  return p === '/internal' || p.startsWith('/internal/');
}
const excludesInternal = (op) => (op.notPaths || []).some((n) => ['/internal/*', '/internal*'].includes(n));

/** R11 - path-scoped access to consent-auth and nothing reaches /internal/*. */
export function checkInternalPaths(aps) {
  const errors = [];
  for (const d of aps) {
    const spec = d.doc.spec || {};
    if (isEmpty(spec) || (spec.action || 'ALLOW') !== 'ALLOW') continue;
    const ns = d.doc.metadata?.namespace;
    const app = spec.selector?.matchLabels?.['app.kubernetes.io/name'];
    for (const c of PATH_SCOPED_CALLEES) {
      if (ns !== c.ns || (app !== undefined && app !== c.name)) continue;
      for (const rule of spec.rules || []) {
        const to = rule.to || [];
        if (to.length === 0 || to.some((t) => (t.operation?.paths || []).length === 0)) {
          errors.push(`R11 ${where(d)}: ALLOW into ${c.name} without paths (reaches /internal/* and every other endpoint)`);
        }
      }
    }
    for (const rule of spec.rules || []) {
      for (const t of rule.to || []) {
        const op = t.operation || {};
        if (excludesInternal(op)) continue;
        for (const p of (op.paths || []).filter(coversInternal)) {
          errors.push(`R11 ${where(d)}: path ${p} covers /internal/*`);
        }
      }
    }
  }
  return errors;
}

/** R10 - secret store scoping and the ExternalSecret admission policy. */
export function checkSecretScoping(docs, contract) {
  const sec = contract.secrets;
  if (!sec) return [];
  const errors = [];
  const byKind = (k) => docs.filter((d) => d.doc.kind === k);
  const stores = new Map(byKind('ClusterSecretStore').map((d) => [d.doc.metadata.name, d]));
  const scopes = secretScopes(contract);
  const platformNs = new Set(sec.platformStoreNamespaces);
  const storeSa = (d) => d.doc.spec?.provider?.aws?.auth?.jwt?.serviceAccountRef?.name;

  // Service store: every condition is the service-namespace selector or names shared namespaces.
  const svc = stores.get(sec.serviceStore);
  if (!svc) errors.push(`R10 ClusterSecretStore ${sec.serviceStore} is missing`);
  else {
    const conds = svc.doc.spec?.conditions || [];
    if (conds.length === 0) errors.push(`R10 ${where(svc)}: ${sec.serviceStore} has no spec.conditions (every namespace could use it)`);
    for (const c of conds) {
      const sel = c.namespaceSelector;
      const selOk =
        sel === undefined ||
        (isEmpty(sel.matchExpressions) &&
          JSON.stringify(sel.matchLabels || {}) === JSON.stringify({ 'fintechbankx.io/namespace-kind': 'service' }));
      const names = c.namespaces || [];
      const bad = names.filter((n) => !(n in scopes) || platformNs.has(n));
      if (!selOk) errors.push(`R10 ${where(svc)}: condition namespaceSelector must be exactly fintechbankx.io/namespace-kind=service`);
      if (bad.length) errors.push(`R10 ${where(svc)}: condition names namespaces outside the service scope: ${bad.join(', ')}`);
      if (c.namespaceRegexes) errors.push(`R10 ${where(svc)}: condition namespaceRegexes is not allowed`);
      if (sel === undefined && names.length === 0) errors.push(`R10 ${where(svc)}: empty condition matches every namespace`);
    }
    if (storeSa(svc) !== sec.serviceStoreServiceAccount) {
      errors.push(`R10 ${where(svc)}: must authenticate as service account ${sec.serviceStoreServiceAccount}`);
    }
  }

  // Platform store: explicit platform namespaces only, own service account (own IAM role).
  const pf = stores.get(sec.platformStore);
  if (!pf) errors.push(`R10 ClusterSecretStore ${sec.platformStore} is missing`);
  else {
    const conds = pf.doc.spec?.conditions || [];
    if (conds.length === 0) errors.push(`R10 ${where(pf)}: ${sec.platformStore} has no spec.conditions`);
    for (const c of conds) {
      if (c.namespaceSelector || c.namespaceRegexes) errors.push(`R10 ${where(pf)}: condition must list namespaces by name (no namespaceSelector / namespaceRegexes)`);
      const bad = (c.namespaces || []).filter((n) => !platformNs.has(n));
      if (bad.length) errors.push(`R10 ${where(pf)}: condition names non-platform namespaces: ${bad.join(', ')}`);
      if (!c.namespaceSelector && !c.namespaceRegexes && (c.namespaces || []).length === 0) errors.push(`R10 ${where(pf)}: empty condition matches every namespace`);
    }
    if (storeSa(pf) !== sec.platformStoreServiceAccount || storeSa(pf) === sec.serviceStoreServiceAccount) {
      errors.push(`R10 ${where(pf)}: must use its own service account ${sec.platformStoreServiceAccount} (own IAM role)`);
    }
  }

  // ExternalSecrets in the documents (static form of the admission policy).
  for (const d of byKind('ExternalSecret')) {
    const ns = d.doc.metadata?.namespace;
    const spec = d.doc.spec || {};
    const storeName = spec.secretStoreRef?.name;
    if (platformNs.has(ns)) {
      if (storeName !== sec.platformStore) errors.push(`R10 ${where(d)}: platform ExternalSecret must use ${sec.platformStore}, not ${storeName}`);
      continue;
    }
    if (spec.secretStoreRef?.kind !== 'ClusterSecretStore' || storeName !== sec.serviceStore) {
      errors.push(`R10 ${where(d)}: must use ClusterSecretStore ${sec.serviceStore}, not ${storeName}`);
    }
    const allowed = scopes[ns] || [];
    const isService = serviceNamespaces(contract).some((n) => n.name === ns);
    const label = d.doc.metadata?.labels?.['app.kubernetes.io/name'];
    const slugs = isService ? allowed.filter((x) => x === label) : allowed;
    if (slugs.length === 0) {
      errors.push(`R10 ${where(d)}: label app.kubernetes.io/name must be one of ${allowed.join(', ') || '(no scope)'}`);
    }
    for (const x of spec.data || []) if (x.sourceRef) errors.push(`R10 ${where(d)}: data sourceRef overrides the store`);
    for (const f of spec.dataFrom || []) {
      if (f.find) errors.push(`R10 ${where(d)}: dataFrom find is not allowed`);
      if (f.sourceRef) errors.push(`R10 ${where(d)}: dataFrom sourceRef overrides the store`);
    }
    const keys = [...(spec.data || []).map((x) => x.remoteRef?.key), ...(spec.dataFrom || []).map((f) => f.extract?.key)].filter(Boolean);
    for (const k of keys.map(String)) {
      // The environment segment is per overlay (ENVIRONMENT in sources, dev|staging|prod rendered).
      const env = k.split('/')[0];
      if (!env || !slugs.some((x) => k.startsWith(`${env}/${x}/`))) {
        errors.push(`R10 ${where(d)}: remote key ${k} is outside <env>/${slugs.join('|') || '?'}/`);
      }
    }
  }

  // The admission policy and its Deny binding.
  const vap = byKind('ValidatingAdmissionPolicy').find((d) =>
    (d.doc.spec?.matchConstraints?.resourceRules || []).some(
      (r) => (r.apiGroups || []).includes('external-secrets.io') && (r.resources || []).includes('externalsecrets') &&
        ['CREATE', 'UPDATE'].every((o) => (r.operations || []).includes(o)),
    ),
  );
  if (!vap) errors.push('R10 no ValidatingAdmissionPolicy matches CREATE/UPDATE of external-secrets.io externalsecrets');
  else {
    if (vap.doc.spec.failurePolicy !== 'Fail') errors.push(`R10 ${where(vap)}: failurePolicy must be Fail`);
    const binding = byKind('ValidatingAdmissionPolicyBinding').find((b) => b.doc.spec?.policyName === vap.doc.metadata.name);
    if (!binding || !(binding.doc.spec.validationActions || []).includes('Deny')) {
      errors.push(`R10 ${where(vap)}: needs a ValidatingAdmissionPolicyBinding with validationActions Deny`);
    }
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
    errors = [...checkMtlsModes(docs, contract), ...checkTelemetryTags(docs), ...checkZeroTrust(docs, contract)];
    console.log(`checked ${docs.length} rendered documents from ${file}`);
  } else {
    const all = loadRepoDocs();
    const deployable = all.filter((d) => DEPLOYABLE.some((p) => d.file.startsWith(p)));
    errors = [
      ...checkMtlsModes(all, contract),
      ...checkTelemetryTags(all),
      ...checkZeroTrust(deployable, contract),
      ...(await checkGenerated()),
    ];
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
