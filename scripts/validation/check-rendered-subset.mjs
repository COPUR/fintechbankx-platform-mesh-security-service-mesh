// Checks that every document of a rendered subset (the pre-Istio platform PKI,
// deploy/kustomize/platform-pki/<env>) appears identically in a rendered
// superset (the mesh overlay overlays/<env>). install-mesh.sh server-side
// applies both with the same field manager, so any difference would be
// flipped back and forth on every install.
//
//   node scripts/validation/check-rendered-subset.mjs <subset.yaml> <superset.yaml>
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { parseAllDocuments } from 'yaml';

const [subsetFile, supersetFile] = process.argv.slice(2);
if (!subsetFile || !supersetFile) {
  console.error('usage: check-rendered-subset.mjs <subset.yaml> <superset.yaml>');
  process.exit(2);
}

const load = (file) =>
  parseAllDocuments(readFileSync(file, 'utf8'))
    .map((d) => d.toJS())
    .filter((d) => d && typeof d === 'object');
const id = (d) => `${d.apiVersion}/${d.kind}/${d.metadata?.namespace ?? ''}/${d.metadata?.name}`;

const superset = new Map(load(supersetFile).map((d) => [id(d), d]));
const subset = load(subsetFile);
const problems = [];
for (const doc of subset) {
  const other = superset.get(id(doc));
  if (!other) problems.push(`${id(doc)}: not in ${supersetFile}`);
  else if (!isDeepStrictEqual(doc, other)) problems.push(`${id(doc)}: differs from ${supersetFile}`);
}
if (subset.length === 0) problems.push(`${subsetFile}: no documents`);
if (problems.length) {
  for (const p of problems) console.error(p);
  process.exit(1);
}
console.log(`${subset.length} documents of ${subsetFile} identical in ${supersetFile}`);
