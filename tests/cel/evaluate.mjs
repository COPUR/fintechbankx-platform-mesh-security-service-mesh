// Runs tests/cel/main.go (cel-go, the CEL the kube-apiserver uses) on a
// ValidatingAdmissionPolicy spec and admission cases; see main.go for what is
// not modelled. Without Go on PATH the callers skip (reported as skipped).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { repoRoot } from '../../scripts/lib/contract.mjs';

const celDir = join(repoRoot, 'tests', 'cel');
export const goAvailable = spawnSync('go', ['version'], { encoding: 'utf8' }).status === 0;
export const skip = goAvailable ? false : 'go is not on PATH: the CEL of the admission policy was NOT evaluated';

/** Case name -> { allowed, messages }. */
export function evaluate(spec, cases) {
  const run = spawnSync('go', ['run', '.'], {
    cwd: celDir,
    input: JSON.stringify({ policy: spec, cases }),
    encoding: 'utf8',
    env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'local', GOFLAGS: '-mod=readonly' },
    timeout: 300_000,
  });
  assert.equal(run.status, 0, `cel harness failed: ${run.stderr}`);
  return Object.fromEntries(JSON.parse(run.stdout).map((r) => [r.name, r]));
}
