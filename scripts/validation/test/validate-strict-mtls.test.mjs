import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { validateStrictMtls } from "../validate-strict-mtls.mjs";

function withFixtureDir(run) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "strict-mtls-test-"));
  try {
    run(tempDir);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

test("passes when mesh strict baseline and internal destination rule are valid", () => {
  withFixtureDir((dir) => {
    const policyPath = path.join(dir, "mtls.yaml");
    fs.writeFileSync(
      policyPath,
      `apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: mesh-default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: service-dr
  namespace: banking
spec:
  host: payment-service.banking.svc.cluster.local
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
`,
      "utf8"
    );

    const result = validateStrictMtls([dir], { requireBaseline: true });
    assert.equal(result.violations.length, 0);
    assert.equal(result.hasMeshStrictBaseline, true);
  });
});

test("fails on permissive peer authentication mode", () => {
  withFixtureDir((dir) => {
    const policyPath = path.join(dir, "mtls.yaml");
    fs.writeFileSync(
      policyPath,
      `apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: mesh-default
  namespace: istio-system
spec:
  mtls:
    mode: PERMISSIVE
`,
      "utf8"
    );

    const result = validateStrictMtls([dir], { requireBaseline: true });
    assert.ok(result.violations.some((v) => v.message.includes("spec.mtls.mode=STRICT")));
  });
});

test("fails on non-ISTIO_MUTUAL internal destination rule", () => {
  withFixtureDir((dir) => {
    const policyPath = path.join(dir, "dr.yaml");
    fs.writeFileSync(
      policyPath,
      `apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: service-dr
  namespace: banking
spec:
  host: customer-service.banking.svc.cluster.local
  trafficPolicy:
    tls:
      mode: DISABLE
`,
      "utf8"
    );

    const result = validateStrictMtls([dir], { requireBaseline: false });
    assert.ok(result.violations.some((v) => v.message.includes("ISTIO_MUTUAL")));
  });
});

test("fails when baseline is required but missing", () => {
  withFixtureDir((dir) => {
    const result = validateStrictMtls([dir], { requireBaseline: true });
    assert.ok(result.violations.some((v) => v.message.includes("Missing mesh baseline")));
  });
});
