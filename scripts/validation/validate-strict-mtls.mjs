#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const __filename = fileURLToPath(import.meta.url);

function isYamlFile(filePath) {
  return filePath.endsWith(".yaml") || filePath.endsWith(".yml");
}

function walkFiles(startPath, files = []) {
  if (!fs.existsSync(startPath)) {
    return files;
  }
  const stat = fs.statSync(startPath);
  if (stat.isFile()) {
    if (isYamlFile(startPath)) {
      files.push(startPath);
    }
    return files;
  }
  for (const entry of fs.readdirSync(startPath)) {
    walkFiles(path.join(startPath, entry), files);
  }
  return files;
}

function toMode(value) {
  if (!value || typeof value !== "string") {
    return "";
  }
  return value.trim().toUpperCase();
}

function isInternalServiceHost(host) {
  if (typeof host !== "string") {
    return false;
  }
  return host.includes(".svc.cluster.local");
}

export function validateStrictMtls(pathsToScan, options = {}) {
  const requireBaseline = options.requireBaseline === true;
  const violations = [];
  let hasMeshStrictBaseline = false;
  let scannedResourceCount = 0;

  const files = [...new Set(pathsToScan.flatMap((p) => walkFiles(p)))];
  for (const filePath of files) {
    const raw = fs.readFileSync(filePath, "utf8");
    const docs = YAML.parseAllDocuments(raw);
    for (const document of docs) {
      if (document.errors.length > 0) {
        violations.push({
          filePath,
          message: `YAML parse error: ${document.errors[0].message}`
        });
        continue;
      }

      const resource = document.toJSON();
      if (!resource || typeof resource !== "object") {
        continue;
      }
      scannedResourceCount += 1;

      const kind = resource.kind;
      const metadata = resource.metadata || {};
      const spec = resource.spec || {};
      const name = metadata.name || "<unknown>";
      const namespace = metadata.namespace || "default";

      if (kind === "PeerAuthentication") {
        const mtlsMode = toMode(spec?.mtls?.mode);
        if (mtlsMode !== "STRICT") {
          violations.push({
            filePath,
            message: `PeerAuthentication ${namespace}/${name} must set spec.mtls.mode=STRICT (found: ${mtlsMode || "unset"})`
          });
        }

        if (namespace === "istio-system" && !spec?.selector && mtlsMode === "STRICT") {
          hasMeshStrictBaseline = true;
        }

        const portLevelMtls = spec?.portLevelMtls || {};
        for (const [port, portConfig] of Object.entries(portLevelMtls)) {
          const portMode = toMode(portConfig?.mode);
          if (portMode !== "STRICT") {
            violations.push({
              filePath,
              message: `PeerAuthentication ${namespace}/${name} port ${port} must set STRICT (found: ${portMode || "unset"})`
            });
          }
        }
      }

      if (kind === "DestinationRule") {
        const host = spec?.host || "";
        if (!isInternalServiceHost(host)) {
          continue;
        }
        const tlsMode = toMode(spec?.trafficPolicy?.tls?.mode);
        if (tlsMode !== "ISTIO_MUTUAL") {
          violations.push({
            filePath,
            message: `DestinationRule ${namespace}/${name} for internal host ${host} must set trafficPolicy.tls.mode=ISTIO_MUTUAL (found: ${tlsMode || "unset"})`
          });
        }
      }
    }
  }

  if (requireBaseline && !hasMeshStrictBaseline) {
    violations.push({
      filePath: "<global>",
      message: "Missing mesh baseline: require PeerAuthentication in istio-system without selector and with spec.mtls.mode=STRICT"
    });
  }

  return {
    filesScanned: files.length,
    resourcesScanned: scannedResourceCount,
    hasMeshStrictBaseline,
    violations
  };
}

function parseArgs(argv) {
  const result = {
    paths: [],
    requireBaseline: false
  };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--path") {
      result.paths.push(argv[i + 1]);
      i += 1;
      continue;
    }
    if (token === "--require-baseline") {
      result.requireBaseline = true;
      continue;
    }
  }
  if (result.paths.length === 0) {
    result.paths = ["k8s", "security"];
  }
  return result;
}

function runCli() {
  const args = parseArgs(process.argv.slice(2));
  const absolutePaths = args.paths.map((p) => path.resolve(process.cwd(), p));
  const result = validateStrictMtls(absolutePaths, {
    requireBaseline: args.requireBaseline
  });

  const summary = `strict-mtls validation: files=${result.filesScanned}, resources=${result.resourcesScanned}, violations=${result.violations.length}`;
  if (result.violations.length > 0) {
    console.error(summary);
    for (const violation of result.violations) {
      console.error(`- ${violation.filePath}: ${violation.message}`);
    }
    process.exit(1);
  }

  if (result.filesScanned === 0) {
    console.warn(`${summary} (no YAML policy files found in provided paths)`);
  } else {
    console.log(summary);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  runCli();
}
