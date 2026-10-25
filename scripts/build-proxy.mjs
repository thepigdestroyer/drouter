#!/usr/bin/env node
/**
 * Bundles `src/proxy-cli/deroute-proxy.ts` into a self-contained single-file
 * Node 20+ ESM script at `public/downloads/deroute-proxy.mjs` and writes its
 * SHA-256 checksum in `shasum -a 256 -c` format to
 * `public/downloads/deroute-proxy.mjs.sha256`.
 */

import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const SRC_DIR = path.join(ROOT, "src");
const ENTRY_POINT = path.join(SRC_DIR, "proxy-cli", "deroute-proxy.ts");
const OUT_DIR = path.join(ROOT, "public", "downloads");
const OUT_FILE = path.join(OUT_DIR, "deroute-proxy.mjs");
const SHA256_FILE = path.join(OUT_DIR, "deroute-proxy.mjs.sha256");

export function resolveSourceCommit() {
  if (
    process.env.DEROUTE_SOURCE_COMMIT &&
    process.env.DEROUTE_SOURCE_COMMIT.trim()
  ) {
    return process.env.DEROUTE_SOURCE_COMMIT.trim();
  }
  try {
    const commit = execSync(
      "git log -n 1 --format=%h --abbrev=12 HEAD -- src/proxy-cli src/lib scripts/build-proxy.mjs package.json package-lock.json",
      {
        cwd: ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    ).trim();
    if (commit) return commit;
    return execSync("git rev-parse --short=12 HEAD", {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "unknown";
  }
}

function resolveWithExtensions(targetPath) {
  const candidates = [
    targetPath,
    `${targetPath}.ts`,
    `${targetPath}.tsx`,
    `${targetPath}.js`,
    `${targetPath}.mjs`,
    `${targetPath}.json`,
    path.join(targetPath, "index.ts"),
    path.join(targetPath, "index.js"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }
  return targetPath;
}

export async function buildProxyBundle() {
  const commit = resolveSourceCommit();

  fs.mkdirSync(OUT_DIR, { recursive: true });

  const aliasPlugin = {
    name: "deroute-alias",
    setup(build) {
      build.onResolve({ filter: /^@\// }, (args) => {
        const subPath = args.path.slice(2);
        const resolved = resolveWithExtensions(path.join(SRC_DIR, subPath));
        return { path: resolved };
      });

      build.onResolve({ filter: /^viem\/chains$/ }, () => ({
        path: "viem-chains-stub",
        namespace: "deroute-stub",
      }));

      build.onLoad(
        { filter: /^viem-chains-stub$/, namespace: "deroute-stub" },
        () => ({
          contents:
            'export const arcTestnet = { id: 5042002, rpcUrls: { default: { http: ["https://rpc.testnet.arc.io"] } } };',
          loader: "js",
        }),
      );
    },
  };

  const bannerLines = [
    "#!/usr/bin/env node",
    `// deRoute Private Local Proxy (source commit: ${commit})`,
    'import { createRequire as __derouteCreateRequire } from "node:module";',
    "const require = __derouteCreateRequire(import.meta.url);",
  ];

  await esbuild.build({
    entryPoints: [ENTRY_POINT],
    outfile: OUT_FILE,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    sourcemap: false,
    minify: false,
    legalComments: "none",
    banner: {
      js: bannerLines.join("\n"),
    },
    plugins: [aliasPlugin],
    logLevel: "silent",
  });

  fs.chmodSync(OUT_FILE, 0o755);

  const fileBytes = fs.readFileSync(OUT_FILE);
  const sha256Hex = crypto
    .createHash("sha256")
    .update(fileBytes)
    .digest("hex")
    .toLowerCase();

  const sha256Line = `${sha256Hex}  deroute-proxy.mjs\n`;
  fs.writeFileSync(SHA256_FILE, sha256Line, "utf8");

  return {
    outFile: OUT_FILE,
    sha256File: SHA256_FILE,
    sha256: sha256Hex,
    sizeBytes: fileBytes.byteLength,
    commit,
  };
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  buildProxyBundle()
    .then((res) => {
      console.log(
        `[build:proxy] Built public/downloads/deroute-proxy.mjs (${res.sizeBytes} bytes, commit ${res.commit})`,
      );
      console.log(`[build:proxy] SHA-256: ${res.sha256}  deroute-proxy.mjs`);
    })
    .catch((err) => {
      console.error(
        "[build:proxy] Build failed:",
        err instanceof Error ? err.message : String(err),
      );
      process.exit(1);
    });
}
