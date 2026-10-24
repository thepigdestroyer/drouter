import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import {
  buildAmdKdsVcekUrl,
  buildArcExplorerAddressUrl,
  buildArcExplorerTxUrl,
  buildGitHubDeploymentJsonUrl,
  buildGitHubHashAssetUrl,
  buildGitHubReleaseTagUrl,
  buildRekorApiEntryByIndexUrl,
  buildRekorApiEntryByUuidUrl,
  buildSigstoreSearchByHashUrl,
  buildSigstoreSearchByLogIndexUrl,
  extractAttestationRekorEntry,
  isDeepAttestationBundle,
  lookupRekorEntryByDigest,
  resolveActiveRegistryNode,
  resolveModelDeploymentProvenance,
} from "@/components/inspector/live-records";
import {
  buildTerminalSnippets,
  normalizeBaseUrl,
  PRODUCTION_BASE_URL,
  REPO_CLONE_URL,
  resolveCliUpstreamUrl,
} from "@/components/inspector/terminal-snippets";
import {
  MODAL_PLAIN_SUMMARY,
  resolveFocusTrapTarget,
  resolveNextTabId,
} from "@/components/modal/modal-a11y";
import { RecordInspectorModal } from "@/components/record-inspector-modal";
import { TerminalModal } from "@/components/terminal-modal";

describe("Record Inspector live URL & record helpers", () => {
  it("builds exact GitHub release tag, tinfoil-deployment.json, and tinfoil.hash URLs", () => {
    expect(
      buildGitHubReleaseTagUrl(
        "tinfoilsh/confidential-model-router",
        "v0.0.167",
      ),
    ).toBe(
      "https://github.com/tinfoilsh/confidential-model-router/releases/tag/v0.0.167",
    );
    expect(
      buildGitHubDeploymentJsonUrl(
        "tinfoilsh/confidential-deepseek-v4-1-flash",
        "v0.0.8+b200",
      ),
    ).toBe(
      "https://github.com/tinfoilsh/confidential-deepseek-v4-1-flash/releases/download/v0.0.8%2Bb200/tinfoil-deployment.json",
    );
    expect(
      buildGitHubHashAssetUrl("tinfoilsh/confidential-kimi-k3", "v0.0.15"),
    ).toBe(
      "https://github.com/tinfoilsh/confidential-kimi-k3/releases/download/v0.0.15/tinfoil.hash",
    );
  });

  it("builds exact AMD KDS VCEK URL from reported chip ID and TCB", () => {
    const chipId =
      "cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8ef7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e";
    const url = buildAmdKdsVcekUrl("Genoa", chipId, {
      bootloader: 10,
      tee: 0,
      snp: 27,
      microcode: 88,
    });
    expect(url).toBe(
      `https://kdsintf.amd.com/vcek/v1/Genoa/${chipId}?blSPL=10&teeSPL=0&snpSPL=27&ucodeSPL=88`,
    );
    expect(buildAmdKdsVcekUrl(undefined, chipId, undefined)).toBeNull();
  });

  it("builds Arc explorer address and transaction URLs from live registry response", () => {
    expect(
      buildArcExplorerAddressUrl(
        "https://explorer.testnet.arc.io/",
        "0xbc8085c2b6fe6e0db05f169925c0b841828f4481",
      ),
    ).toBe(
      "https://explorer.testnet.arc.io/address/0xbc8085c2b6fe6e0db05f169925c0b841828f4481",
    );
    expect(
      buildArcExplorerTxUrl(
        "https://explorer.testnet.arc.io",
        "0x1234567890abcdef",
      ),
    ).toBe("https://explorer.testnet.arc.io/tx/0x1234567890abcdef");
    expect(
      buildArcExplorerTxUrl(
        "https://explorer.testnet.arc.io",
        "https://explorer.testnet.arc.io/tx/0xdeadbeef",
      ),
    ).toBe("https://explorer.testnet.arc.io/tx/0xdeadbeef");
  });

  it("extracts Sigstore Rekor logIndex from /api/relay/attestation bundle", () => {
    const extracted = extractAttestationRekorEntry({
      domain: "inference.tinfoil.sh",
      digest:
        "5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
      sigstoreBundle: {
        verificationMaterial: {
          tlogEntries: [
            {
              logIndex: "3406368420",
              integratedTime: "1792717164",
              inclusionProof: {
                logIndex: "3284464158",
                rootHash: "dphj2hzPqcg665T/lMcsgy8UPCi+LUvI0uw5CqUYCR8=",
                treeSize: "3284464186",
              },
            },
          ],
        },
      },
    });
    expect(extracted).not.toBeNull();
    expect(extracted?.logIndex).toBe("3406368420");
    expect(extracted?.searchUrl).toBe(
      buildSigstoreSearchByLogIndexUrl("3406368420"),
    );
    expect(extracted?.apiUrl).toBe(buildRekorApiEntryByIndexUrl("3406368420"));
    expect(
      buildSigstoreSearchByHashUrl(
        "sha256:5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
      ),
    ).toBe(
      "https://search.sigstore.dev/?hash=5233a27f1468f474d27c103e06c1a7a607e6a722ff4f9299ddf4e32fa87f201e",
    );
  });

  it("resolves Rekor entry by digest and model deployment provenance via mocked fetch", async () => {
    const digest =
      "c35a71bc3e26691ed650e5f480fd317cdfe00e5442f45426d110bb0e665e1c1d";
    const uuid =
      "108e9186e8c5677a24f1f86ad61b5bfd02172e439d5fe9e41aad4c1c7214f8030e92d8bb2b0062bd";

    const mockFetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("api.github.com/repos/tinfoilsh/confidential-kimi-k3")) {
        return new Response(
          JSON.stringify({
            assets: [
              {
                name: "tinfoil-deployment.json",
                digest: `sha256:${digest}`,
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("rekor.sigstore.dev/api/v1/index/retrieve")) {
        return new Response(JSON.stringify([uuid]), { status: 200 });
      }
      if (url === buildRekorApiEntryByUuidUrl(uuid)) {
        return new Response(
          JSON.stringify({
            [uuid]: { logIndex: 3377370377, integratedTime: 1792647567 },
          }),
          { status: 200 },
        );
      }
      return new Response(null, { status: 404 });
    }) as unknown as typeof fetch;

    const prov = await resolveModelDeploymentProvenance(
      { repo: "tinfoilsh/confidential-kimi-k3", tag: "v0.0.15" },
      mockFetch,
    );
    expect(prov.sha256Digest).toBe(digest);
    expect(prov.rekor?.uuid).toBe(uuid);
    expect(prov.rekor?.logIndex).toBe(3377370377);
    expect(prov.rekor?.searchUrl).toBe(
      "https://search.sigstore.dev/?logIndex=3377370377",
    );

    const invalid = await lookupRekorEntryByDigest("not-a-hex-digest", mockFetch);
    expect(invalid).toBeNull();
  });

  it("matches active node against live /api/registry snapshot and checks bundle type guard", () => {
    const resolved = resolveActiveRegistryNode(null, {
      source: "arc",
      address: "0xbc8085c2b6fe6e0db05f169925c0b841828f4481",
      nodes: [
        {
          id: "0x2696913aef54b88e8338ba4a362549e7c70465faa781aaa12240d20a247df29a",
          kind: "tinfoil",
          name: "Tinfoil confidential router",
          endpoint: "inference.tinfoil.sh",
          measurement: "0x0cdd",
          operator: "0x7a5cCE3386c4D572A9C2891103250fA878838cfB",
          stake: "0.01",
          status: "active",
          region: "us",
          registeredAt: 1,
          lastVerifiedAt: 2,
          lastVerifiedOk: true,
        },
      ],
    });
    expect(resolved?.operator).toBe(
      "0x7a5cCE3386c4D572A9C2891103250fA878838cfB",
    );
    expect(isDeepAttestationBundle({ routerHost: "x", models: {} })).toBe(true);
    expect(isDeepAttestationBundle(null)).toBe(false);
  });
});

describe("Terminal modal verbatim commands & snippets", () => {
  it("normalizes base URLs and upgrades plain HTTP localhost to HTTPS for CLI upstream", () => {
    expect(normalizeBaseUrl("https://drouter-demo.vercel.app/")).toBe(
      PRODUCTION_BASE_URL,
    );
    expect(resolveCliUpstreamUrl("http://localhost:3000")).toBe(
      PRODUCTION_BASE_URL,
    );
    expect(resolveCliUpstreamUrl("https://custom.drouter.example")).toBe(
      "https://custom.drouter.example",
    );
  });

  it("builds verbatim commands that work without an npm CLI package and uses deRoute user-visible branding", () => {
    const snippets = buildTerminalSnippets(
      "http://localhost:3000",
      "kimi-k3",
    );
    expect(snippets.curlSnippet).toContain(
      `git clone ${REPO_CLONE_URL} && cd drouter && npm ci && node scripts/drouter-cli.mjs verify`,
    );
    expect(snippets.curlSnippet).toContain(
      `curl ${PRODUCTION_BASE_URL}/v1/models`,
    );
    expect(snippets.sdkSnippet).toContain(
      `baseURL: "${PRODUCTION_BASE_URL}/v1"`,
    );
    expect(snippets.sdkSnippet).toContain("x-drouter-credit");
    expect(snippets.sdkSnippet).toContain("deRoute accepts any value");
    expect(snippets.sdkSnippet).not.toContain("dRouter");
    const parsedOpencode = JSON.parse(snippets.opencodeConfig);
    expect(
      parsedOpencode.provider["drouter-confidential"].options.baseURL,
    ).toBe(`${PRODUCTION_BASE_URL}/v1`);
    expect(
      parsedOpencode.provider["drouter-confidential"].options.apiKey,
    ).toBe("any-value");
    expect(parsedOpencode.provider["drouter-confidential"].name).toBe(
      "deRoute Confidential TEE (Attested)",
    );
  });
});

describe("Shared InkModal accessibility, layout, summary, and deRoute branding", () => {
  it("exposes exact verbatim plain-language summary text", () => {
    expect(MODAL_PLAIN_SUMMARY).toBe(
      "What this shows: the sealed computer's signed proof that it runs the published code. You do not need to read this; it is here so experts can check our work.",
    );
  });

  it("traps focus at first and last focusable elements on Tab and Shift+Tab", () => {
    const items = ["close-btn", "tab-1", "tab-2", "copy-btn"] as const;
    // Forward Tab from last item wraps to first
    expect(resolveFocusTrapTarget(items, "copy-btn", false)).toBe("close-btn");
    // Forward Tab when focus is outside modal wraps to first
    expect(resolveFocusTrapTarget(items, null, false)).toBe("close-btn");
    // Forward Tab from interior item allows native Tab (returns null)
    expect(resolveFocusTrapTarget(items, "tab-1", false)).toBeNull();
    // Shift+Tab from first item wraps to last
    expect(resolveFocusTrapTarget(items, "close-btn", true)).toBe("copy-btn");
    // Shift+Tab when focus is outside modal wraps to last
    expect(resolveFocusTrapTarget(items, null, true)).toBe("copy-btn");
    // Shift+Tab from interior item allows native Shift+Tab (returns null)
    expect(resolveFocusTrapTarget(items, "tab-2", true)).toBeNull();
  });

  it("computes keyboard tablist navigation for ArrowRight, ArrowLeft, Home, and End", () => {
    const tabs = ["overview", "silicon", "gpu", "provenance", "onchain", "privacy"] as const;
    expect(resolveNextTabId(tabs, "overview", "ArrowRight")).toBe("silicon");
    expect(resolveNextTabId(tabs, "privacy", "ArrowRight")).toBe("overview");
    expect(resolveNextTabId(tabs, "overview", "ArrowLeft")).toBe("privacy");
    expect(resolveNextTabId(tabs, "gpu", "Home")).toBe("overview");
    expect(resolveNextTabId(tabs, "gpu", "End")).toBe("privacy");
    expect(resolveNextTabId(tabs, "gpu", "Enter")).toBeNull();
  });

  it("renders RecordInspectorModal and TerminalModal with non-shrinking header, non-clipping tablist, plain summary, reduced-motion bloom CSS, and deRoute branding", () => {
    const inspectorHtml = renderToStaticMarkup(
      React.createElement(RecordInspectorModal, {
        open: true,
        initialTab: "privacy",
        onClose: () => {},
        node: null,
        model: "kimi-k3",
        checks: [],
        evidence: {},
      }),
    );

    expect(inspectorHtml).toContain('role="dialog"');
    expect(inspectorHtml).toContain('aria-modal="true"');
    expect(inspectorHtml).toContain('data-testid="ink-modal-header"');
    expect(inspectorHtml).toContain('data-testid="ink-modal-tabbar"');
    expect(inspectorHtml).toContain('role="tablist"');
    expect(inspectorHtml).toContain('data-testid="ink-modal-body"');
    expect(inspectorHtml).toContain(
      "What this shows: the sealed computer&#x27;s signed proof that it runs the published code. You do not need to read this; it is here so experts can check our work.",
    );
    expect(inspectorHtml).toContain("prefers-reduced-motion: reduce");
    expect(inspectorHtml).toContain("The deRoute relay only forwards ciphertext.");
    expect(inspectorHtml).not.toContain("dRouter");

    const terminalHtml = renderToStaticMarkup(
      React.createElement(TerminalModal, {
        open: true,
        onClose: () => {},
      }),
    );

    expect(terminalHtml).toContain("Use deRoute from Terminal, OpenCode, or Cursor");
    expect(terminalHtml).toContain(
      "What this shows: the sealed computer&#x27;s signed proof that it runs the published code. You do not need to read this; it is here so experts can check our work.",
    );
    expect(terminalHtml).toContain("https://drouter-demo.vercel.app/v1");
    expect(terminalHtml).toContain("scripts/drouter-cli.mjs verify");
    expect(terminalHtml).not.toContain("dRouter");
  });
});
