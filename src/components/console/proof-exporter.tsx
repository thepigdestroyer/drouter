"use client";

import { useState } from "react";
import {
  buildProofBundle,
  downloadForensicProofBundle,
  verifyForensicProofBundleOffline,
  type BuildSessionProofBundleInput,
  type ForensicProofBundle,
  type ForensicProofVerificationResult,
} from "@/lib/forensics";
import { getCurrentVaultSession } from "@/lib/auth/vault";
import { TechDetails } from "@/components/ink/tech-details";

export interface ExportedSessionProof {
  bundle: ForensicProofBundle;
  verification: ForensicProofVerificationResult;
  filename: string;
}

/**
 * Builds, verifies offline, and triggers download of a `.drouter-proof.json` bundle
 * for the current or most recent session using `@/lib/forensics`.
 */
export function exportSessionProof(
  input: BuildSessionProofBundleInput,
  opts?: { triggerDownload?: boolean },
): ExportedSessionProof {
  if (opts?.triggerDownload === false) {
    const bundle = buildProofBundle(input);
    const vaultSession = getCurrentVaultSession();
    const verification = verifyForensicProofBundleOffline(bundle, {
      expectedClientPublicKeyHex: vaultSession?.ed25519PublicKeyHex,
      expectedPopSignerPublicKeyHex: bundle.popReceipt?.signerPublicKey,
    });
    const safeNodeSlug =
      bundle.nodeId.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 16) || "session";
    const filename = `drouter-proof-${safeNodeSlug}-${bundle.createdAt}.drouter-proof.json`;
    return { bundle, verification, filename };
  }
  return downloadForensicProofBundle(input);
}

export interface ForensicProofCardProps {
  exportedProof: ExportedSessionProof;
  onDismiss: () => void;
  onRedownload: () => void;
}

export function ForensicProofCard({
  exportedProof,
  onDismiss,
  onRedownload,
}: ForensicProofCardProps) {
  const { bundle, verification, filename } = exportedProof;
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  const handleCopyCmd = async () => {
    try {
      await navigator.clipboard.writeText(bundle.cliVerifyOneLiner);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    } catch {
      setCopiedCmd(false);
    }
  };

  const handleCopyJson = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(bundle, null, 2));
      setCopiedJson(true);
      setTimeout(() => setCopiedJson(false), 2000);
    } catch {
      setCopiedJson(false);
    }
  };

  return (
    <div className="ep-card space-y-3 p-4 text-xs text-ink">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="ep-label">deRoute Proof Receipt</span>
          {verification.valid ? (
            <span className="ep-pass">Verified on your device</span>
          ) : (
            <span className="ep-fail">Check incomplete</span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onRedownload}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            Download proof file
          </button>
          <button
            type="button"
            onClick={() => void handleCopyJson()}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            {copiedJson ? "Copied proof" : "Copy proof"}
          </button>
          <button
            type="button"
            onClick={onDismiss}
            className="ep-btn-ghost px-2.5 py-1 text-xs"
          >
            Close
          </button>
        </div>
      </div>

      <p className="text-xs text-ink-2">
        This receipt proves that your browser checked the seal on the computer
        before sending your messages. You can keep it or share it with anyone to
        verify offline.
      </p>

      {!verification.valid && verification.reasons.length > 0 && (
        <div className="rounded border border-accent bg-accent-soft px-3 py-2 text-xs text-accent">
          Some parts of this proof receipt did not pass local verification. Open
          technical details below to inspect the exact check notes.
        </div>
      )}

      <TechDetails label="Show technical details">
        <div className="mt-2 space-y-3">
          {!verification.valid && verification.reasons.length > 0 && (
            <div className="ep-inset p-2.5 font-mono text-[11px] text-accent">
              {verification.reasons.join(" · ")}
            </div>
          )}
          <dl className="divide-y divide-rule border-t border-b border-rule text-xs">
            <div className="grid grid-cols-1 gap-1 py-1.5 sm:grid-cols-[11rem_1fr] sm:gap-3">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-3">
                File name
              </dt>
              <dd className="ep-mono">{filename}</dd>
            </div>
            <div className="grid grid-cols-1 gap-1 py-1.5 sm:grid-cols-[11rem_1fr] sm:gap-3">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-3">
                Bundle SHA-256
              </dt>
              <dd className="ep-mono">{bundle.bundleDigestHex}</dd>
            </div>
            <div className="grid grid-cols-1 gap-1 py-1.5 sm:grid-cols-[11rem_1fr] sm:gap-3">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-3">
                Client Ed25519 key
              </dt>
              <dd className="ep-mono">
                {bundle.clientPublicKeyHex}{" "}
                {verification.originVerified
                  ? "(bound to your unlocked account)"
                  : "(temporary session key)"}
              </dd>
            </div>
            <div className="grid grid-cols-1 gap-1 py-1.5 sm:grid-cols-[11rem_1fr] sm:gap-3">
              <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-3">
                Client signature
              </dt>
              <dd className="ep-mono">{bundle.clientSignatureHex}</dd>
            </div>
          </dl>

          <div className="ep-inset p-2.5 space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <span className="ep-label">
                Standalone Node.js offline verifier
              </span>
              <button
                type="button"
                onClick={() => void handleCopyCmd()}
                className="ep-btn-ghost px-2 py-0.5 text-[11px]"
              >
                {copiedCmd ? "Copied command" : "Copy command"}
              </button>
            </div>
            <pre className="ep-mono overflow-x-auto whitespace-pre-wrap text-[11px]">
              {bundle.cliVerifyOneLiner}
            </pre>
          </div>
        </div>
      </TechDetails>
    </div>
  );
}
