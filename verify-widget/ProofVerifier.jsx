import { useState, useCallback } from "react";
import {
  blake2b256,
  hexToBytes,
  bytesToHex,
  computeLeafHash,
  walkProof,
} from "./blake2b.js";

const API = "https://pay.frontiercompute.io";

// Styles

const s = {
  container: {
    background: "#0a0a0f",
    border: "1px solid #1a1a2e",
    borderRadius: "8px",
    padding: "32px",
    maxWidth: "760px",
    width: "100%",
    fontFamily: "'Inter', system-ui, sans-serif",
    color: "#e0e0e0",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: "6px",
  },
  title: {
    fontSize: "20px",
    fontWeight: 600,
    color: "#ffffff",
    margin: 0,
  },
  protocolTag: {
    fontSize: "11px",
    fontWeight: 600,
    color: "#4b5563",
    background: "rgba(75, 85, 99, 0.15)",
    padding: "3px 8px",
    borderRadius: "4px",
  },
  subtitle: {
    fontSize: "13px",
    color: "#6b7280",
    margin: "0 0 24px 0",
  },
  inputRow: {
    display: "flex",
    gap: "8px",
    marginBottom: "24px",
  },
  input: {
    flex: 1,
    background: "#111118",
    border: "1px solid #1a1a2e",
    borderRadius: "6px",
    padding: "10px 14px",
    color: "#ffffff",
    fontSize: "13px",
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    outline: "none",
  },
  button: {
    background: "#ffffff",
    color: "#0a0a0f",
    border: "none",
    borderRadius: "6px",
    padding: "10px 20px",
    fontSize: "13px",
    fontWeight: 600,
    cursor: "pointer",
    whiteSpace: "nowrap",
  },
  buttonOutline: {
    background: "transparent",
    color: "#9ca3af",
    border: "1px solid #1a1a2e",
    borderRadius: "6px",
    padding: "8px 16px",
    fontSize: "12px",
    fontWeight: 500,
    cursor: "pointer",
    whiteSpace: "nowrap",
  },
  error: { fontSize: "12px", color: "#ef4444", marginBottom: "16px" },
  loading: {
    textAlign: "center",
    padding: "40px 0",
    color: "#6b7280",
    fontSize: "13px",
  },

  // Result banner
  resultBanner: {
    borderRadius: "8px",
    padding: "16px 20px",
    marginBottom: "24px",
    display: "flex",
    alignItems: "center",
    gap: "12px",
    fontSize: "15px",
    fontWeight: 600,
  },
  verified: {
    background: "rgba(34, 197, 94, 0.1)",
    border: "1px solid rgba(34, 197, 94, 0.3)",
    color: "#22c55e",
  },
  failed: {
    background: "rgba(239, 68, 68, 0.1)",
    border: "1px solid rgba(239, 68, 68, 0.3)",
    color: "#ef4444",
  },

  // Proof card
  card: {
    background: "#111118",
    border: "1px solid #1a1a2e",
    borderRadius: "8px",
    padding: "24px",
    marginBottom: "16px",
  },
  sectionTitle: {
    fontSize: "11px",
    textTransform: "uppercase",
    letterSpacing: "0.06em",
    color: "#6b7280",
    fontWeight: 600,
    marginBottom: "12px",
  },
  mono: {
    fontFamily: "'JetBrains Mono', 'Fira Code', 'SF Mono', monospace",
    fontSize: "12px",
    wordBreak: "break-all",
    lineHeight: 1.6,
  },

  // Leaf verification
  leafCheck: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    marginBottom: "8px",
    fontSize: "12px",
  },
  checkIcon: {
    width: "16px",
    height: "16px",
    flexShrink: 0,
  },

  // Merkle path
  pathContainer: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "0",
    padding: "8px 0",
  },
  pathStep: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    width: "100%",
    maxWidth: "560px",
  },
  pathArrow: {
    color: "#374151",
    fontSize: "14px",
    lineHeight: 1,
    padding: "2px 0",
    userSelect: "none",
  },
  pathLabel: {
    fontSize: "9px",
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    fontWeight: 600,
    marginBottom: "3px",
  },
  pathNode: {
    borderRadius: "6px",
    padding: "6px 12px",
    fontSize: "11px",
    fontFamily: "'JetBrains Mono', monospace",
    textAlign: "center",
    maxWidth: "100%",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
    border: "1px solid",
  },
  nodeLeaf: { borderColor: "#818cf8", color: "#818cf8", background: "rgba(99,102,241,0.08)" },
  nodeSibling: { borderColor: "#374151", color: "#9ca3af", background: "rgba(55,65,81,0.15)" },
  nodeComputed: { borderColor: "#6366f1", color: "#a5b4fc", background: "rgba(99,102,241,0.06)" },
  nodeRoot: { borderColor: "#22c55e", color: "#4ade80", background: "rgba(34,197,94,0.08)" },
  nodeRootFail: { borderColor: "#ef4444", color: "#f87171", background: "rgba(239,68,68,0.08)" },

  // Pair row
  pairRow: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
    width: "100%",
    maxWidth: "560px",
    justifyContent: "center",
  },
  pairPlus: {
    color: "#4b5563",
    fontSize: "12px",
    fontWeight: 600,
    flexShrink: 0,
  },

  // Anchor
  anchorRow: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    flexWrap: "wrap",
  },
  anchorLink: {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: "12px",
    color: "#60a5fa",
    textDecoration: "none",
    wordBreak: "break-all",
  },
  anchorBlock: {
    fontSize: "12px",
    color: "#6b7280",
  },

  // Actions
  actions: {
    display: "flex",
    gap: "8px",
    marginTop: "8px",
  },

  // Event badge
  eventBadge: {
    fontSize: "10px",
    fontWeight: 700,
    padding: "3px 8px",
    borderRadius: "4px",
    letterSpacing: "0.04em",
    textTransform: "uppercase",
    background: "rgba(99,102,241,0.14)",
    color: "#818cf8",
  },

  // Info row
  infoGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "12px",
    marginBottom: "16px",
  },
  infoItem: {
    display: "flex",
    flexDirection: "column",
    gap: "2px",
  },
  infoLabel: {
    fontSize: "10px",
    color: "#6b7280",
    textTransform: "uppercase",
    letterSpacing: "0.06em",
    fontWeight: 500,
  },
  infoValue: {
    fontSize: "13px",
    fontFamily: "'JetBrains Mono', monospace",
    color: "#e0e0e0",
  },
};

function truncHash(h, n = 12) {
  if (!h || h.length <= n * 2) return h || "";
  return `${h.slice(0, n)}…${h.slice(-n)}`;
}

function CheckSVG({ ok }) {
  if (ok) {
    return (
      <svg style={s.checkIcon} viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="7" stroke="#22c55e" strokeWidth="1.5" />
        <path d="M5 8l2 2 4-4" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  return (
    <svg style={s.checkIcon} viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="7" stroke="#ef4444" strokeWidth="1.5" />
      <path d="M5.5 5.5l5 5M10.5 5.5l-5 5" stroke="#ef4444" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function SkipSVG() {
  return (
    <svg style={s.checkIcon} viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="7" stroke="#6b7280" strokeWidth="1.5" />
      <path d="M5 8h6" stroke="#6b7280" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

export default function ProofVerifier({ leafHash: propLeafHash } = {}) {
  const [inputHash, setInputHash] = useState(propLeafHash || "");
  const [bundle, setBundle] = useState(null);
  const [result, setResult] = useState(null); // { leafMatch, rootMatch, computedRoot, steps, leafRecomputed, recomputedHash }
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const verify = useCallback(async (hash) => {
    const h = (hash || inputHash).trim();
    if (!h) return;
    setLoading(true);
    setError(null);
    setBundle(null);
    setResult(null);

    try {
      const res = await fetch(`${API}/verify/${h}/proof.json`);
      if (!res.ok) {
        if (res.status === 404) throw new Error("Proof not found for this leaf hash");
        throw new Error(`HTTP ${res.status}`);
      }
      const data = await res.json();
      setBundle(data);

      // Client-side verification

      // 1. Try to recompute leaf hash
      let leafRecomputed = false;
      let leafMatch = null;
      let recomputedHash = null;

      if (data.leaf && data.leaf.wallet_hash) {
        const computed = computeLeafHash(
          data.leaf.event_type,
          data.leaf.wallet_hash,
          data.leaf.serial_number
        );
        if (computed) {
          recomputedHash = bytesToHex(computed);
          leafMatch = recomputedHash === data.leaf.hash;
          leafRecomputed = true;
        }
      }

      // 2. Walk the Merkle proof
      const { computedRoot, steps } = walkProof(data.leaf.hash, data.proof);

      // 3. Compare
      const rootMatch = computedRoot === data.root.hash;

      setResult({ leafMatch, rootMatch, computedRoot, steps, leafRecomputed, recomputedHash });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [inputHash]);

  const handleDownload = () => {
    if (!bundle) return;
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `proof-${(bundle.leaf?.hash || inputHash).slice(0, 16)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const allVerified = result && result.rootMatch && (result.leafMatch === null || result.leafMatch);

  return (
    <div style={s.container}>
      <div style={s.header}>
        <h3 style={s.title}>Proof Verifier</h3>
        {bundle && (
          <span style={s.protocolTag}>
            {bundle.protocol || "ZAP1"} v{bundle.version || "1"}
          </span>
        )}
      </div>
      <p style={s.subtitle}>
        Zero-trust in-browser Merkle proof verification. No server involved.
      </p>

      {!propLeafHash && (
        <div style={s.inputRow}>
          <input
            style={s.input}
            type="text"
            placeholder="Enter leaf hash…"
            value={inputHash}
            onChange={(e) => setInputHash(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && verify()}
            spellCheck={false}
          />
          <button
            style={{ ...s.button, opacity: inputHash.trim() ? 1 : 0.5 }}
            onClick={() => verify()}
          >
            Verify
          </button>
        </div>
      )}

      {error && <div style={s.error}>{error}</div>}
      {loading && <div style={s.loading}>Fetching and verifying proof…</div>}

      {result && bundle && (
        <>
          {/* Verdict banner */}
          <div style={{ ...s.resultBanner, ...(allVerified ? s.verified : s.failed) }}>
            {allVerified ? (
              <>
                <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
                  <circle cx="11" cy="11" r="10" stroke="currentColor" strokeWidth="2" />
                  <path d="M6 11l3 3 7-7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                VERIFIED - Proof is cryptographically valid
              </>
            ) : (
              <>
                <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
                  <circle cx="11" cy="11" r="10" stroke="currentColor" strokeWidth="2" />
                  <path d="M7 7l8 8M15 7l-8 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                </svg>
                FAILED - Proof verification did not pass
              </>
            )}
          </div>

          {/* Verification checks */}
          <div style={{ ...s.card, marginBottom: "16px" }}>
            <div style={s.sectionTitle}>Verification Checks</div>
            <div style={s.leafCheck}>
              {result.leafRecomputed ? <CheckSVG ok={result.leafMatch} /> : <SkipSVG />}
              <span style={{ color: result.leafRecomputed ? (result.leafMatch ? "#22c55e" : "#ef4444") : "#6b7280" }}>
                {result.leafRecomputed
                  ? result.leafMatch
                    ? "Leaf hash recomputed from event data - matches"
                    : "Leaf hash recomputed - MISMATCH"
                  : `Leaf recomputation skipped (${bundle.leaf.event_type} formula not implemented client-side)`}
              </span>
            </div>
            <div style={s.leafCheck}>
              <CheckSVG ok={result.rootMatch} />
              <span style={{ color: result.rootMatch ? "#22c55e" : "#ef4444" }}>
                {result.rootMatch
                  ? "Merkle path walks to root - matches"
                  : "Merkle path computed root does NOT match declared root"}
              </span>
            </div>
          </div>

          {/* Leaf info */}
          <div style={s.card}>
            <div style={s.sectionTitle}>Leaf</div>
            <div style={s.infoGrid}>
              <div style={s.infoItem}>
                <span style={s.infoLabel}>Event Type</span>
                <span style={s.eventBadge}>{bundle.leaf.event_type}</span>
              </div>
              <div style={s.infoItem}>
                <span style={s.infoLabel}>Created</span>
                <span style={{ fontSize: "12px", color: "#9ca3af" }}>
                  {bundle.leaf.created_at ? new Date(bundle.leaf.created_at).toLocaleString() : "-"}
                </span>
              </div>
              {bundle.leaf.wallet_hash && (
                <div style={{ ...s.infoItem, gridColumn: "1 / -1" }}>
                  <span style={s.infoLabel}>Wallet Hash</span>
                  <span style={{ ...s.mono, color: "#e0e0e0" }}>{bundle.leaf.wallet_hash}</span>
                </div>
              )}
            </div>
            <div style={s.infoLabel}>Leaf Hash</div>
            <div style={{ ...s.mono, color: "#818cf8", marginTop: "4px" }}>{bundle.leaf.hash}</div>
            {result.leafRecomputed && (
              <div style={{ ...s.mono, color: result.leafMatch ? "#22c55e" : "#ef4444", marginTop: "4px", fontSize: "11px" }}>
                Recomputed: {result.recomputedHash}
              </div>
            )}
          </div>

          {/* Merkle path visualization */}
          <div style={s.card}>
            <div style={s.sectionTitle}>Merkle Path ({bundle.proof.length} step{bundle.proof.length !== 1 ? "s" : ""})</div>
            <div style={s.pathContainer}>
              {/* Leaf node */}
              <div style={s.pathStep}>
                <div style={{ ...s.pathLabel, color: "#818cf8" }}>Leaf</div>
                <div style={{ ...s.pathNode, ...s.nodeLeaf }} title={bundle.leaf.hash}>
                  {truncHash(bundle.leaf.hash, 16)}
                </div>
              </div>

              {/* Each proof step */}
              {result.steps.map((step, i) => {
                const sibPos = bundle.proof[i].position;
                const sibHash = bundle.proof[i].hash;
                const isLast = i === result.steps.length - 1;
                return (
                  <div key={i} style={s.pathStep}>
                    <div style={s.pathArrow}>↓</div>
                    <div style={s.pairRow}>
                      <div
                        style={{
                          ...s.pathNode,
                          ...(sibPos === "left" ? s.nodeSibling : s.nodeComputed),
                          flex: 1,
                          minWidth: 0,
                        }}
                        title={sibPos === "left" ? sibHash : step.left}
                      >
                        <span style={{ ...s.pathLabel, color: sibPos === "left" ? "#6b7280" : "#6366f1", display: "block" }}>
                          {sibPos === "left" ? `Sibling (L)` : "Current"}
                        </span>
                        {truncHash(sibPos === "left" ? sibHash : step.left, 10)}
                      </div>
                      <span style={s.pairPlus}>+</span>
                      <div
                        style={{
                          ...s.pathNode,
                          ...(sibPos === "right" ? s.nodeSibling : s.nodeComputed),
                          flex: 1,
                          minWidth: 0,
                        }}
                        title={sibPos === "right" ? sibHash : step.right}
                      >
                        <span style={{ ...s.pathLabel, color: sibPos === "right" ? "#6b7280" : "#6366f1", display: "block" }}>
                          {sibPos === "right" ? `Sibling (R)` : "Current"}
                        </span>
                        {truncHash(sibPos === "right" ? sibHash : step.right, 10)}
                      </div>
                    </div>
                    <div style={s.pathArrow}>↓</div>
                    <div
                      style={{
                        ...s.pathNode,
                        ...(isLast
                          ? result.rootMatch ? s.nodeRoot : s.nodeRootFail
                          : s.nodeComputed),
                      }}
                      title={step.result}
                    >
                      <span
                        style={{
                          ...s.pathLabel,
                          color: isLast ? (result.rootMatch ? "#22c55e" : "#ef4444") : "#6366f1",
                          display: "block",
                        }}
                      >
                        {isLast ? "Computed Root" : `Node ${i + 1}`}
                      </span>
                      {truncHash(step.result, 16)}
                    </div>
                  </div>
                );
              })}

              {/* Declared root comparison */}
              <div style={{ marginTop: "12px", fontSize: "11px", textAlign: "center" }}>
                <span style={{ color: "#6b7280" }}>Declared root: </span>
                <span style={{ ...s.mono, color: result.rootMatch ? "#22c55e" : "#ef4444" }}>
                  {truncHash(bundle.root.hash, 16)}
                </span>
                <span style={{ color: result.rootMatch ? "#22c55e" : "#ef4444", marginLeft: "6px", fontWeight: 600 }}>
                  {result.rootMatch ? "MATCH" : "MISMATCH"}
                </span>
              </div>
            </div>
          </div>

          {/* Anchor */}
          {bundle.anchor && (
            <div style={s.card}>
              <div style={s.sectionTitle}>On-Chain Anchor</div>
              <div style={s.anchorRow}>
                <a
                  href={`https://blockchair.com/zcash/transaction/${bundle.anchor.txid}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={s.anchorLink}
                  title={bundle.anchor.txid}
                >
                  {truncHash(bundle.anchor.txid, 20)} ↗
                </a>
                {bundle.anchor.height && (
                  <span style={s.anchorBlock}>
                    Block {bundle.anchor.height.toLocaleString()}
                  </span>
                )}
              </div>
              {bundle.root.leaf_count && (
                <div style={{ fontSize: "12px", color: "#6b7280", marginTop: "8px" }}>
                  Tree contains {bundle.root.leaf_count} leaves
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          <div style={s.actions}>
            <button style={s.buttonOutline} onClick={handleDownload}>
              ↓ Download Proof Bundle
            </button>
            {bundle.verify_command && (
              <button
                style={s.buttonOutline}
                onClick={() => navigator.clipboard.writeText(bundle.verify_command)}
                title={bundle.verify_command}
              >
                ⎘ Copy CLI Command
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
