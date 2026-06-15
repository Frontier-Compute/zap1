# Sovereign Agent Attestation

Status: Partially implemented  
Date: 2026-04-01  
Depends on: Orchard shielded pool, ZAP1 v3.0.0

## Problem

When an autonomous agent operates through an Orchard shielded wallet, its financial activity is private. This is the correct default. But the agent's principal (the human or system that deployed it) and external verifiers (counterparties, auditors, protocols) sometimes need to know what the agent did without seeing everything it spent.

There is no standard way for an autonomous agent to:
- Commit to a policy before acting
- Leave checkable evidence for disclosed actions after acting
- Build a verifiable track record from shielded operations
- Present behavioral credentials to external systems

## Approach

ZAP1 attestation events for agent lifecycle operations. The same hash-and-Merkle-and-anchor mechanism used for lifecycle events, governance, ZSA attestation, and mining pool operations. No protocol changes. No new cryptographic primitives. Event types in the 0x40-0x4F range following the existing pattern.

The agent's wallet stays shielded. The attestation layer commits bounded claims
about what the agent did without revealing what it spent.

## Architecture

```
Agent principal (human or system)
    |
    v
Agent runtime (LLM + tools + policy engine)
    |
    +-- Orchard wallet (shielded, private)
    |     Financial activity is invisible
    |
    +-- ZAP1 attestation (public, verifiable)
          Every action committed to Merkle tree
          Roots anchored to Zcash
          Proofs exportable, cross-chain verifiable
```

The wallet and the attestation layer are independent. The wallet handles value. The attestation layer handles proof. A verifier checks the attestation without seeing the wallet.

## Policy Commitment

An agent commits its decision rules before acting. The policy is a set of constraints: spending limits, approved counterparty hashes, model version, action whitelist. The hash of the policy is committed to the Merkle tree via AGENT_POLICY.

After the agent acts, anyone with the policy preimage and disclosed action
preimages can verify:
1. The committed policy hash matches the disclosed rules
2. The disclosed action receipts (AGENT_ACTION, AGENT_PAYMENT, AGENT_DECISION) are consistent with the rules
3. Any divergence between disclosed receipts and committed policy can be checked

ZAP1 inclusion proofs do not prove that every real-world action was captured, and
they do not prove model or agent correctness. They prove that specific disclosed
claims match committed leaves under an anchored root.

This is structurally the same pattern as policy commitment in shielded voting systems, where a vote weight and choice are committed before the tally. The domain differs (agent behavior vs governance) but the commitment model is identical.

## Event Types (0x40-0x4F)

| Type | Name | Trigger |
|------|------|---------|
| `0x40` | `AGENT_REGISTER` | Agent identity committed (agent ID + public key hash + model hash + initial policy hash) |
| `0x41` | `AGENT_POLICY` | Policy rules updated (new version + rules hash) |
| `0x42` | `AGENT_ACTION` | Agent performed a tool call or operation (action type + input/output hashes) |
| `0x43` | `AGENT_PAYMENT` | Agent sent or received a payment (payment hash + counterparty hash) |
| `0x44` | `AGENT_DECISION` | Agent made a decision with context (context hash + decision hash) |
| `0x45` | `AGENT_CHECKPOINT` | Agent state snapshot for recovery or audit (state hash + epoch) |
| `0x46` | `AGENT_DELEGATE` | Agent delegated authority to a sub-agent (delegate ID + scope hash) |
| `0x47` | `AGENT_REVOKE` | Delegation revoked (delegate ID + reason hash) |
| `0x48` | `AGENT_INFERENCE` | Model inference result committed (model hash + input/output hashes + proof commitment) |
| `0x49` | `AGENT_AUDIT` | Periodic behavior audit root (audit tree root + period) |

Types `0x4A`-`0x4F` reserved for future agent operations.

## Hash Constructions

All hashes use BLAKE2b-256 with `NordicShield_` personalization. Variable-length fields are length-prefixed with 2-byte big-endian length. Fixed-size hashes (32 bytes) and integers are not length-prefixed.

```text
AGENT_REGISTER   = BLAKE2b_32(0x40 || len(agent_id) || agent_id || pubkey_hash || model_hash || policy_hash)
AGENT_POLICY     = BLAKE2b_32(0x41 || len(agent_id) || agent_id || policy_version_be || rules_hash)
AGENT_ACTION     = BLAKE2b_32(0x42 || len(agent_id) || agent_id || len(action_type) || action_type || input_hash || output_hash)
AGENT_PAYMENT    = BLAKE2b_32(0x43 || len(agent_id) || agent_id || payment_hash || counterparty_hash)
AGENT_DECISION   = BLAKE2b_32(0x44 || len(agent_id) || agent_id || context_hash || decision_hash)
AGENT_CHECKPOINT = BLAKE2b_32(0x45 || len(agent_id) || agent_id || state_hash || epoch_be)
AGENT_DELEGATE   = BLAKE2b_32(0x46 || len(agent_id) || agent_id || len(delegate_id) || delegate_id || scope_hash)
AGENT_REVOKE     = BLAKE2b_32(0x47 || len(agent_id) || agent_id || len(delegate_id) || delegate_id || reason_hash)
AGENT_INFERENCE  = BLAKE2b_32(0x48 || len(agent_id) || agent_id || model_hash || input_hash || output_hash || proof_commitment)
AGENT_AUDIT      = BLAKE2b_32(0x49 || len(agent_id) || agent_id || audit_root || period_be)
```

Fields:
- `agent_id` - operator-assigned agent identifier (hashed, not raw)
- `pubkey_hash` - 32-byte hash of the agent's public key (binds identity to a signing key)
- `model_hash` - 32-byte hash of the model binary, weights, or version identifier
- `policy_hash` / `rules_hash` - 32-byte hash of the policy document or constraint set
- `input_hash` / `output_hash` - 32-byte hashes of action inputs and outputs
- `context_hash` - 32-byte hash of the decision context (prompt, state, environment)
- `decision_hash` - 32-byte hash of the decision output
- `payment_hash` - 32-byte hash of payment metadata (amount is hashed, not revealed)
- `counterparty_hash` - 32-byte hash of the counterparty identifier
- `state_hash` - 32-byte hash of the agent's full state at checkpoint time
- `scope_hash` - 32-byte hash of the delegation scope (what the sub-agent can do)
- `reason_hash` - 32-byte hash of the revocation reason
- `proof_commitment` - 32-byte commitment to an external proof (STARK, SNARK, or other)
- `audit_root` - 32-byte Merkle root of the agent's internal audit tree
- `policy_version_be` - 4-byte big-endian policy version counter
- `epoch_be` / `period_be` - 4-byte big-endian epoch or period identifier

## Selective Disclosure

Agent attestation follows the same selective disclosure model as revenue proofs (see REVENUE_PROOFS.md).

An agent supports the claim "I took action X at time Y" by presenting the leaf
hash, proof path, and anchor reference. The verifier confirms inclusion in the
Merkle tree without learning:
- What the agent spent
- Who the agent transacted with
- What model weights were used
- What the full decision context was

For cases where disclosure is required (audit, compliance, dispute), the agent's principal can reveal the hash preimage. The verifier recomputes the leaf hash from the disclosed fields and confirms it matches the committed leaf.

## Inference Verification

AGENT_INFERENCE (0x48) includes a `proof_commitment` field. This is a 32-byte commitment to an external proof that the model inference was correct.

The proof itself is not stored on Zcash. The commitment binds the attestation leaf to the proof. A verifier who has both the ZAP1 Merkle proof and the inference proof can confirm:
1. The agent committed to this inference result (ZAP1 proof)
2. The inference was computed correctly (external proof)

This connects to the Proof Profile defined in ONCHAIN_PROTOCOL.md Section 12. The proof commitment is the extension point where verifiable inference systems (STARK-based, SNARK-based, or other) bind to ZAP1 attestation.

The ZAP1 protocol does not specify which proving system to use. It provides the commitment slot. The proving system is chosen by the agent operator.

## Credential Derivation

An agent with N attestation events in the Merkle tree can derive behavioral credentials without revealing specific events.

Examples of what inclusion proofs can show:
- "Active agent for 90+ days" - AGENT_REGISTER exists with a timestamp 90+ days ago, plus recent AGENT_ACTION events
- "100+ completed actions" - 100+ AGENT_ACTION leaves present in the tree
- "Policy committed before first action" - AGENT_POLICY leaf precedes AGENT_ACTION leaves in insertion order

Inclusion proofs cannot prove absence (e.g., "zero policy violations" or "never delegated"). Absence proofs require a completeness model that ZAP1 does not currently provide. The Credential Profile (ONCHAIN_PROTOCOL.md Section 12) may address this in future work; it is not available today.

These credentials use the Credential Profile when available. Until then, credential claims are limited to what inclusion proofs can demonstrate.

Credentials are portable: a credential derived from one ZAP1 deployment verifies against the anchored Merkle root without contacting the issuing operator.

## Cross-Chain Agent Proofs

The Solidity verifier (`zap1-verify-sol`, deployed on Sepolia) can verify agent attestation proofs without modification. The verifier is type-agnostic - it checks Merkle path correctness and root registration, not event semantics.

An Ethereum smart contract can gate access based on agent behavior:
- Require proof of AGENT_REGISTER before accepting an agent as a counterparty
- Require proof of AGENT_POLICY with a rules hash matching a known-good policy
- Require proof of N AGENT_ACTION events to establish track record
- Require proof of AGENT_INFERENCE with a proof commitment to verify decision quality

The agent's Zcash transaction graph stays shielded. Only the behavioral proofs cross chains.

## Use Cases

### Agent-to-agent trust

Two agents transact. Agent A needs to know Agent B follows a specific policy. Agent B presents a ZAP1 proof of AGENT_POLICY commitment. Agent A verifies the proof against the Zcash anchor. Trust is established from the proof, not from reputation or identity.

### Autonomous treasury management

A DAO deploys an agent to manage its treasury via an Orchard shielded wallet. The agent commits its spending policy (AGENT_POLICY), logs every disbursement (AGENT_PAYMENT), and publishes periodic audit roots (AGENT_AUDIT). DAO members verify the agent followed its policy from the Merkle proofs without seeing individual transactions.

### Verifiable AI service

An agent provides inference-as-a-service. Each inference is attested via AGENT_INFERENCE with a proof commitment. Clients verify both the attestation (ZAP1 Merkle proof) and the inference correctness (external proving system). The service builds a verifiable track record anchored to Zcash.

### Regulatory compliance

An agent operating in a regulated environment commits its compliance rules as AGENT_POLICY. When audited, the principal discloses the policy preimage and selected action preimages. The auditor recomputes hashes and confirms they match the committed leaves. Full transaction history is not required - only the events relevant to the audit.

## Relationship to Existing ZAP1 Families

| Family | Domain | Policy model |
|--------|--------|--------------|
| Lifecycle (0x01-0x09) | Hardware operations | Operator commits to machine lifecycle |
| Staking (0x0A-0x0C) | Validator economics | Validator commits stake |
| Governance (0x0D-0x0F) | Voting | Voter commits to proposal + choice |
| ZSA (0x10-0x1F) | Asset lifecycle | Issuer commits to issuance/burn/supply |
| Mining pool (0x20-0x2F) | Pool operations | Pool commits to hashrate/payouts |
| Crosslink (0x30-0x3F) | Validator lifecycle | Validator commits to attestation/uptime |
| **Agents (0x40-0x4F)** | **Agent behavior** | **Agent commits to policy + actions** |

All families use the same Merkle tree, the same anchor mechanism, the same verification SDKs, and the same cross-chain verifier. The difference is the domain semantics encoded in the event type byte.

## Activation

These event types will activate when:
1. The agent identity model (agent_id derivation) is finalized
2. Hash constructions are validated with test vectors
3. At least one agent runtime integration is implemented

Until then, types `0x40`-`0x4F` are reserved in the ZAP1 registry. The API will reject events in this range.

## Registry Update

With this spec, the ZAP1 event type registry is:

| Range | Family | Count | Status |
|-------|--------|-------|--------|
| 0x01-0x09 | Lifecycle | 9 | Active |
| 0x0A-0x0C | Staking | 3 | Implemented, pending Crosslink |
| 0x0D-0x0F | Governance | 3 | Active |
| 0x10-0x1F | ZSA | 16 | Reserved (spec published) |
| 0x20-0x2F | Mining pool | 16 | Reserved (spec published) |
| 0x30-0x3F | Crosslink validator | 16 | Reserved (spec published) |
| 0x40-0x4F | Sovereign agents | 16 | Reserved (this document) |
| 0x50-0xFF | Unallocated | 176 | Future use |

Total defined: 79 event types across 7 families.
