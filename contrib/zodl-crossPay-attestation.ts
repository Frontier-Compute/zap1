/**
 * ZAP1 attestation module for Zodl CrossPay.
 *
 * Attests every cross-chain swap that goes through NEAR Intents.
 * Zero dependencies - uses native fetch.
 *
 * Usage:
 *   const zap1 = new CrossPayAttestation("https://pay.frontiercompute.io", API_KEY);
 *   const receipt = await zap1.attest(swapResult);
 *
 * Protocol: https://github.com/Frontier-Compute/zap1/blob/main/ONCHAIN_PROTOCOL.md
 */

// Swap result from CrossPay intent resolution
export interface CrossPaySwap {
  // Source shielded ZEC wallet hash (BLAKE2b of the UA or z-addr)
  sourceWalletHash: string;
  // Destination wallet hash on target chain
  destWalletHash: string;
  // Source asset, e.g. "ZEC"
  sourceAsset: string;
  // Destination asset, e.g. "USDC", "ETH"
  destAsset: string;
  // Amount in source asset smallest unit (zatoshis for ZEC)
  amountSourceZat: number;
  // Amount in destination asset smallest unit
  amountDestSmallest: number;
  // NEAR Intent transaction ID
  intentTxId: string;
  // Route taken, e.g. "ZEC -> NEAR -> Base:USDC"
  route: string;
  // Whether the swap completed successfully
  success: boolean;
  // Optional failure reason
  failureReason?: string;
}

// Attestation result returned after POST /event
export interface AttestationReceipt {
  leafHash: string;
  rootHash: string;
  verifyUrl: string;
  eventType: string;
  timestamp: number;
  swap: CrossPaySwap;
}

// Error from the ZAP1 API or network
export class AttestationError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly body?: string
  ) {
    super(message);
    this.name = "AttestationError";
  }
}

export class CrossPayAttestation {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  /**
   * Attest a CrossPay swap.  Posts a TRANSFER event to ZAP1.
   *
   * The swap is encoded as:
   *   wallet_hash     = sourceWalletHash (shielded ZEC side)
   *   new_wallet_hash = destWalletHash (target chain side)
   *   serial_number   = intentTxId (NEAR Intent tx, used as the unique swap ID)
   *
   * This produces a Merkle leaf anchored to Zcash mainnet.
   * The leaf hash is the verifiable receipt for this swap.
   */
  async attest(swap: CrossPaySwap): Promise<AttestationReceipt> {
    if (!swap.sourceWalletHash || !swap.destWalletHash || !swap.intentTxId) {
      throw new AttestationError(
        "sourceWalletHash, destWalletHash, and intentTxId are required"
      );
    }

    const eventType = "TRANSFER";

    const body = {
      event_type: eventType,
      wallet_hash: swap.sourceWalletHash,
      new_wallet_hash: swap.destWalletHash,
      serial_number: swap.intentTxId,
    };

    const res = await fetch(`${this.baseUrl}/event`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new AttestationError(
        `ZAP1 API returned ${res.status}`,
        res.status,
        text
      );
    }

    const data = await res.json();

    return {
      leafHash: data.leaf_hash,
      rootHash: data.root_hash,
      verifyUrl: `${this.baseUrl}/verify/${data.leaf_hash}`,
      eventType,
      timestamp: Date.now(),
      swap,
    };
  }

  /**
   * Attest a failed swap.  Records the attempt so users can prove
   * they initiated a swap even if it did not complete.
   *
   * Uses the same TRANSFER event type.  The serial_number encodes
   * the intent TX ID prefixed with "FAILED:" so it is distinguishable
   * from successful swaps in the Merkle tree.
   */
  async attestFailed(swap: CrossPaySwap): Promise<AttestationReceipt> {
    const failedSwap: CrossPaySwap = {
      ...swap,
      success: false,
    };

    const body = {
      event_type: "TRANSFER",
      wallet_hash: swap.sourceWalletHash,
      new_wallet_hash: swap.destWalletHash,
      serial_number: `FAILED:${swap.intentTxId}`,
    };

    const res = await fetch(`${this.baseUrl}/event`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new AttestationError(
        `ZAP1 API returned ${res.status}`,
        res.status,
        text
      );
    }

    const data = await res.json();

    return {
      leafHash: data.leaf_hash,
      rootHash: data.root_hash,
      verifyUrl: `${this.baseUrl}/verify/${data.leaf_hash}`,
      eventType: "TRANSFER",
      timestamp: Date.now(),
      swap: failedSwap,
    };
  }

  /**
   * Verify a previously issued attestation receipt.
   * Calls GET /verify/{leaf_hash}/check to confirm the leaf
   * exists in the Merkle tree and has been anchored to Zcash.
   */
  async verify(leafHash: string): Promise<{
    valid: boolean;
    root: string;
    anchored: boolean;
    serverVerified: boolean;
  }> {
    const res = await fetch(
      `${this.baseUrl}/verify/${leafHash}/check`
    );

    if (res.status === 404) {
      return { valid: false, root: "", anchored: false, serverVerified: false };
    }

    if (!res.ok) {
      throw new AttestationError(
        `ZAP1 verify returned ${res.status}`,
        res.status
      );
    }

    const data = await res.json();

    return {
      valid: data.valid,
      root: data.root,
      anchored: !!data.root,
      serverVerified: data.server_verified ?? false,
    };
  }

  /**
   * Get the full proof bundle for a swap attestation.
   * Returns the Merkle path, root, and anchor transaction
   * needed for independent verification.
   */
  async getProof(leafHash: string): Promise<Record<string, unknown> | null> {
    const res = await fetch(
      `${this.baseUrl}/verify/${leafHash}/proof.json`
    );

    if (res.status === 404) return null;
    if (!res.ok) {
      throw new AttestationError(
        `ZAP1 proof returned ${res.status}`,
        res.status
      );
    }

    return res.json();
  }
}
