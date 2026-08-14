/**
 * ZAP1 reference client for TypeScript.
 * Generated from conformance/openapi.yaml.
 * Zero dependencies. Works with any ZAP1-compatible server.
 */

const DEFAULT_BASE = "https://api.frontiercompute.cash";

export class Zap1Client {
  private base: string;
  private apiKey: string;

  constructor(baseUrl: string = DEFAULT_BASE, apiKey: string = "") {
    this.base = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  private authHeaders(): Record<string, string> {
    if (!this.apiKey) throw new Error("API key required for authenticated route");
    return { "Authorization": `Bearer ${this.apiKey}` };
  }

  private async get(path: string, authenticated = false): Promise<any> {
    const headers: Record<string, string> = { "Accept": "application/json" };
    if (authenticated) Object.assign(headers, this.authHeaders());
    const resp = await fetch(`${this.base}${path}`, { headers });
    if (!resp.ok) throw new Error(`${path}: HTTP ${resp.status}`);
    return resp.json();
  }

  private async postText(path: string, body: string): Promise<any> {
    const resp = await fetch(`${this.base}${path}`, {
      method: "POST",
      headers: { "Accept": "application/json", "Content-Type": "text/plain" },
      body,
    });
    if (!resp.ok) throw new Error(`${path}: HTTP ${resp.status}`);
    return resp.json();
  }

  protocolInfo() { return this.get("/protocol/info"); }
  stats() { return this.get("/stats"); }
  health() { return this.get("/health"); }
  events(limit = 50) { return this.get(`/events?limit=${encodeURIComponent(limit)}`); }
  anchorHistory() { return this.get("/anchor/history"); }
  anchorStatus() { return this.get("/anchor/status"); }
  verify(leafHash: string) { return this.get(`/verify/${encodeURIComponent(leafHash)}/check`); }
  proofBundle(leafHash: string) { return this.get(`/verify/${encodeURIComponent(leafHash)}/proof.json`); }
  decodeMemo(hexBytes: string) { return this.postText("/memo/decode", hexBytes); }
  lifecycle(walletHash: string) {
    return this.get(`/lifecycle/${encodeURIComponent(walletHash)}`, true);
  }
}
