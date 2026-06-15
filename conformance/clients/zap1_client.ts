/**
 * ZAP1 reference client for TypeScript.
 * Generated from conformance/openapi.yaml.
 * Zero dependencies. Works with any ZAP1-compatible server.
 */

const DEFAULT_BASE = "https://api.frontiercompute.cash";

export class Zap1Client {
  private base: string;

  constructor(baseUrl: string = DEFAULT_BASE) {
    this.base = baseUrl.replace(/\/$/, "");
  }

  private async get(path: string): Promise<any> {
    const resp = await fetch(`${this.base}${path}`);
    if (!resp.ok) throw new Error(`${path}: HTTP ${resp.status}`);
    return resp.json();
  }

  private async post(path: string, body: string): Promise<any> {
    const resp = await fetch(`${this.base}${path}`, { method: "POST", body });
    if (!resp.ok) throw new Error(`${path}: HTTP ${resp.status}`);
    return resp.json();
  }

  protocolInfo() { return this.get("/protocol/info"); }
  stats() { return this.get("/stats"); }
  health() { return this.get("/health"); }
  events(limit = 50) { return this.get(`/events?limit=${limit}`); }
  anchorHistory() { return this.get("/anchor/history"); }
  anchorStatus() { return this.get("/anchor/status"); }
  verify(leafHash: string) { return this.get(`/verify/${leafHash}/check`); }
  proofBundle(leafHash: string) { return this.get(`/verify/${leafHash}/proof.json`); }
  decodeMemo(hexBytes: string) { return this.post("/memo/decode", hexBytes); }
  lifecycle(walletHash: string) { return this.get(`/lifecycle/${walletHash}`); }
}
