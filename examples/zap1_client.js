#!/usr/bin/env node
/**
 * ZAP1 API client for JavaScript. Zero dependencies.
 * Works in Node.js and browsers (via fetch).
 *
 * Usage:
 *   const zap1 = new ZAP1Client('https://api.frontiercompute.cash');
 *   const stats = await zap1.stats();
 *   const proof = await zap1.verifyLeaf('abc123...');
 *   const event = await zap1.createEvent('DEPLOYMENT', { wallet_hash: '...', serial_number: '...', facility_id: '...' });
 */

class ZAP1Client {
  constructor(baseUrl, apiKey) {
    this.url = baseUrl.replace(/\/$/, '');
    this.key = apiKey || '';
  }

  async _get(path) {
    const res = await fetch(`${this.url}${path}`);
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    return res.json();
  }

  async _post(path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.key) headers['Authorization'] = `Bearer ${this.key}`;
    const res = await fetch(`${this.url}${path}`, {
      method: 'POST', headers, body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
    return res.json();
  }

  // Read endpoints
  async health() { return this._get('/health'); }
  async stats() { return this._get('/stats'); }
  async protocolInfo() { return this._get('/protocol/info'); }
  async anchorStatus() { return this._get('/anchor/status'); }
  async anchorHistory() { return this._get('/anchor/history'); }
  async events(limit = 50) { return this._get(`/events?limit=${limit}`); }
  async buildInfo() { return this._get('/build/info'); }

  // Verification
  async verifyLeaf(leafHash) { return this._get(`/verify/${leafHash}/check`); }
  async proofBundle(leafHash) { return this._get(`/verify/${leafHash}/proof.json`); }
  async lifecycle(walletHash) { return this._get(`/lifecycle/${walletHash}`); }

  // Memo decode
  async decodeMemo(hex) { return this._post('/memo/decode', hex); }

  // Write endpoints (require API key)
  async createEvent(eventType, params) {
    return this._post('/event', { event_type: eventType, ...params });
  }

  async createInvoice(amountZec, memo) {
    return this._post('/invoice', { amount_zec: amountZec, memo });
  }
}

// CLI demo
if (typeof process !== 'undefined' && process.argv[1] && process.argv[1].includes('zap1_client')) {
  const url = process.argv[2] || 'https://api.frontiercompute.cash';
  const client = new ZAP1Client(url);

  (async () => {
    const info = await client.protocolInfo();
    const stats = await client.stats();
    const history = await client.anchorHistory();

    console.log(`${info.protocol} ${info.version}`);
    console.log(`${stats.total_anchors} anchors, ${stats.total_leaves} leaves, ${info.deployed_types} types`);
    console.log(`Last anchor: block ${history.anchors.slice(-1)[0]?.height || 'none'}`);
  })().catch(e => console.error(e.message));
}

if (typeof module !== 'undefined') module.exports = { ZAP1Client };
