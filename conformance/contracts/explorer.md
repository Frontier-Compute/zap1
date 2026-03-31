# Explorer Contract

How a block explorer indexes and displays ZAP1 attestation data.

## Discovery

```
GET /events?limit=50
```

Returns recent attestation events with leaf hashes, event types, and verification URLs. Poll periodically to index new events.

## Proof display

```
GET /verify/{leaf_hash}/proof.json
```

Returns a proof bundle with Merkle path, root, and anchor data. Display the proof steps, root hash, and on-chain anchor reference.

## Verification

```
GET /verify/{leaf_hash}/check
```

Returns `valid: true/false` with the verification SDK used. Server-side check using zap1-verify.

## Memo classification

```
POST /memo/decode
Body: hex-encoded memo bytes
```

Returns format classification. Useful for displaying memo type badges in transaction views.

## Failure modes

- unknown leaf_hash: 404
- API unreachable: cache last known state
- new event types: display type byte as hex if label is unknown

## Stability

- `/events` response schema is stable per conformance/api_schemas.json
- new fields may be added to event objects (additive)
- event_type labels are stable for assigned types
- verify_url and proof_url paths are stable

## Example

See `examples/consumer_explorer.py` for a working implementation.
