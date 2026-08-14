# Historical Zaino gRPC retrieval run

Date: 2026-03-30

Status: application-operated historical test

The operator exercised Zaino 0.2.0 against a local Zebra 4.3.0 mainnet node.
This is a dated infrastructure receipt, not an independent validation or a
claim about current production state.

## Recorded environment

- Zaino gRPC: `127.0.0.1:8137`
- ZainoDB: 96 GB
- Zebra RPC: `127.0.0.1:8232`
- recorded chain tip: `3,289,945`

## Calls exercised

| Method | Historical observation |
| --- | --- |
| `GetLightdInfo` | returned version, mainnet label, and height |
| `GetLatestBlock` | returned height `3,289,945` and a hash |
| `GetBlock(3286631)` | returned compact block data |
| `GetBlockRange(3286631-3286633)` | streamed three blocks |
| `GetTransaction(ba63e44f...)` | returned non-empty transaction bytes |
| `GetLatestTreeState` | returned Sapling and Orchard tree state |

The run also found the recorded txid
`ba63e44f9589c63baaebae25eb0c369bf59a7d4db559f6b51cf8a2b27fc7793b`
at height `3,290,002`.

This establishes historical retrieval through that operator's Zaino instance.
It does not decrypt the Orchard memo, bind an API-supplied root to that memo,
validate every scanner behavior, prove backend parity, or show that Zaino is
the current production backend.
