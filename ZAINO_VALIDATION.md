# Zaino gRPC Validation

Date: March 30, 2026
Status: Validated on mainnet

## Infrastructure

- Zaino 0.2.0 (ZingoLabs ZainoD)
- gRPC on 127.0.0.1:8137
- ZainoDB: 96GB at /mnt/zebra/zaino-db
- Connected to Zebra 4.3.0 at 127.0.0.1:8232
- Chain tip: 3,289,945 (synced)

## Endpoints Tested

| Method | Result |
|--------|--------|
| GetLightdInfo | Version 0.2.0, chain main, block 3,289,945 |
| GetLatestBlock | Height 3,289,945, hash returned |
| GetBlock(3286631) | First anchor block, compact tx data present |
| GetBlockRange(3286631-3286633) | 3 blocks streamed |
| GetTransaction(ba63e44f...) | Anchor tx at height 3,290,002, full raw data |
| GetLatestTreeState | Sapling + Orchard tree state at tip |

## Anchor Verification via Zaino

The latest anchor (txid ba63e44f9589c63baaebae25eb0c369bf59a7d4db559f6b51cf8a2b27fc7793b, block 3,290,002) was retrieved via Zaino gRPC, confirming the dual-backend path works for ZAP1 anchor verification.

## Dual Backend Summary

| Backend | Port | Protocol | Scanner Use |
|---------|------|----------|------------|
| Zebra RPC | 8232 | JSON-RPC | Current production scanner (polling getblock) |
| Zaino gRPC | 8137 | CompactTxStreamer | Compact block streaming (validated, integration target) |

The NodeBackend trait in zap1/src/node.rs abstracts both paths. Switching from Zebra RPC to Zaino gRPC requires changing the backend config, not the scanner logic.
