CREATE TABLE IF NOT EXISTS anchor_broadcasts (
    txid TEXT PRIMARY KEY
        CHECK (length(txid) = 64 AND txid = lower(txid) AND txid NOT GLOB '*[^0-9a-f]*'),
    root_hash TEXT NOT NULL
        CHECK (length(root_hash) = 64 AND root_hash = lower(root_hash) AND root_hash NOT GLOB '*[^0-9a-f]*'),
    leaf_count INTEGER NOT NULL CHECK (leaf_count > 0),
    raw_tx_hex TEXT NOT NULL,
    spent_position INTEGER NOT NULL CHECK (spent_position >= 0),
    status TEXT NOT NULL CHECK (status IN ('prepared', 'recorded')),
    created_at TEXT NOT NULL,
    recorded_at TEXT,
    last_error TEXT,
    confirmation_attempts INTEGER NOT NULL DEFAULT 0 CHECK (confirmation_attempts >= 0),
    next_confirmation_at TEXT,
    last_confirmation_at TEXT,
    confirmed_at TEXT,
    UNIQUE(root_hash, leaf_count)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_anchor_broadcast_one_prepared
    ON anchor_broadcasts(status) WHERE status = 'prepared';

CREATE UNIQUE INDEX IF NOT EXISTS idx_merkle_roots_anchor_txid
    ON merkle_roots(anchor_txid) WHERE anchor_txid IS NOT NULL;
