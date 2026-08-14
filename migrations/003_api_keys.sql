CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'trial',
    leaves_used INTEGER NOT NULL DEFAULT 0,
    leaves_limit INTEGER NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
