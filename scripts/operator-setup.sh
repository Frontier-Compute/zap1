#!/usr/bin/env bash
set -euo pipefail

# Generate a complete ZAP1 operator deployment config.
# Usage: ./scripts/operator-setup.sh <operator-name> [port]
# Example: ./scripts/operator-setup.sh acme 3081

OPERATOR=${1:-}
PORT=${2:-3081}

if [ -z "$OPERATOR" ]; then
    echo "Usage: $0 <operator-name> [port]"
    echo "Example: $0 acme 3081"
    exit 1
fi

# Sanitize operator name
OPERATOR=$(echo "$OPERATOR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
OUTDIR="operators/$OPERATOR"

if [ -d "$OUTDIR" ]; then
    echo "Error: $OUTDIR already exists"
    exit 1
fi

echo "Generating operator config: $OPERATOR (port $PORT)"

# Generate keys
KEYS=$(cargo run --release --bin keygen -- mainnet 2>/dev/null)
SEED=$(echo "$KEYS" | grep "^SEED=" | cut -d= -f2)
UFVK=$(echo "$KEYS" | grep "^UFVK=" | cut -d= -f2)
ADDRESS=$(echo "$KEYS" | grep "^# ANCHOR_TO_ADDRESS=" | cut -d= -f2)

# Generate API key
API_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)

mkdir -p "$OUTDIR"

# Write .env
cat > "$OUTDIR/.env" <<EOF
# ZAP1 operator: $OPERATOR
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

UFVK=$UFVK
NETWORK=Mainnet
ZEBRA_RPC_URL=http://127.0.0.1:8232
ZAINO_GRPC_URL=http://127.0.0.1:8137
SCAN_FROM_HEIGHT=3292000
LISTEN_ADDR=127.0.0.1:$PORT
DB_PATH=/data/zap1.db
API_KEY=$API_KEY
ANCHOR_TO_ADDRESS=$ADDRESS
EOF

# Write seed file (keep separate, don't put in .env)
cat > "$OUTDIR/.seed" <<EOF
# ZAP1 operator spending seed - KEEP SECRET
# Operator: $OPERATOR
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
SEED=$SEED
EOF
chmod 600 "$OUTDIR/.seed"

# Write docker-compose
cat > "$OUTDIR/docker-compose.yml" <<EOF
services:
  zap1-$OPERATOR:
    image: zap1:latest
    container_name: zap1-$OPERATOR
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./data:/data
    env_file:
      - .env
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://127.0.0.1:$PORT/health"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF

# Write run script
cat > "$OUTDIR/run.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "\$(dirname "\$0")"
docker compose up -d
echo "ZAP1 operator '$OPERATOR' started on port $PORT"
echo "Health: curl http://127.0.0.1:$PORT/health"
echo "Anchor QR: http://127.0.0.1:$PORT/admin/anchor/qr?key=$API_KEY"
EOF
chmod +x "$OUTDIR/run.sh"

# Summary
echo ""
echo "Operator: $OPERATOR"
echo "Port: $PORT"
echo "API key: $API_KEY"
echo "Address: $ADDRESS"
echo ""
echo "Files:"
echo "  $OUTDIR/.env        - container config"
echo "  $OUTDIR/.seed       - spending seed (chmod 600)"
echo "  $OUTDIR/docker-compose.yml"
echo "  $OUTDIR/run.sh"
echo ""
echo "Start: cd $OUTDIR && ./run.sh"
echo "Anchor: open http://127.0.0.1:$PORT/admin/anchor/qr?key=$API_KEY"
