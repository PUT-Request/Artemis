#!/bin/bash
# Artemis DOT Deployment Script
# Run this from the Artemis directory

set -e

SERVER="192.210.199.118"
USER="root"
PASS="eason2830"
ARTEMIS_DIR="/opt/artemis"

echo "=== Artemis DOT Deployment ==="

# Upload binary
echo "[1/6] Uploading binary..."
sshpass -e scp -o StrictHostKeyChecking=no artemis-linux-amd64 ${USER}@${SERVER}:${ARTEMIS_DIR}/artemis

# Generate self-signed TLS cert for DOT
echo "[2/6] Generating TLS certificates..."
sshpass -e ssh -o StrictHostKeyChecking=no ${USER}@${SERVER} << 'EOF'
mkdir -p /etc/artemis/tls
cd /etc/artemis/tls
if [ ! -f cert.pem ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout key.pem -out cert.pem -days 3650 -nodes \
        -subj "/CN=dns.local" \
        -addext "subjectAltName=DNS:dns.local,IP:192.210.199.118"
    chmod600 key.pem
    echo "TLS certificates generated"
else
    echo "TLS certificates already exist"
fi
EOF

# Upload config with DOT enabled
echo "[3/6] Updating configuration..."
sshpass -e ssh -o StrictHostKeyChecking=no ${USER}@${SERVER} << 'EOF'
cat > /opt/artemis/config.yaml << 'CONFIG'
server:
  listen: "0.0.0.0:53"
  acl:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "127.0.0.0/8"

doh:
  enabled: true
  listen: "127.0.0.1:8053"
  path: "/dns-query"

dot:
  enabled: true
  listen: "0.0.0.0:853"
  cert_file: "/etc/artemis/tls/cert.pem"
  key_file: "/etc/artemis/tls/key.pem"

http:
  enabled: true
  listen: "0.0.0.0:80"
  answer_ip: "192.210.199.118"

webui:
  enabled: true
  listen: "127.0.0.1:8082"
  username: "admin"
  password: "artemis"

database:
  path: "/opt/artemis/artemis.db"
  retention_days: 30
CONFIG
echo "Configuration updated"
EOF

# Open firewall for DOT
echo "[4/6] Configuring firewall..."
sshpass -e ssh -o StrictHostKeyChecking=no ${USER}@${SERVER} << 'EOF'
ufw allow 853/tcp comment "DNS-over-TLS"
ufw allow 53/tcp comment "DNS TCP"
ufw allow 53/udp comment "DNS UDP"
ufw allow 80/tcp comment "HTTP"
ufw allow 443/tcp comment "HTTPS"
echo "Firewall rules added"
ufw status | grep -E "853|53|80|443"
EOF

# Configure Caddy for DOT proxy (TCP passthrough)
echo "[5/6] Updating Caddy configuration..."
sshpass -e ssh -o StrictHostKeyChecking=no ${USER}@${SERVER} << 'EOF'
# Add DOT reverse proxy to Caddy (TCP passthrough)
# Note: DOT requires TCP layer4 proxy, not HTTP reverse proxy
# Check if caddy has layer4 module
if caddy list-modules 2>/dev/null | grep -q "layer4"; then
    echo "Caddy has layer4 module - can proxy DOT"
    # Add to Caddyfile if not exists
    if ! grep -q "dns.local:853" /etc/caddy/Caddyfile2>/dev/null; then
        cat >> /etc/caddy/Caddyfile << CADDY

# DNS-over-TLS proxy
dns.local:853 {
    tls /etc/artemis/tls/cert.pem /etc/artemis/tls/key.pem
    route {
        proxy {
            upstream 127.0.0.1:853
        }
    }
}
CADDY
        systemctl reload caddy
        echo "Caddy DOT proxy configured"
    fi
else
    echo "NOTE: Caddy doesn't have layer4 module"
    echo "DOT will be served directly by Artemis on port853"
    echo "Clients can connect to: 192.210.199.118:853"
fi
EOF

# Restart Artemis
echo "[6/6] Restarting Artemis..."
sshpass -e ssh -o StrictHostKeyChecking=no ${USER}@${SERVER} << 'EOF'
# Kill existing Artemis
pkill -f "artemis" || true
sleep1

# Start Artemis (assuming systemd service exists)
if systemctl is-enabled artemis 2>/dev/null; then
    systemctl restart artemis
    systemctl status artemis --no-pager
else
    # Start in background if no systemd service
    cd /opt/artemis
    nohup ./artemis --config config.yaml > artemis.log2>&1 &
    sleep2
    echo "Artemis started (PID: $(pgrep -f artemis))"
    tail -5 artemis.log
fi
EOF

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "DNS-over-TLS is now available at:"
echo "  Server: 192.210.199.118"
echo "  Port: 853"
echo "  Protocol: TLS (RFC7858)"
echo ""
echo "Test with:"
echo "  kdig @192.210.199.118 +tls example.com"
echo "  dnslookup example.com 192.210.199.118:853"
echo ""
echo "Web UI: http://192.210.199.118:8082"
echo "  Username: admin"
echo "  Password: artemis"
