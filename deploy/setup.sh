#!/bin/bash
# MCP Sentinel — VPS Setup Script
# Run once on a fresh Ubuntu 22.04 server as root or with sudo
set -euo pipefail

echo "=== MCP Sentinel Server Setup ==="

# 1. System packages
apt-get update -qq
apt-get install -y -qq git curl nginx certbot python3-certbot-nginx

# 2. Docker
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 3. Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -qq nodejs
corepack enable
corepack prepare pnpm@10.29.3 --activate

# 4. Clone repo (replace with your repo URL)
cd /opt
git clone https://github.com/YOUR_ORG/mcpsentinal.git mcp-sentinel
cd mcp-sentinel

# 5. Environment file
cp .env.example .env
echo ""
echo ">>> Edit /opt/mcp-sentinel/.env now, then re-run this script from step 6 <<<"
echo "    Set: POSTGRES_PASSWORD, GITHUB_TOKEN"
