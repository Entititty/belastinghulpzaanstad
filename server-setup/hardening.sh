#!/bin/bash
# ============================================================
#  Belastinghulp Zaanstad — Server Hardening Script
#  Werkt op: Ubuntu 20.04 / 22.04 / 24.04 met Nginx
#  Uitvoeren als root: sudo bash hardening.sh
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[--]${NC} $1"; }
info() { echo -e "     $1"; }

echo ""
echo "============================================================"
echo "  Server Hardening: UFW + Nginx rate limiting + Fail2ban"
echo "============================================================"
echo ""

# ─── 1. UFW FIREWALL ─────────────────────────────────────────
echo "--- UFW Firewall ---"

if ! command -v ufw &>/dev/null; then
  warn "UFW niet gevonden, installeren..."
  apt-get install -y ufw
fi

UFW_STATUS=$(ufw status | head -1)

if echo "$UFW_STATUS" | grep -q "inactive"; then
  warn "UFW is inactief — configureren en inschakelen"
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp comment 'SSH'
  ufw allow 80/tcp comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'
  ufw --force enable
  ok "UFW ingeschakeld (poorten 22, 80, 443 open)"
else
  ok "UFW is al actief"
  # Zorg dat de juiste poorten open zijn
  ufw allow 22/tcp  comment 'SSH'  2>/dev/null || true
  ufw allow 80/tcp  comment 'HTTP' 2>/dev/null || true
  ufw allow 443/tcp comment 'HTTPS' 2>/dev/null || true
  info "Huidige status:"
  ufw status numbered | grep -E "ALLOW|Status"
fi

echo ""

# ─── 2. NGINX RATE LIMITING ──────────────────────────────────
echo "--- Nginx Rate Limiting ---"

NGINX_CONF_D="/etc/nginx/conf.d"
RATE_FILE="$NGINX_CONF_D/rate-limit.conf"

if [ ! -d "$NGINX_CONF_D" ]; then
  # Sommige setups gebruiken sites-available
  NGINX_CONF_D="/etc/nginx/sites-available"
  RATE_FILE="$NGINX_CONF_D/rate-limit.conf"
fi

if [ -f "$RATE_FILE" ]; then
  ok "Rate limiting config bestaat al ($RATE_FILE)"
else
  warn "Rate limiting ontbreekt — aanmaken..."

  cat > "$RATE_FILE" << 'EOF'
# ── Rate limiting zones (http context) ──────────────────────
# Wordt automatisch geladen via conf.d/

# Algemene zone: max 20 req/s per IP, 10 MB geheugen (~160.000 IPs)
limit_req_zone $binary_remote_addr zone=general:10m rate=20r/s;

# Stricter voor formulieren / API-achtige endpoints
limit_req_zone $binary_remote_addr zone=strict:5m  rate=5r/s;

# Logging bij rate limit overtreding
limit_req_log_level warn;
limit_req_status 429;

# Verbindingen per IP (aanvullend op req/s)
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;
EOF

  ok "Rate limiting zones aangemaakt in $RATE_FILE"
fi

# Controleer of de zones ook toegepast worden in de server block
SITE_CONF=$(nginx -T 2>/dev/null | grep -l "limit_req zone=general" 2>/dev/null || true)

if [ -z "$SITE_CONF" ]; then
  # Zoek het actieve server block
  ACTIVE_CONF=$(nginx -T 2>/dev/null | grep "# configuration file" | grep -v "mime\|fastcgi\|proxy\|uwsgi\|scgi\|rate" | head -1 | awk '{print $4}' | tr -d ':')

  if [ -n "$ACTIVE_CONF" ] && [ -f "$ACTIVE_CONF" ]; then
    # Controleer of er al limit_req in staat
    if ! grep -q "limit_req" "$ACTIVE_CONF"; then
      warn "Rate limiting nog niet toegepast in server block: $ACTIVE_CONF"
      info "Voeg dit toe aan je server { } block in $ACTIVE_CONF:"
      echo ""
      echo "    # Rate limiting (toevoegen in server { } block)"
      echo "    limit_req  zone=general burst=40 nodelay;"
      echo "    limit_conn conn_per_ip 20;"
      echo ""
      info "Daarna: sudo nginx -t && sudo systemctl reload nginx"
    else
      ok "limit_req al aanwezig in $ACTIVE_CONF"
    fi
  fi
fi

# Nginx config test
if nginx -t 2>/dev/null; then
  ok "Nginx config geldig"
  systemctl reload nginx
  ok "Nginx herladen"
else
  warn "Nginx config heeft een fout — niet herladen. Controleer: sudo nginx -t"
fi

echo ""

# ─── 3. FAIL2BAN ─────────────────────────────────────────────
echo "--- Fail2ban ---"

if ! command -v fail2ban-client &>/dev/null; then
  warn "Fail2ban niet gevonden, installeren..."
  apt-get install -y fail2ban
fi

F2B_JAIL="/etc/fail2ban/jail.local"

if [ -f "$F2B_JAIL" ] && grep -q "\[nginx-" "$F2B_JAIL" 2>/dev/null; then
  ok "Fail2ban jail.local bestaat al met nginx-regels"
else
  warn "Fail2ban jail.local aanmaken / uitbreiden..."

  # Bewaar eventueel bestaand bestand
  [ -f "$F2B_JAIL" ] && cp "$F2B_JAIL" "${F2B_JAIL}.bak.$(date +%s)"

  cat > "$F2B_JAIL" << 'EOF'
# ── Fail2ban jail.local ──────────────────────────────────────
# Overschrijft defaults uit jail.conf (die wordt door updates aangepast)

[DEFAULT]
# Standaard ban: 1 uur na 5 foute pogingen binnen 10 minuten
bantime  = 3600
findtime = 600
maxretry = 5
backend  = auto

# Negeer localhost en eigen serverIP
ignoreip = 127.0.0.1/8 ::1

# Ban-methode (nftables op Ubuntu 22+, iptables op oudere versies)
banaction = ufw

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 4
bantime  = 86400

# ── Nginx jails ──────────────────────────────────────────────

# Te veel 404s (scanners / bots)
[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
           /var/log/nginx/error.log
filter   = nginx-botsearch
maxretry = 10
findtime = 60
bantime  = 3600

# Te veel requests (DDoS / rate-limit hits)
[nginx-req-limit]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
filter   = nginx-req-limit
maxretry = 10
findtime = 60
bantime  = 3600

# HTTP auth brute force
[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5
EOF

  ok "jail.local aangemaakt"
fi

# Zorg dat de nginx-req-limit filter bestaat
F2B_FILTER_DIR="/etc/fail2ban/filter.d"

if [ ! -f "$F2B_FILTER_DIR/nginx-req-limit.conf" ]; then
  cat > "$F2B_FILTER_DIR/nginx-req-limit.conf" << 'EOF'
# Fail2ban filter: pakt IPs die nginx rate limit raken
[Definition]
failregex = ^\s*\[error\].*limiting requests, excess:.*by zone.*client: <HOST>
ignoreregex =
EOF
  ok "Filter nginx-req-limit aangemaakt"
fi

# nginx-botsearch filter bestaat normaal al, anders aanmaken
if [ ! -f "$F2B_FILTER_DIR/nginx-botsearch.conf" ]; then
  cat > "$F2B_FILTER_DIR/nginx-botsearch.conf" << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) .*\.(php|asp|aspx|jsp|cgi|env|git|bash|sh|sql|bak|zip|tar)\b.* (404|403|400) .*$
ignoreregex =
EOF
  ok "Filter nginx-botsearch aangemaakt"
fi

# Fail2ban herstarten
systemctl enable fail2ban
systemctl restart fail2ban
sleep 2

if systemctl is-active --quiet fail2ban; then
  ok "Fail2ban actief"
  info "Actieve jails:"
  fail2ban-client status 2>/dev/null | grep "Jail list" || true
else
  warn "Fail2ban kon niet starten — check: sudo journalctl -u fail2ban -n 30"
fi

echo ""
echo "============================================================"
echo ""
echo "Samenvatting:"
echo "  UFW:        $(ufw status | head -1)"
echo "  Fail2ban:   $(systemctl is-active fail2ban)"
echo "  Nginx:      $(systemctl is-active nginx)"
echo ""
echo "Handige commando's:"
echo "  sudo ufw status numbered"
echo "  sudo fail2ban-client status"
echo "  sudo fail2ban-client status nginx-req-limit"
echo "  sudo fail2ban-client status sshd"
echo "  sudo fail2ban-client unban <IP>   # IP deblokkeren"
echo ""
echo "BELANGRIJK: controleer of je SSH-poort (22) open staat"
echo "voordat je de sessie sluit: sudo ufw status | grep 22"
echo ""
