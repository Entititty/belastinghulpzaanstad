#!/usr/bin/env bash
# ============================================================
#  De app (aanvragen, herinneringslijst, beheer) installeren op de VPS
#
#  Eenmalig, na de uitrol waarin app/ op de server is gekomen:
#    sudo bash /var/www/belastinghulpzaanstad.nl/html/server-setup/app-installeren.sh
#
#  Opnieuw draaien kan altijd: wat er al staat, blijft staan (app.env wordt
#  nooit overschreven). Uitleg per stap: server-setup/APP.md.
#
#  Wat het doet:
#   1. Node.js 24 (NodeSource), en Node mee in de automatische updates
#   2. gebruiker bhz-app, /var/lib/belastinghulp, /var/backups/belastinghulp
#   3. /etc/belastinghulp/app.env uit het voorbeeld, met een nieuw geheim
#   4. de map voor de klikmeting
#   5. de systemd-dienst belastinghulp-app, en starten
#   6. nginx: drie bestanden in conf.d en (na uw "j") het server-blok
#   7. controles
# ============================================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

WEBROOT=/var/www/belastinghulpzaanstad.nl/html
GEBRUIKER=bhz-app
DATA=/var/lib/belastinghulp
BACKUP=/var/backups/belastinghulp
ETC=/etc/belastinghulp
ENV_BESTAND=$ETC/app.env
SITE=/etc/nginx/sites-available/belastinghulpzaanstad.nl
NODE_MAJOR=24

GROEN='\033[0;32m'; GEEL='\033[1;33m'; ROOD='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GROEN}[OK]${NC} $1"; }
let_op() { echo -e "${GEEL}[!!]${NC} $1"; }
fout() { echo -e "${ROOD}[FOUT]${NC} $1"; }
stap() { echo; echo "=== $1"; }

[ "$(id -u)" -eq 0 ] || { fout "Draai dit met sudo."; exit 1; }
[ -f "$WEBROOT/app/server.js" ] || { fout "$WEBROOT/app/server.js ontbreekt. Is de uitrol met de app al langs geweest? (tail /tmp/belasting-deploy.log)"; exit 1; }

# ---------------------------------------------------------------
stap "1. Node.js $NODE_MAJOR"
huidig=$( (node -v 2>/dev/null || echo v0) | sed 's/^v//; s/\..*//')
if [ "$huidig" -ge "$NODE_MAJOR" ]; then
  ok "Node $(node -v) staat er al"
else
  apt-get update -q
  apt-get install -y -q ca-certificates curl gnupg
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
  apt-get update -q
  apt-get install -y -q nodejs
  ok "Node $(node -v) geinstalleerd"
fi
node --disable-warning=ExperimentalWarning -e "require('node:sqlite')" || { fout "Deze Node kent node:sqlite niet (nodig: 22.13 of nieuwer)."; exit 1; }

# enable-auto-updates.sh neemt alleen de pakketten van Ubuntu mee. Dit voegt
# NodeSource toe, binnen dezelfde hoofdversie (node_24.x).
cat > /etc/apt/apt.conf.d/53unattended-upgrades-nodesource <<'EOF'
// Node.js van NodeSource meenemen in de automatische updates.
// De bron is node_24.x, dus het blijft bij versie 24.
Unattended-Upgrade::Origins-Pattern {
        "site=deb.nodesource.com";
};
EOF
ok "Node gaat mee met de automatische updates"

# ---------------------------------------------------------------
stap "2. Gebruiker en mappen"
if id -u "$GEBRUIKER" >/dev/null 2>&1; then ok "gebruiker $GEBRUIKER bestaat al"; else
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$GEBRUIKER"
  ok "gebruiker $GEBRUIKER aangemaakt"
fi
usermod -a -G www-data "$GEBRUIKER"
install -d -o "$GEBRUIKER" -g "$GEBRUIKER" -m 700 "$DATA"
install -d -o "$GEBRUIKER" -g "$GEBRUIKER" -m 700 "$BACKUP"
install -d -o root -g "$GEBRUIKER" -m 750 "$ETC"
ok "$DATA, $BACKUP en $ETC staan klaar"

# ---------------------------------------------------------------
stap "3. Geheimen: $ENV_BESTAND"
if [ -f "$ENV_BESTAND" ]; then
  ok "bestaat al; niet overschreven"
else
  install -o root -g "$GEBRUIKER" -m 640 "$WEBROOT/server-setup/app.env.voorbeeld" "$ENV_BESTAND"
  ok "aangemaakt uit server-setup/app.env.voorbeeld"
fi
grep -q '^BHZ_GEHEIM=' "$ENV_BESTAND" || echo 'BHZ_GEHEIM=' >> "$ENV_BESTAND"
if grep -qE '^BHZ_GEHEIM=.{32,}' "$ENV_BESTAND"; then
  ok "BHZ_GEHEIM staat er al"
else
  sed -i "s/^BHZ_GEHEIM=.*/BHZ_GEHEIM=$(openssl rand -hex 32)/" "$ENV_BESTAND"
  ok "BHZ_GEHEIM ingevuld"
fi
chown root:"$GEBRUIKER" "$ENV_BESTAND"
chmod 640 "$ENV_BESTAND"
if grep -qE '^SMTP_WACHTWOORD=.+' "$ENV_BESTAND" || grep -qE '^BREVO_API_SLEUTEL=.+' "$ENV_BESTAND"; then
  ok "mailgegevens ingevuld"
else
  let_op "nog geen mailgegevens. De app draait wel en bewaart de mails tot ze ingevuld zijn (APP.md, stap 3)."
fi

# ---------------------------------------------------------------
stap "4. Map voor de klikmeting"
install -d -o www-data -g www-data -m 750 /var/log/belastinghulp/tellingen
[ -f /var/log/belastinghulp/tellingen/START ] || { date -I > /var/log/belastinghulp/tellingen/START; chown www-data:www-data /var/log/belastinghulp/tellingen/START; }
ok "/var/log/belastinghulp/tellingen (www-data; de app leest mee via de groep)"

# ---------------------------------------------------------------
stap "5. De dienst belastinghulp-app"
install -m 644 "$WEBROOT/server-setup/belastinghulp-app.service" /etc/systemd/system/belastinghulp-app.service
systemctl daemon-reload
systemctl enable belastinghulp-app >/dev/null 2>&1
systemctl restart belastinghulp-app
for i in $(seq 1 15); do
  if curl -fsS -o /dev/null http://127.0.0.1:8790/api/gezond 2>/dev/null; then break; fi
  sleep 1
done
if curl -fsS http://127.0.0.1:8790/api/gezond; then
  echo; ok "de app draait"
else
  fout "de app reageert niet. Kijk in het logboek: journalctl -u belastinghulp-app -n 50"
  exit 1
fi

# ---------------------------------------------------------------
stap "6. nginx"
if ! grep -qE '^\s*include\s+/etc/nginx/conf\.d/\*\.conf' /etc/nginx/nginx.conf; then
  let_op "/etc/nginx/nginx.conf laadt conf.d/*.conf niet. Zie DEPLOY.md 2.3; daarna dit script opnieuw."
  exit 1
fi
STEMPEL=$(date +%F-%H%M%S)
BEWAAR=/root/nginx-backup-$STEMPEL
mkdir -p "$BEWAAR"
cp -a /etc/nginx/conf.d "$BEWAAR/conf.d"
cp -a "$SITE" "$BEWAAR/site.conf"
ok "back-up in $BEWAAR"

install -m 644 "$WEBROOT/server-setup/nginx-app.conf"       /etc/nginx/conf.d/belastinghulp-app.conf
install -m 644 "$WEBROOT/server-setup/nginx-cache-map.conf" /etc/nginx/conf.d/cache-map.conf
install -m 644 "$WEBROOT/server-setup/nginx-tellingen.conf" /etc/nginx/conf.d/tellingen.conf
ok "conf.d: belastinghulp-app.conf, cache-map.conf, tellingen.conf"

echo
echo "Verschil tussen het draaiende server-blok en de versie in de repo:"
echo "(verwacht: /api/, /beheer/, /app/, .vcf, en eerdere regels die nog niet op de server stonden."
echo " Ziet u gewijzigde ssl_-regels, antwoord dan n: dan heeft certbot iets verplaatst. Zie DEPLOY.md 2.4.)"
echo
diff "$SITE" "$WEBROOT/server-setup/nginx-belastinghulpzaanstad.conf" || true
echo
antwoord=""
read -r -p "Het server-blok vervangen door de versie uit de repo? [j/N] " antwoord || antwoord=""
if [ "$antwoord" = "j" ] || [ "$antwoord" = "J" ]; then
  cp "$WEBROOT/server-setup/nginx-belastinghulpzaanstad.conf" "$SITE"
  ok "server-blok vervangen"
else
  let_op "server-blok NIET vervangen. Zonder de regels voor /api/ werken de formulieren straks niet."
fi

if nginx -t; then
  systemctl reload nginx
  ok "nginx herladen"
else
  fout "nginx -t faalt. Alles wordt teruggezet uit $BEWAAR; de site draait door op de oude config."
  rm -f /etc/nginx/conf.d/belastinghulp-app.conf
  cp -a "$BEWAAR/conf.d/." /etc/nginx/conf.d/
  cp -a "$BEWAAR/site.conf" "$SITE"
  nginx -t && systemctl reload nginx
  exit 1
fi

# ---------------------------------------------------------------
stap "7. Controles"
if grep -qE '^\s*rotate\s+14\b' /etc/logrotate.d/nginx 2>/dev/null && grep -qE '^\s*daily\b' /etc/logrotate.d/nginx; then
  ok "nginx-logs worden dagelijks geroteerd en 14 dagen bewaard (zoals het privacybeleid zegt)"
else
  let_op "controleer /etc/logrotate.d/nginx: het privacybeleid zegt dat serverlogs na 14 dagen weg zijn (daily + rotate 14)."
fi
URL=https://belastinghulpzaanstad.nl
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
echo "  /api/gezond           $(code $URL/api/gezond)   (verwacht 200)"
echo "  /app/server.js        $(code $URL/app/server.js)   (verwacht 404)"
echo "  /beheer/              $(code $URL/beheer/)   (verwacht 404 tot module 2 live is, daarna 200 of 303)"
echo "  formulier van buiten  $(code -X POST -H 'Origin: https://kwaad.example' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept: application/json' --data 'x=1' $URL/api/aanvraag)   (verwacht 403)"

echo
echo "Klaar. Vul nu de mailgegevens in (APP.md, stap 3):"
echo "  sudo nano $ENV_BESTAND"
echo "  sudo systemctl restart belastinghulp-app"
echo "  sudo -u $GEBRUIKER node $WEBROOT/app/testmail.js info@belastinghulpzaanstad.nl"
