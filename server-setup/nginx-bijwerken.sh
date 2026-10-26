#!/usr/bin/env bash
# ============================================================
#  nginx bijwerken naar de versie in de repo
#
#  Na een uitrol waarin server-setup/nginx-*.conf is veranderd:
#    sudo bash /var/www/belastinghulpzaanstad.nl/html/server-setup/nginx-bijwerken.sh
#
#  Wat het doet:
#   1. back-up van conf.d en het server-blok naar /root/nginx-backup-<tijd>
#   2. de drie bestanden in conf.d bijwerken (app, cache-map, tellingen)
#   3. het verschil met het draaiende server-blok laten zien; na uw "j" vervangen
#   4. nginx -t; gaat dat goed, dan herladen, anders alles terugzetten
#   5. controleren: HTTP/2, /.git/ en .md dicht, en de site zelf
#
#  Opnieuw draaien kan altijd. Het is stap 6 van app-installeren.sh, zonder
#  de rest van de installatie. Uitleg: server-setup/DEPLOY.md, 4c.
# ============================================================
set -euo pipefail

WEBROOT=/var/www/belastinghulpzaanstad.nl/html
SITE=/etc/nginx/sites-available/belastinghulpzaanstad.nl
REPO_SITE=$WEBROOT/server-setup/nginx-belastinghulpzaanstad.conf
URL=https://belastinghulpzaanstad.nl
CONFD="belastinghulp-app.conf:nginx-app.conf cache-map.conf:nginx-cache-map.conf tellingen.conf:nginx-tellingen.conf"

GROEN='\033[0;32m'; GEEL='\033[1;33m'; ROOD='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GROEN}[OK]${NC} $1"; }
let_op() { echo -e "${GEEL}[!!]${NC} $1"; }
fout() { echo -e "${ROOD}[FOUT]${NC} $1"; }
stap() { echo; echo "=== $1"; }

[ "$(id -u)" -eq 0 ] || { fout "Draai dit met sudo."; exit 1; }
[ -f "$REPO_SITE" ] || { fout "$REPO_SITE ontbreekt."; exit 1; }
if ! grep -qE '^\s*listen 443 ssl http2;' "$REPO_SITE"; then
  fout "De repo op de server heeft de nieuwe config nog niet. Is de uitrol al langs geweest? (tail /tmp/belasting-deploy.log)"
  exit 1
fi

# ---------------------------------------------------------------
stap "1. Back-up"
STEMPEL=$(date +%F-%H%M%S)
BEWAAR=/root/nginx-backup-$STEMPEL
mkdir -p "$BEWAAR"
cp -a /etc/nginx/conf.d "$BEWAAR/conf.d"
cp -a "$SITE" "$BEWAAR/site.conf"
ok "back-up in $BEWAAR"

terugzetten() {
  for paar in $CONFD; do
    doel=${paar%%:*}
    if [ -f "$BEWAAR/conf.d/$doel" ]; then cp -a "$BEWAAR/conf.d/$doel" /etc/nginx/conf.d/; else rm -f "/etc/nginx/conf.d/$doel"; fi
  done
  cp -a "$BEWAAR/site.conf" "$SITE"
}

# ---------------------------------------------------------------
stap "2. conf.d"
for paar in $CONFD; do
  install -m 644 "$WEBROOT/server-setup/${paar#*:}" "/etc/nginx/conf.d/${paar%%:*}"
done
ok "conf.d: belastinghulp-app.conf, cache-map.conf, tellingen.conf"

# ---------------------------------------------------------------
stap "3. Server-blok"
if diff -q "$SITE" "$REPO_SITE" >/dev/null; then
  ok "het server-blok is al gelijk aan de repo"
else
  echo "Verschil tussen het draaiende server-blok (<) en de repo (>)."
  echo "Verwacht bij de uitrol van oktober 2026: http2 bij de twee listen-regels,"
  echo "charset utf-8, de regels voor /.git/ en .md, en wat commentaar."
  echo "Ziet u gewijzigde ssl_-regels, antwoord dan n: dan heeft certbot iets"
  echo "verplaatst. Zie DEPLOY.md 2.4."
  echo
  diff "$SITE" "$REPO_SITE" || true
  echo
  antwoord=""
  read -r -p "Het server-blok vervangen door de versie uit de repo? [j/N] " antwoord || antwoord=""
  if [ "$antwoord" = "j" ] || [ "$antwoord" = "J" ]; then
    cp "$REPO_SITE" "$SITE"
    ok "server-blok vervangen"
  else
    let_op "server-blok NIET vervangen; alleen conf.d is bijgewerkt."
  fi
fi

# ---------------------------------------------------------------
stap "4. nginx -t en herladen"
if nginx -t; then
  systemctl reload nginx
  ok "nginx herladen"
else
  fout "nginx -t faalt. Alles wordt teruggezet uit $BEWAAR; de site draait door op de oude config."
  terugzetten
  nginx -t && systemctl reload nginx
  exit 1
fi

# ---------------------------------------------------------------
stap "5. Controles"
# "|| true": een curl die faalt geeft 000 en mag het script niet stoppen (set -e)
code() { curl -s -o /dev/null -w "%{http_code}" "$@" || true; }
verwacht() {   # verwacht <code> <pad> <omschrijving>
  local c
  c=$(code "$URL$2")
  if [ "$c" = "$1" ]; then ok "$3 ($2: $c)"; else let_op "$3: $2 geeft $c, verwacht $1"; fi
}
versie=$(curl -s -o /dev/null --http2 -w "%{http_version}" "$URL/" || echo "?")
if [ "$versie" = "2" ]; then ok "HTTP/2 staat aan"; else let_op "de site praat HTTP/$versie, niet HTTP/2. Is het server-blok vervangen?"; fi
verwacht 200 / "homepage"
CSS=$(cd "$WEBROOT" && ls belasting.*.min.css 2>/dev/null | head -1 || true)
[ -n "$CSS" ] && verwacht 200 "/$CSS" "stylesheet"
verwacht 200 /fonts/bhz-serif-2026-10.woff2 "lettertype"
verwacht 200 /api/gezond "app"
verwacht 404 /.git/HEAD "git-map dicht"
verwacht 404 /AUDIT.md "werkdocumenten dicht"
verwacht 404 /scripts/bouw.js "scripts dicht"
type=$(curl -s -o /dev/null -w "%{content_type}" "$URL/llms.txt" || true)
if echo "$type" | grep -qi 'charset=utf-8'; then ok "llms.txt als UTF-8 ($type)"; else let_op "llms.txt zonder charset: $type"; fi
hsts=$(curl -sI "$URL/fonts/bhz-serif-2026-10.woff2" | grep -ci '^strict-transport-security' || true)
if [ "$hsts" -ge 1 ]; then ok "security headers komen mee"; else let_op "Strict-Transport-Security ontbreekt bij de lettertypen"; fi

echo
echo "Klaar. Terug naar de vorige config:"
echo "  sudo cp $BEWAAR/site.conf $SITE && sudo cp -a $BEWAAR/conf.d/. /etc/nginx/conf.d/ && sudo nginx -t && sudo systemctl reload nginx"
