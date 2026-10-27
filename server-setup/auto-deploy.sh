#!/usr/bin/env bash
# ============================================================
#  Auto-deploy voor belastinghulpzaanstad.nl
#  Spiegelt de live web-root aan GitHub 'main'.
#  Draait als cron-job op de VPS (zie AUTO-DEPLOY-SETUP.md).
#
#  - Geen inkomende SSH nodig, geen secrets.
#  - Pullt alleen als er echt nieuwe commits zijn.
#  - 'reset --hard' zorgt dat de map exact gelijk is aan GitHub.
#    (Raakt alleen door git gevolgde bestanden; laat server-only
#     bestanden die niet in git staan met rust.)
#  - Daarna meldt het de gewijzigde pagina's bij IndexNow. Zo weet Bing
#    meteen welke pagina's nieuw zijn, en Bing is de zoekmachine achter
#    ChatGPT en Copilot. Mislukt dat, dan staat de uitrol gewoon.
#    (Een nieuwe versie van dit script geldt pas vanaf de uitrol erna:
#     bash leest door in de oude versie die al draait.)
# ============================================================
set -euo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin

REPO_DIR="/var/www/belastinghulpzaanstad.nl/html"
BRANCH="main"
LOG="/tmp/belasting-deploy.log"

# Voorkom dat twee runs elkaar overlappen
exec 9>/tmp/belasting-deploy.lock
flock -n 9 || exit 0

cd "$REPO_DIR"

git fetch --quiet origin "$BRANCH"
LOCAL="$(git rev-parse HEAD)"
REMOTE="$(git rev-parse "origin/$BRANCH")"

if [ "$LOCAL" != "$REMOTE" ]; then
  git reset --hard "origin/$BRANCH" >>"$LOG" 2>&1
  echo "$(date -Is) deployed ${REMOTE:0:8} (was ${LOCAL:0:8})" >>"$LOG"
  if command -v node >/dev/null 2>&1; then
    node scripts/indexnow.js --sinds "$LOCAL" >>"$LOG" 2>&1 \
      || echo "$(date -Is) indexnow mislukt (uitrol staat wel)" >>"$LOG"
  fi
fi
