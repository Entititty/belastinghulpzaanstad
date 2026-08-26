# Uitrollen van belastinghulpzaanstad.nl

Deze ronde bevat naast pagina's ook twee wijzigingen die **niet** met de
git-deploy meegaan: het nginx map-bestand en het nginx server-blok. Daarom
staat hieronder de volledige volgorde.

Lees eerst §1 (waarom deze volgorde) en volg dan §2 stap voor stap.

---

## 1. Waarom deze volgorde

**De site wordt uitgerold door een cron-job op de VPS.** `auto-deploy.sh`
doet `git fetch` en, als er nieuwe commits zijn, `git reset --hard
origin/main`. De webroot is dus een spiegel van GitHub. Een `git push` naar
`main` is daarmee de uitrol; er is geen aparte stap.

**De stylesheet heeft een content-hash in de naam.** De HTML verwijst naar `belasting.<hash>.min.css`. Verandert de inhoud, dan verandert de naam
(`node scripts/hash-css.js`). Oude en nieuwe HTML verwijzen dus nooit naar
dezelfde URL met verschillende inhoud. **Daardoor is de CSS zelf-bustend en
maakt het niet uit of nginx eerder of later live gaat.** Dat was vóór deze
ronde niet zo: toen kon een bezoeker een week lang oude CSS bij nieuwe HTML
krijgen.

**Wat wél volgorde-afhankelijk is: de twee nginx-bestanden.** Het server-blok
gebruikt de variabele `$cache_control`, en die wordt gedefinieerd in de map.
Zet je het server-blok eerst, dan kent nginx die variabele niet.

| stap | volgorde-kritisch? | waarom |
|---|---|---|
| git push (pagina's + CSS) | nee | hash in de bestandsnaam |
| nginx map-bestand | **ja, eerst** | definieert `$cache_control` |
| nginx server-blok | **ja, daarna** | gebruikt `$cache_control` |

---

## 2. Stappen

### 2.1 Vooraf, op je eigen machine

```bash
cd "/pad/naar/Website belasting"

node scripts/hash-css.js            # naam en verwijzingen kloppend maken
node scripts/check-fiscale-cijfers.js
node scripts/crawl-audit.js         # verwacht: 94 pagina's, 404:0, dupTitle:0
node scripts/build-sitemap.js       # NA het committen, VOOR het pushen
```

Werkboom schoon? Dan pas verder.

### 2.2 Pagina's en CSS uitrollen

```bash
git checkout main
git merge --ff-only homepage-rework
git push
```

De cron-job pakt dit binnen een uur op. Handmatig forceren op de server:

```bash
ssh <user>@<server>
/var/www/belastinghulpzaanstad.nl/html/server-setup/auto-deploy.sh
cat /tmp/belasting-deploy.log | tail -3
```

Controleer dat de nieuwe CSS er staat en de oude weg is:

```bash
CSS=$(ls belasting.*.min.css)   # bijv. belasting.1dbc5d84.min.css
curl -o /dev/null -w "%{http_code}\n" "https://belastinghulpzaanstad.nl/$CSS"              # 200
curl -o /dev/null -w "%{http_code}\n" https://belastinghulpzaanstad.nl/belasting.min.css   # 404
```

Krijg je 404 op de eerste: de deploy is nog niet langs geweest, of de hash in
de repo is niet die van het bestand. Draai `node scripts/hash-css.js` opnieuw.

### 2.3 nginx: eerst de map

```bash
cd /var/www/belastinghulpzaanstad.nl/html

# controleer dat conf.d al binnen http { } wordt geinclude
grep -n "include /etc/nginx/conf.d" /etc/nginx/nginx.conf
```

Staat die regel er: kopieer het bestand erheen.

```bash
sudo cp server-setup/nginx-cache-map.conf /etc/nginx/conf.d/cache-map.conf
```

Staat die regel er **niet**: zet dan zelf `include /etc/nginx/conf.d/*.conf;`
binnen het `http { }`-blok van `/etc/nginx/nginx.conf`, of plak de inhoud van
het map-bestand daar rechtstreeks in. De `map`-directive **moet** in de
http-context staan; in een server-blok geeft hij
`"map" directive is not allowed here`.

Test de map alvast los:

```bash
sudo nginx -t
```

Dit moet slagen. De map alleen doet nog niets, want niemand gebruikt
`$cache_control` nog.

### 2.4 nginx: dan het server-blok

Eerst een back-up en een diff, want certbot kan het live bestand hebben
aangepast:

```bash
sudo cp /etc/nginx/sites-available/belastinghulpzaanstad.nl ~/nginx-backup-$(date +%F).conf

diff /etc/nginx/sites-available/belastinghulpzaanstad.nl \
     server-setup/nginx-belastinghulpzaanstad.conf
```

Verwacht: alleen de cache- en 404-regels. Zie je gewijzigde `ssl_`-regels,
dan heeft certbot iets verplaatst; stop dan en merge met de hand.

```bash
sudo cp server-setup/nginx-belastinghulpzaanstad.conf \
        /etc/nginx/sites-available/belastinghulpzaanstad.nl
sudo nginx -t
```

`nginx -t` moet `syntax is ok` en `test is successful` geven. **Slaat hij af,
herlaad dan niet.** Zie §3.

```bash
sudo systemctl reload nginx
```

### 2.5 De drie curl-checks

```bash
curl -sI https://belastinghulpzaanstad.nl/ \
  | grep -i "cache-control\|strict-transport"

curl -sI "https://belastinghulpzaanstad.nl/$(ls belasting.*.min.css)" \
  | grep -i "cache-control\|strict-transport"

curl -sI https://belastinghulpzaanstad.nl/fonts/nunito-sans.woff2 \
  | grep -i "cache-control\|strict-transport"
```

Verwacht:

| URL | Cache-Control | HSTS |
|---|---|---|
| `/` | `public, max-age=0, must-revalidate` | aanwezig |
| `/belasting.<hash>.min.css` | `public, max-age=31536000, immutable` | aanwezig |
| `/fonts/nunito-sans.woff2` | `public, max-age=31536000, immutable` | aanwezig |

**`Strict-Transport-Security` moet in alle drie de gevallen meekomen.** Mist
hij bij een van de statische bestanden, dan heeft er alsnog een `location`
een eigen `add_header` gekregen; in nginx erft zo'n blok de headers uit het
server-blok dan niet meer. Zoek met:

```bash
sudo nginx -T | grep -n "add_header"
```

Er horen precies zes regels te staan: HSTS in het www-redirect-blok, de vier
security headers in het server-blok, en `Cache-Control $cache_control`. Geen
enkele binnen een `location`.

En de vier paden die dicht moeten:

```bash
for p in /scripts/gsc-export.js /server-setup/auto-deploy.sh /docs/TODO-kvk-btw.md /data/gsc/totals.csv; do
  printf "%-34s " "$p"
  curl -s -o /dev/null -w "%{http_code}\n" "https://belastinghulpzaanstad.nl$p"
done
curl -s -o /dev/null -w "seizoen.json %{http_code}\n" https://belastinghulpzaanstad.nl/data/seizoen.json
```

De eerste vier moeten 404 geven, `seizoen.json` moet 200 geven. Die laatste
is de belangrijkste: hij bewijst dat het blokkeren van `/data/gsc/` de
seizoensbanner niet heeft meegenomen.

### 2.6 Na de uitrol

```bash
node scripts/indexnow.js --alles     # Bing, en daarmee ChatGPT-zoek
```

Doe dit **na** de deploy. IndexNow haalt het sleutelbestand op om te
verifieren; is de site nog niet bij, dan weigert hij.

In Search Console: `/senioren/` handmatig laten indexeren. Dat is een nieuwe
URL en Google is daar traag mee op een kleine site.

---

## 3. Wat er misgaat bij de verkeerde volgorde

### Server-blok vóór de map

```
nginx: [emerg] unknown "cache_control" variable
nginx: configuration file /etc/nginx/nginx.conf test failed
```

`nginx -t` slaat af. **Herlaad niet.** De draaiende nginx houdt de oude
configuratie in het geheugen, dus de site blijft online; alleen je nieuwe
config is niet actief. Los het op door §2.3 te doen en dan opnieuw
`sudo nginx -t`.

Heb je toch `systemctl reload nginx` gedaan met een kapotte config, dan
weigert nginx te herladen en blijft het oude proces draaien. De site gaat er
dus niet van plat. `systemctl restart nginx` zou dat wél doen: bij een
kapotte config start hij niet meer op. **Gebruik `reload`, nooit `restart`.**

### Map zonder server-blok

Niets kapot. De map staat er, niemand gebruikt hem, de headers blijven zoals
ze waren. Je mist alleen de caching.

### CSS-wijziging zonder `hash-css.js`

Dan staat er een nieuwe inhoud onder de oude bestandsnaam, en die naam is
`immutable` voor een jaar. Bestaande bezoekers houden de oude CSS tot hun
cache verloopt. Draai altijd `node scripts/hash-css.js` na een wijziging in
de stylesheet en vóór het committen.

### Git push zonder `build-sitemap.js`

De sitemap mist `/senioren/` of heeft verkeerde `lastmod`-datums. Niet
kritisch, maar draai het script en push opnieuw.

---

## 4. Terugrollen

### Alleen nginx terug

```bash
sudo cp ~/nginx-backup-$(date +%F).conf \
        /etc/nginx/sites-available/belastinghulpzaanstad.nl
sudo rm -f /etc/nginx/conf.d/cache-map.conf
sudo nginx -t && sudo systemctl reload nginx
```

Verwijder ze samen. Het server-blok zonder de map geeft `unknown
"cache_control" variable`.

### Pagina's terug

De webroot is een spiegel van `origin/main`, dus terugrollen gaat via git.

```bash
# op je eigen machine
git checkout main
git revert --no-commit <eerste-commit>..<laatste-commit>
git commit -m "Homepage-rework teruggedraaid"
git push
```

Of, als `main` alleen deze ronde bevat en nog niemand anders erop werkt:

```bash
git reset --hard <commit-voor-de-merge>
git push --force-with-lease
```

`--force-with-lease` en niet `--force`: dan mislukt het als er intussen iets
anders is gepusht.

Wacht op de cron of forceer met `auto-deploy.sh`.

### Alleen de KvK-regel

Die staat er nu niet op. Terugzetten zodra het nummer er is:

```bash
node scripts/set-kvk.js --kvk 12345678 --btw NL123456789B01
```

Zie `docs/TODO-kvk-btw.md`.

---

## 5. Korte versie

```bash
# lokaal
node scripts/hash-css.js && node scripts/check-fiscale-cijfers.js \
  && node scripts/crawl-audit.js && node scripts/build-sitemap.js
git checkout main && git merge --ff-only homepage-rework && git push

# server
cd /var/www/belastinghulpzaanstad.nl/html && ./server-setup/auto-deploy.sh
sudo cp server-setup/nginx-cache-map.conf /etc/nginx/conf.d/cache-map.conf
sudo nginx -t
sudo cp /etc/nginx/sites-available/belastinghulpzaanstad.nl ~/nginx-backup-$(date +%F).conf
sudo cp server-setup/nginx-belastinghulpzaanstad.conf \
        /etc/nginx/sites-available/belastinghulpzaanstad.nl
sudo nginx -t && sudo systemctl reload nginx

# controleren, dan
node scripts/indexnow.js --alles
```
