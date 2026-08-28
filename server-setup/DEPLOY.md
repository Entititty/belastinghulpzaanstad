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
| kopie onder de oude CSS-naam | eenmalig, na de deploy | oude HTML in browsercaches vraagt die naam nog op, zie §2.2 |
| nginx map-bestand | **ja, eerst** | definieert `$cache_control` |
| nginx map-bestand voor de tellingen | **ja, eerst** | definieert `$tel_dag`, `$tel_mee` en het logformaat |
| nginx server-blok | **ja, daarna** | gebruikt `$cache_control`, `$tel_dag` en `$tel_mee` |

De hash lost het probleem op voor HTML die nog gedownload moet worden, niet
voor HTML die iemand al in zijn cache heeft. Dat verschil is de reden voor
die tweede regel.

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

#### Eenmalig bij deze uitrol: de oude bestandsnaam even laten staan

De hash maakt nieuwe HTML zelf-bustend, maar er loopt ook nog **oude** HTML
rond in browsercaches, en die verwijst naar `belasting.min.css`. Dat bestand
verdwijnt bij deze uitrol.

Meting op de live site, 27 augustus 2026:

```
Last-Modified: Sat, 15 Aug 2026 15:48:34 GMT
(geen Cache-Control)
```

Zonder `Cache-Control` verzint een browser zelf een houdbaarheid: ongeveer
10 % van de leeftijd van het document. Twaalf dagen oud betekent ruim
**een dag** dat een terugkerende bezoeker zijn oude HTML hergebruikt. Die
HTML vraagt `belasting.min.css` op, krijgt 404, en toont een pagina zonder
opmaak.

Zet daarom na de deploy eenmalig een kopie onder de oude naam:

```bash
cd /var/www/belastinghulpzaanstad.nl/html
cp "$(ls belasting.*.min.css)" belasting.min.css
```

Dat bestand is niet getrackt en `git reset --hard` verwijdert het niet, dus
het overleeft de volgende deploys. Haal het na twee dagen weg:

```bash
rm /var/www/belastinghulpzaanstad.nl/html/belasting.min.css
```

Dit is eenmalig. Zodra de map uit §2.3 staat, krijgt HTML
`max-age=0, must-revalidate` en kan dit niet meer gebeuren. Doe §2.3 dus
snel na de deploy, niet volgende week.

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
sudo nginx -T | grep -nE "^[[:space:]]*add_header"
```

Er horen precies zes regels te staan: HSTS in het www-redirect-blok, de vier
security headers in het server-blok, en `Cache-Control $cache_control`. Geen
enkele binnen een `location`.

Let op de `^[[:space:]]*` in die grep. Zonder die ankering telt hij ook de
commentaarregel mee die het woord `add_header` bevat, en dan krijg je zeven
treffers terwijl er zes directives zijn. Dat lijkt op een fout en is het niet.

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

### 2.6 Conversiemeting aanzetten

Dit is het enige deel van deze ronde dat **niet** met de git-deploy meekomt.
De pagina's en `js/tellingen.js` komen er vanzelf op, maar nginx moet een map
hebben om in te schrijven, en de maps en het logformaat moeten in de
http-context staan.

#### Wat er gemeten wordt

Vijf dingen: een klik op WhatsApp, op een telefoonnummer, op een e-mailadres,
het versturen van een formulier, en het halverwege verlaten van een formulier.
`js/tellingen.js` stuurt met `sendBeacon` een leeg POST-verzoek naar `/t`,
nginx antwoordt 204 en schrijft er een regel over weg:

```
{"t":"2026-08-28T14:00","e":"whatsapp","p":"/senioren/","v":""}
```

Tijdstip op het hele uur, gebeurtenis, pad, en bij afhaken de naam van het
laatst aangeraakte veld. **Geen IP-adres, geen user-agent, geen sessie, geen
verwijzende pagina, geen cookie.** Daarom is er geen toestemming nodig en staat
deze meting los van de cookiebalk. Veldwaarden gaan er nooit in; alleen namen
uit de lijst in `js/tellingen.js`, en een naam die daar niet op staat wordt
`overig`.

Er draait geen programma. Een access_log is append-only: de kernel schrijft met
`O_APPEND`, dus twee gelijktijdige klikken kunnen elkaar niet overschrijven.
Dat was de reden om geen JSON-bestand te gebruiken dat elke keer opnieuw wordt
weggeschreven.

#### 1. Een map om in te schrijven

```bash
sudo install -d -o www-data -g www-data -m 750 /var/log/belastinghulp/tellingen
date -I | sudo tee /var/log/belastinghulp/tellingen/START
```

**Buiten de webroot, en met opzet.** De webroot is de repo-root; een vergeten
nginx-regel zou de cijfers publiek downloadbaar maken. In `/var/log` kan dat
niet. Eigenaar `www-data`, want dat is de gebruiker waaronder de
nginx-workers draaien.

`START` bevat de datum waarop je begint te meten. Het overzicht zet die datum
bovenaan, zodat je later niet vergelijkt met een periode waarin er nog niets
gemeten werd.

**Voeg hier geen logrotate-regel voor toe.** nginx maakt zelf al een bestand
per dag; logrotate zou daar overheen gaan. De bewaartermijn staat verderop.

#### 2. De maps en het logformaat, vóór het server-blok

```bash
sudo cp server-setup/nginx-tellingen.conf /etc/nginx/conf.d/tellingen.conf
sudo nginx -t
```

Zelfde volgorde-eis als bij de cache-map, en om dezelfde reden: het server-blok
gebruikt `$tel_dag`, `$tel_mee` en het logformaat `tellingen`. Zet je het
server-blok eerst, dan slaat `nginx -t` af met `unknown "tel_dag" variable`.

#### 3. Je eigen IP-adres, zodat je jezelf niet meetelt

```bash
curl -s https://api.ipify.org; echo      # IPv4
curl -s https://api64.ipify.org; echo    # IPv6, als je die hebt

sudo tee /etc/nginx/conf.d/eigen-ip.map <<'IPS'
198.51.100.24  0;
IPS

sudo nginx -t && sudo systemctl reload nginx
```

Let op de puntkomma achter elke regel. Vervang het adres door dat van jezelf.
Bestaat het bestand niet, dan is dat geen fout: de include in
`nginx-tellingen.conf` gebruikt een sterretje en nginx slaat een patroon
zonder treffers over.

**Waarom twee filters voor eigen bezoek.** `?mijzelf=1` zet dit apparaat uit,
maar dat zit in localStorage en werkt dus per apparaat en per browser. Het
IP-filter werkt wél voor elk apparaat tegelijk: laptop, telefoon op de wifi,
tablet. Zit je op 4G, dan valt je telefoon buiten het IP-filter; open daar dan
eenmalig `https://belastinghulpzaanstad.nl/?mijzelf=1`. Er verschijnt een
groene balk als het gelukt is. `?mijzelf=0` zet hem weer aan.

Het IP-adres staat bewust niet in git. Het is een persoonsgegeven en de
repo-root is de webroot.

#### 4. Controleren dat POST wordt aangenomen

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST "https://belastinghulpzaanstad.nl/t?e=whatsapp&p=/test/"
```

Verwacht **204**. Krijg je 405, dan draait de oude config nog; krijg je 404,
dan mist `location = /t`. Kijk daarna of de regel er staat:

```bash
sudo cat /var/log/belastinghulp/tellingen/$(date -I).ndjson
```

Staat er niets, loop dan deze drie langs:

| geen regel omdat | controleer met |
|---|---|
| je eigen IP staat in `eigen-ip.map` (dit is de bedoeling) | test vanaf je telefoon op 4G |
| `curl` telt als bot, want de UA bevat "curl" | gebruik `-A "Mozilla/5.0"` |
| nginx mag niet in de map schrijven | `sudo -u www-data touch /var/log/belastinghulp/tellingen/x` |

En controleer dat het overzicht niet publiek is:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://belastinghulpzaanstad.nl/intern/tellingen/
```

Verwacht **404**.

#### 5. Uitlezen

Op de server, als daar Node op staat (`node -v`):

```bash
cd /var/www/belastinghulpzaanstad.nl/html
node scripts/tellingen-rapport.js --bron /var/log/belastinghulp/tellingen
```

Dat drukt de tabellen in de terminal af en schrijft `intern/tellingen/index.html`.
Staat er geen Node op de server, dan hoeft dat ook niet:

```bash
# op je eigen machine
rsync -av <user>@<server>:/var/log/belastinghulp/tellingen/ data/tellingen/
node scripts/tellingen-rapport.js
```

Het overzicht komt dan lokaal in `intern/tellingen/index.html`; open dat met
je browser. `/intern/` geeft op de server met opzet 404, dus in de browser
kun je er niet bij — dat is de prijs voor niet publiceren. `data/tellingen/`
en `intern/` staan in `.gitignore`.

#### 6. Bewaartermijn

Ruwe regels blijven **90 dagen** staan. Daarna houdt het script alleen de
dagtotalen per gebeurtenis over, zonder pagina en zonder veldnaam, in
`dagtotalen.json`. Wekelijks, als root, want de bestanden zijn van
`www-data`:

```
7 4 * * 1 cd /var/www/belastinghulpzaanstad.nl/html && /usr/bin/node scripts/tellingen-rapport.js --bron /var/log/belastinghulp/tellingen --opruimen >/dev/null 2>&1
```

Draai je het nooit, dan blijven de regels staan. Ze bevatten geen
persoonsgegevens, dus dat is geen datalek, maar de map groeit wel.

---

### 2.7 Na de uitrol

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

### `unexpected "{" in cache-map.conf`

```
nginx: [emerg] unexpected "{" in /etc/nginx/conf.d/cache-map.conf:26
```

nginx ziet `{` en `}` als begin en einde van een blok. Een parameter met een
accolade erin, zoals de regex `[0-9a-f]{8}`, moet dus tussen aanhalingstekens.
Zonder quotes leest nginx `{8}` als een nieuw blok en slaat af.

Dit is opgelost in de repo. Zie je het toch: haal de nieuwe versie op met
`git pull` en kopieer het bestand opnieuw. `nginx -t` slaat hier af voordat
er iets herlaadt, dus de site merkt er niets van.

### Server-blok vóór `tellingen.conf`

```
nginx: [emerg] unknown "tel_dag" variable
```

Of `unknown log format "tellingen"`. Zelfde geval als hierboven: `nginx -t`
slaat af, de draaiende nginx houdt de oude config, de site blijft online. Doe
§2.6 stap 2 en test opnieuw.

### Wel 204, maar geen regel in het dagbestand

Dat is meestal goed nieuws: je eigen IP staat in `eigen-ip.map`. Zie de tabel
in §2.6 stap 4 voor de drie oorzaken. De belangrijkste om uit te sluiten is de
laatste: als nginx niet in de map mag schrijven, staat er in
`/var/log/nginx/error.log` een regel met `Permission denied`.

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

### Alleen de meting uit

De meting zit in de pagina's en in nginx. Los van elkaar uit te zetten:

```bash
# alleen de logregels stoppen, script blijft draaien maar krijgt 404
sudo rm /etc/nginx/conf.d/tellingen.conf
# dan MOET ook location = /t uit het server-blok, anders geeft nginx -t
# unknown "tel_dag" variable
sudo nginx -t && sudo systemctl reload nginx
```

Laat je `location = /t` staan en haal je alleen het map-bestand weg, dan
weigert nginx te herladen. De site blijft draaien op de oude config, maar je
wijziging is niet actief. Haal ze samen weg, net als bij de cache-map.

De verzoeken van de bezoeker gaan dan naar niets. Dat is geen probleem:
`sendBeacon` wacht nergens op en de pagina merkt er niets van.

Wil je het script er ook uit:

```bash
grep -rl 'js/tellingen.js' --include=index.html . | xargs sed -i '/js/tellingen.js/d'
```

De verzamelde regels blijven staan in `/var/log/belastinghulp/tellingen/`.

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
sudo cp server-setup/nginx-tellingen.conf  /etc/nginx/conf.d/tellingen.conf
sudo install -d -o www-data -g www-data -m 750 /var/log/belastinghulp/tellingen
date -I | sudo tee /var/log/belastinghulp/tellingen/START
sudo nginx -t
sudo cp /etc/nginx/sites-available/belastinghulpzaanstad.nl ~/nginx-backup-$(date +%F).conf
sudo cp server-setup/nginx-belastinghulpzaanstad.conf \
        /etc/nginx/sites-available/belastinghulpzaanstad.nl
sudo nginx -t && sudo systemctl reload nginx

# controleren, dan
node scripts/indexnow.js --alles
```
