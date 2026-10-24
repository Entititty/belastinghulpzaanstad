# De app: aanvragen, herinneringslijst en beheer

Sinds november 2026 komen de formulieren van de site niet meer bij Formspree
binnen, maar bij een klein programma op de eigen server. Dit document gaat over
dat programma: wat het is, hoe je het één keer installeert, hoe je de mail
instelt, en hoe je controleert dat alles werkt.

Lees §1 en §2 eerst. Daarna §3 tot en met §5 in volgorde.

---

## 1. Wat het is

```
bezoeker ── formulier ──▶ nginx ──/api/──▶ app (Node, 127.0.0.1:8790) ──▶ database
                                                   │
                                                   └──▶ Brevo ──▶ mail aan jou
```

- **De app** is één Node-programma zonder extra pakketten. Het draait als
  systemd-dienst `belastinghulp-app` onder een eigen gebruiker `bhz-app`, en
  luistert alleen op de server zelf (127.0.0.1). nginx stuurt `/api/` en
  `/beheer/` erheen.
- **De database** is één SQLite-bestand. Er draait geen databaseserver; SQLite
  zit in Node zelf.
- **De mail** gaat via Brevo: een melding per aanvraag, de bevestigingsmail
  van de herinneringslijst, en de herinnering zelf.
- **Na een uitrol** ziet de app binnen een minuut dat `git reset --hard` iets
  nieuws heeft neergezet, stopt netjes, en systemd start hem opnieuw met de
  nieuwe code. Daarvoor hoef je niets te doen.

Waarom niet alles in nginx, zoals de klikmeting? Een database, een login en
mail versturen kan nginx niet. Om de risico's klein te houden:
- geen npm-pakketten, dus naast Node zelf niets om bij te houden;
- Node gaat mee met de automatische updates;
- de dienst mag alleen in zijn eigen twee mappen schrijven.

Ligt de app toch plat, dan krijgt een bezoeker bij het versturen de melding
"Bel of app ons op 06 19 71 18 48". De klikmeting (`/t`) blijft gewoon in nginx
en merkt er niets van.

### Wat waar staat

| wat | waar | in git? |
|---|---|---|
| code | `/var/www/belastinghulpzaanstad.nl/html/app/` | ja (nginx geeft 404 op `/app/`) |
| publieke instellingen | `data/aanvraag.json` | ja |
| geheimen (mail, app-geheim) | `/etc/belastinghulp/app.env` | **nooit** |
| database | `/var/lib/belastinghulp/leads.db` | **nooit** |
| back-ups (vanaf module 2) | `/var/backups/belastinghulp/` | **nooit** |
| logboek | `journalctl -u belastinghulp-app` | n.v.t. |

In het logboek staan geen namen, telefoonnummers of e-mailadressen, alleen
nummers van aanvragen en soorten gebeurtenissen.

---

## 2. Twee uitrolstappen

Er mag geen moment zijn waarop een formulier naar een server wijst die nog
niet klaar is. Daarom gaat het in twee stappen:

| stap | wat er live komt | formulieren gaan naar |
|---|---|---|
| **Release A** | de app, de serverbestanden, de klikmeting met knop en bron | nog Formspree |
| **Release B** | de formulieren, /bedankt/, de herinneringslijst, /beheer, het nieuwe privacybeleid | de app |

Tussen A en B doe je §3 tot en met §5 van dit document. Pas als §5 helemaal
klopt, rol je B uit.

---

## 3. Installeren (eenmalig)

Na de uitrol van Release A (`git push`, en de cron of
`./server-setup/auto-deploy.sh` is langs geweest):

```bash
ssh <user>@<server>
sudo bash /var/www/belastinghulpzaanstad.nl/html/server-setup/app-installeren.sh
```

Het script legt bij elke stap uit wat het doet. Opnieuw draaien kan altijd;
`app.env` overschrijft het nooit. Wat het doet:

1. **Node.js 24** van NodeSource, en een regel zodat de automatische updates
   Node meenemen.
2. **Gebruiker en mappen**: `bhz-app`, `/var/lib/belastinghulp` en
   `/var/backups/belastinghulp`, allebei alleen voor die gebruiker.
3. **`/etc/belastinghulp/app.env`** uit `server-setup/app.env.voorbeeld`, met
   een nieuw willekeurig `BHZ_GEHEIM`.
4. **De map voor de klikmeting**, als die er nog niet was (DEPLOY.md §2.6).
5. **De dienst** `belastinghulp-app`: neerzetten, aanzetten en starten.
   Het script stopt als de app niet reageert.
6. **nginx**. Eerst een back-up van `conf.d` en het server-blok in
   `/root/nginx-backup-<datum>/`. Dan:
   - drie bestanden in `/etc/nginx/conf.d/`:
     - `belastinghulp-app.conf` (de limieten en het adres van de app);
     - `cache-map.conf`, nu met no-store voor `/api/` en `/beheer/`;
     - `tellingen.conf`, met het nieuwe logformaat waarin knop, bron en campagne staan.
   - Het script toont het **verschil** tussen het draaiende server-blok en de
     versie in de repo, en vraagt of het mag vervangen. Verwacht in dat
     verschil:
     - `/api/`, `/beheer/`, `/app/` en `.vcf`;
     - de regels uit DEPLOY.md §4b die nog niet op de server stonden (de 301's
       voor de samengevoegde artikelen en de eigen 404-pagina).

     Zie je gewijzigde `ssl_`-regels, antwoord dan **n**: dan heeft certbot iets
     verplaatst en moet je met de hand samenvoegen (DEPLOY.md §2.4).
   - `nginx -t`. Slaat die af, dan zet het script alles terug uit de back-up
     en draait de site door op de oude config.
7. **Controles**: de logrotatie van nginx (het privacybeleid zegt dat
   serverlogs na 14 dagen weg zijn) en vier curl-verzoeken.

---

## 4. Mail instellen met Brevo

Je domein kan nu alleen mail **ontvangen**: Porkbun stuurt `info@` door. Om te
kunnen **versturen** vanaf `info@belastinghulpzaanstad.nl` gebruikt de app
Brevo. Het gratis abonnement is ruim genoeg; de app verstuurt de jaarlijkse
herinnering in porties van hoogstens 250 per dag, onder de daggrens van Brevo.

De namen van knoppen en menu's in Brevo kunnen iets afwijken van wat hieronder
staat. Zoek dan op het woord tussen aanhalingstekens.

### 4a. Account

Maak een account aan op brevo.com met `info@belastinghulpzaanstad.nl`.

### 4b. Het domein verifiëren (DNS bij Porkbun)

In Brevo, bij "Senders, Domains" (of "Afzenders en domeinen"): voeg het domein
`belastinghulpzaanstad.nl` toe. Brevo toont dan een paar DNS-records:
- een verificatiecode (TXT);
- DKIM (een of twee records);
- een DMARC-voorstel.

Zet die bij Porkbun onder Domain Management > DNS, precies zoals Brevo ze
toont. Let op:

- **Laat de bestaande MX-records en het SPF-record staan.** Die regelen het
  doorsturen van `info@`.
- **Er mag maar één SPF-record zijn** (het TXT-record dat met `v=spf1` begint).
  Vraagt Brevo om een SPF-regel, zet dan het stukje dat Brevo noemt (`include:...`)
  in het bestaande record, voor `~all`. Maak geen tweede SPF-record.
- **DMARC**: er is nu geen DMARC-record. Neem het voorstel van Brevo over, met
  `p=none` om te beginnen. Gmail en Yahoo eisen DMARC van afzenders die
  regelmatig mailen.

Klik in Brevo op "Verify" / "Authenticate". DNS kan tot een paar uur duren.

Controleren vanaf je eigen machine:

```bash
nslookup -type=TXT _dmarc.belastinghulpzaanstad.nl
nslookup -type=TXT belastinghulpzaanstad.nl        # één regel met v=spf1
```

### 4c. SMTP-sleutel

In Brevo, bij "SMTP & API" > "SMTP": maak een SMTP-sleutel aan. Je hebt twee
dingen nodig:
- de **Login** die daar staat;
- de **SMTP-sleutel** zelf. Die zie je maar één keer.

Het is géén Brevo-wachtwoord en géén API-sleutel.

### 4d. In app.env zetten

```bash
sudo nano /etc/belastinghulp/app.env
```

Vul in:

```
SMTP_GEBRUIKER=<de Login uit Brevo>
SMTP_WACHTWOORD=<de SMTP-sleutel>
```

`SMTP_HOST=smtp-relay.brevo.com` en `SMTP_POORT=2525` staan er al. **Poort
2525 en niet 587:** DigitalOcean blokkeert op nieuwe accounts de mailpoorten
25, 465 en 587. Brevo neemt op 2525 dezelfde versleutelde verbinding aan
(STARTTLS; getest op 24 oktober 2026).

Opslaan, dan:

```bash
sudo systemctl restart belastinghulp-app
sudo -u bhz-app node /var/www/belastinghulpzaanstad.nl/html/app/testmail.js info@belastinghulpzaanstad.nl
```

`testmail.js` verstuurt één proefmail rechtstreeks en zegt in gewone taal wat
er mis is als het niet lukt:

| melding | oorzaak en oplossing |
|---|---|
| `kan niet verbinden`, `ECONNREFUSED`, `geen antwoord` | De poort is dicht. Zie het vangnet hieronder. |
| `535`, `authent` | Login of sleutel klopt niet. Kopieer ze opnieuw uit Brevo. |
| `sender`, `domain` | Het domein is nog niet geverifieerd in Brevo (stap 4b). |

**Vangnet als ook poort 2525 dicht is:** maak in Brevo bij "SMTP & API" >
"API keys" een API-sleutel aan, en zet in `app.env`:

```
MAIL_VIA=brevo-api
BREVO_API_SLEUTEL=<de API-sleutel>
```

De mail gaat dan via gewone HTTPS (poort 443), die DigitalOcean nooit
blokkeert. Herstart en draai `testmail.js` opnieuw.

---

## 5. Controleren

Alle vijf moeten kloppen voordat je Release B uitrolt.

```bash
# 1. De app reageert, met de juiste versie en de mail ingesteld
curl -s http://127.0.0.1:8790/api/gezond; echo
# verwacht: {"ok":true,"commit":"<eerste 8 tekens van de laatste commit>","mail":"ingesteld","wachtrij":{"wacht":0,"gestopt":0}}

# 2. Via nginx, van buiten: alleen ok
curl -s https://belastinghulpzaanstad.nl/api/gezond; echo          # {"ok":true}

# 3. De code is niet op te vragen
curl -s -o /dev/null -w "%{http_code}\n" https://belastinghulpzaanstad.nl/app/server.js   # 404
```

**4. Een proefaanvraag**, zoals het formulier hem straks stuurt:

```bash
curl -s -X POST https://belastinghulpzaanstad.nl/api/aanvraag \
  -H "Origin: https://belastinghulpzaanstad.nl" -H "Accept: application/json" \
  --data-urlencode "formulier=terugbellen" --data-urlencode "toestemming_versie=terugbellen-2026-10" \
  --data-urlencode "naam=Proef Aanvraag" --data-urlencode "telefoon=06 12 34 56 78" \
  --data-urlencode "dienst=aangifte" --data-urlencode "akkoord=on" --data-urlencode "h_pagina=/contact/"; echo
# verwacht: {"ok":true,"volgende":"/bedankt/"}
```

Binnen een minuut moet op `info@` een mail binnenkomen met als onderwerp
"Nieuwe aanvraag: Belastingaangifte", met een knop om te bellen en een knop
voor WhatsApp. Haal de proefaanvraag daarna weer weg:

```bash
sudo -u bhz-app node --disable-warning=ExperimentalWarning -e "const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync('/var/lib/belastinghulp/leads.db');console.log(d.prepare(\"DELETE FROM aanvragen WHERE naam='Proef Aanvraag'\").run().changes+' verwijderd')"
```

**5. De limiet**: acht keer snel achter elkaar.

```bash
for i in 1 2 3 4 5 6 7 8; do curl -s -o /dev/null -w "%{http_code} " -X POST https://belastinghulpzaanstad.nl/api/aanvraag -H "Accept: application/json" --data "x=1"; done; echo
# verwacht: een paar keer 422 (formulier niet compleet), daarna alleen nog 429
```

De app laat per IP-adres vijf aanvragen per uur toe en nginx zes per minuut.
Na deze proef doet het adres van de server zelf dus een uur niet mee. Een
bezoeker merkt daar niets van.

---

## 6. Dagelijks

- **Kijken of hij draait**: `systemctl status belastinghulp-app`
- **Logboek**: `journalctl -u belastinghulp-app -n 100`. Zoek naar `[fout]`.
- **Herstarten** (na het aanpassen van `app.env`):
  `sudo systemctl restart belastinghulp-app`
- **Mails die blijven hangen**: `curl -s http://127.0.0.1:8790/api/gezond`
  toont de wachtrij. De app probeert het na 1, 5, 15 en daarna elke 60
  minuten opnieuw, tot 48 uur. Een aanvraag zelf raakt nooit kwijt: die staat
  in de database, ook als de melding niet aankomt.

## 7. Terugdraaien

**Alleen de app uit** (de site zelf blijft gewoon werken):

```bash
sudo systemctl disable --now belastinghulp-app
```

Na Release B geven de formulieren dan de melding "Bel of app ons". Wil je terug
naar Formspree, draai dan de commit van Release B terug (`git revert`) en push.

**nginx terug**: de back-up staat in `/root/nginx-backup-<datum>/`.

```bash
sudo cp /root/nginx-backup-<datum>/site.conf /etc/nginx/sites-available/belastinghulpzaanstad.nl
sudo rm /etc/nginx/conf.d/belastinghulp-app.conf
sudo nginx -t && sudo systemctl reload nginx
```

Haal het server-blok en `belastinghulp-app.conf` samen terug. Het server-blok
zonder dat bestand geeft `zero size shared memory zone "bhz_formulier"`.
