# Auto-deploy instellen (eenmalig, op de VPS)

Doel: na een `git push` naar GitHub wordt de live site **automatisch** bijgewerkt,
zonder handmatig `git pull`. Een cron-job op de server checkt elke 2 minuten of er
nieuwe commits zijn en spiegelt dan `/var/www/belastinghulpzaanstad.nl` aan GitHub.

Je hoeft dit **maar één keer** te doen.

## Stap 1 — dit script op de server krijgen (laatste handmatige pull)

SSH naar de server en pull nog één keer handmatig, zodat `auto-deploy.sh` op de
server staat:

```bash
cd /var/www/belastinghulpzaanstad.nl
git pull origin main
chmod +x server-setup/auto-deploy.sh
```

## Stap 2 — script testen

```bash
./server-setup/auto-deploy.sh
cat /tmp/belasting-deploy.log   # bij een update zie je hier een regel; anders leeg = ok
```

Geen foutmelding? Dan werkt het.

## Stap 3 — cron-job installeren

Open de crontab van de gebruiker die eigenaar is van `/var/www/...`
(dezelfde gebruiker waarmee je zojuist pullde):

```bash
crontab -e
```

Voeg onderaan deze regel toe en sla op:

```cron
*/2 * * * * /var/www/belastinghulpzaanstad.nl/server-setup/auto-deploy.sh
```

Klaar. Vanaf nu is publiceren = **alleen pushen naar GitHub**; binnen ~2 minuten
staat het live.

## Controleren of het loopt

```bash
crontab -l                       # toont de regel
tail -n 5 /tmp/belasting-deploy.log   # toont de laatste deploys
```

## Handig om te weten

- **Vertraging:** maximaal ~2 minuten. Sneller nodig? Zet `*/2` op `*/1`.
- **Veilig:** er gaat geen poort open en er staan geen sleutels in GitHub. De server
  haalt zelf op via het publieke GitHub-repo (HTTPS).
- **Terugdraaien:** verwijder de cron-regel met `crontab -e` om auto-deploy te stoppen.
- **`reset --hard`:** de server-map wordt exact gelijk aan GitHub. Bewerk daarom nooit
  bestanden rechtstreeks op de server — wijzigingen daar worden bij de volgende deploy
  overschreven. Alles gaat via een commit + push.
