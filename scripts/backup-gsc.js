#!/usr/bin/env node
/*
 * backup-gsc.js
 * Kopieert het meetarchief naar een map BUITEN de repo.
 *
 * Waarom dit nodig is:
 *   - Search Console bewaart maar 16 maanden. Daarna is de data weg bij Google.
 *   - data/gsc/ en reports/ staan in .gitignore, want de webroot is de repo-root.
 *     Ze zitten dus NIET in git en NIET in een GitHub-backup.
 *   Zonder deze kopie bestaat het archief op precies één schijf.
 *
 * Doelmap: OneDrive, zodat de kopie ook in de cloud staat.
 * Andere map? Zet BACKUP_DIR.
 *
 * Gebruik:
 *   node scripts/backup-gsc.js
 *   node scripts/backup-gsc.js --dry
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

const ROOT = path.resolve(__dirname, '..');
const DRY = process.argv.indexOf('--dry') !== -1;

const DOEL = process.env.BACKUP_DIR ||
  path.join(os.homedir(), 'OneDrive', 'Backups', 'belastinghulpzaanstad');

// Mappen die wel lokaal staan, maar niet in git. Precies die moeten mee.
const MAPPEN = ['data/gsc', 'reports'];

function kopieerMap(van, naar) {
  if (!fs.existsSync(van)) return { nieuw: 0, bij: 0, gelijk: 0 };
  fs.mkdirSync(naar, { recursive: true });
  let nieuw = 0, bij = 0, gelijk = 0;

  for (const e of fs.readdirSync(van, { withFileTypes: true })) {
    const bron = path.join(van, e.name);
    const doel = path.join(naar, e.name);
    if (e.isDirectory()) {
      const r = kopieerMap(bron, doel);
      nieuw += r.nieuw; bij += r.bij; gelijk += r.gelijk;
      continue;
    }
    const s = fs.statSync(bron);
    const bestaat = fs.existsSync(doel);
    // Alleen kopieren als het bestand nieuw is of echt veranderd. Zo blijft
    // OneDrive rustig en duurt een tweede run bijna niets.
    if (bestaat) {
      const d = fs.statSync(doel);
      if (d.size === s.size && Math.floor(d.mtimeMs / 1000) >= Math.floor(s.mtimeMs / 1000)) { gelijk++; continue; }
    }
    if (!DRY) {
      fs.copyFileSync(bron, doel);
      fs.utimesSync(doel, s.atime, s.mtime);
    }
    if (bestaat) bij++; else nieuw++;
  }
  return { nieuw: nieuw, bij: bij, gelijk: gelijk };
}

console.log((DRY ? '[dry] ' : '') + 'doel: ' + DOEL);
let tot = { nieuw: 0, bij: 0, gelijk: 0 };
for (const m of MAPPEN) {
  const r = kopieerMap(path.join(ROOT, m), path.join(DOEL, m));
  tot.nieuw += r.nieuw; tot.bij += r.bij; tot.gelijk += r.gelijk;
  console.log('  ' + m.padEnd(12) + r.nieuw + ' nieuw, ' + r.bij + ' bijgewerkt, ' + r.gelijk + ' ongewijzigd');
}

// Een leesmij, zodat je over een jaar nog weet wat deze map is.
if (!DRY) {
  fs.writeFileSync(path.join(DOEL, 'LEESMIJ.txt'),
    'Meetarchief belastinghulpzaanstad.nl\n' +
    'Laatste backup: ' + new Date().toISOString().slice(0, 16).replace('T', ' ') + '\n\n' +
    'data/gsc/  = Search Console, een CSV per dag + totals.csv\n' +
    'reports/   = weekrapporten en crawl-audits\n\n' +
    'Deze data staat NIET in git en NIET bij Google na 16 maanden.\n' +
    'Deze map is de enige langetermijnkopie. Niet weggooien.\n', 'utf8');
}
console.log('klaar: ' + tot.nieuw + ' nieuw, ' + tot.bij + ' bijgewerkt, ' + tot.gelijk + ' ongewijzigd');
