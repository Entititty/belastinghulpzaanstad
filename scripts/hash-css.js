#!/usr/bin/env node
/*
 * hash-css.js
 * Zet een content-hash in de bestandsnaam van de stylesheet en werkt alle
 * verwijzingen in de HTML bij: belasting.min.css -> belasting.<hash>.min.css
 *
 * Waarom: de webroot is de repo-root en nginx mag CSS lang cachen. Zonder
 * hash in de naam moeten de CSS en de nginx-regel in de juiste volgorde
 * live gaan, anders zien bestaande bezoekers een week lang de oude CSS bij
 * nieuwe HTML. Met een hash is de naam nieuw zodra de inhoud verandert, dus
 * de volgorde van uitrollen maakt niet meer uit.
 *
 * Draai dit na elke wijziging in de stylesheet en voor het committen.
 *
 * Gebruik:
 *   node scripts/hash-css.js
 *   node scripts/hash-css.js --dry
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const DRY = process.argv.indexOf('--dry') !== -1;
const BASIS = 'belasting';
const STAART = '.min.css';

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      walk(path.join(dir, e.name), acc);
    } else if (e.name === 'index.html') acc.push(path.join(dir, e.name));
  }
  return acc;
}

/* ---------- huidige stylesheet vinden ---------- */
const kandidaten = fs.readdirSync(ROOT).filter(function (f) {
  return f === BASIS + STAART || new RegExp('^' + BASIS + '\\.[0-9a-f]{8}\\' + STAART.replace('.', '\\.') + '$').test(f);
});
if (!kandidaten.length) {
  console.error('Geen ' + BASIS + STAART + ' of gehashte variant gevonden in ' + ROOT);
  process.exit(1);
}
if (kandidaten.length > 1) {
  console.error('Meer dan een stylesheet gevonden, ruim eerst op: ' + kandidaten.join(', '));
  process.exit(1);
}
const huidig = kandidaten[0];
const inhoud = fs.readFileSync(path.join(ROOT, huidig));
const hash = crypto.createHash('sha256').update(inhoud).digest('hex').slice(0, 8);
const nieuw = BASIS + '.' + hash + STAART;

console.log('huidig : ' + huidig);
console.log('hash   : ' + hash + '  (' + (inhoud.length / 1024).toFixed(1) + ' KB)');
console.log('nieuw  : ' + nieuw);

if (huidig === nieuw) {
  console.log('\nDe naam klopt al bij de inhoud. Alleen verwijzingen controleren.');
}

/* ---------- verwijzingen bijwerken ---------- */
// Alle vormen die in de HTML voorkomen: /x, ../x en ../../x
const oudeNamen = [huidig, BASIS + STAART];
let geraakt = 0, verwijzingen = 0;
const zonder = [];

for (const f of walk(ROOT, [])) {
  let s = fs.readFileSync(f, 'utf8');
  const voor = s;
  for (const oud of oudeNamen) {
    if (oud === nieuw) continue;
    while (s.indexOf(oud) !== -1) { s = s.replace(oud, nieuw); verwijzingen++; }
  }
  if (s !== voor) { if (!DRY) fs.writeFileSync(f, s, 'utf8'); geraakt++; }
  if (s.indexOf(nieuw) === -1 && /<link[^>]*stylesheet/.test(s)) {
    zonder.push(path.relative(ROOT, f).split(path.sep).join('/'));
  }
}

/* ---------- bestand omnoemen ---------- */
if (huidig !== nieuw && !DRY) {
  fs.renameSync(path.join(ROOT, huidig), path.join(ROOT, nieuw));
}

/* ---------- oude gehashte kopieen opruimen ---------- */
let opgeruimd = 0;
for (const f of fs.readdirSync(ROOT)) {
  if (f === nieuw) continue;
  if (f === BASIS + STAART || new RegExp('^' + BASIS + '\\.[0-9a-f]{8}\\.min\\.css$').test(f)) {
    if (!DRY) fs.unlinkSync(path.join(ROOT, f));
    console.log('opgeruimd: ' + f);
    opgeruimd++;
  }
}

console.log('\n' + (DRY ? '[dry] ' : '') + 'verwijzingen bijgewerkt: ' + verwijzingen + ' in ' + geraakt + ' pagina\'s');
console.log((DRY ? '[dry] ' : '') + 'oude bestanden opgeruimd: ' + opgeruimd);

/* ---------- controle ---------- */
if (!DRY) {
  let fout = 0;
  if (!fs.existsSync(path.join(ROOT, nieuw))) { console.error('FOUT: ' + nieuw + ' bestaat niet'); fout++; }
  for (const f of walk(ROOT, [])) {
    const s = fs.readFileSync(f, 'utf8');
    const rel = path.relative(ROOT, f).split(path.sep).join('/');
    // een verwijzing naar de oude naam mag nergens meer staan
    if (new RegExp(BASIS + '\\.min\\.css').test(s) && s.indexOf(nieuw) === -1) {
      console.error('FOUT: oude verwijzing in ' + rel); fout++;
    }
    // controleer dat het pad klopt ten opzichte van de pagina
    for (const m of s.matchAll(/href="([^"]*belasting\.[0-9a-f]{8}\.min\.css)"/g)) {
      const href = m[1];
      const doel = href[0] === '/'
        ? path.join(ROOT, href.slice(1))
        : path.resolve(path.dirname(f), href);
      if (!fs.existsSync(doel)) { console.error('FOUT: ' + rel + ' verwijst naar ' + href + ' (bestaat niet)'); fout++; }
    }
  }
  if (zonder.length) { console.error('\nPagina met een stylesheet maar zonder deze CSS:'); zonder.forEach(function (z) { console.error('  ' + z); }); }
  console.log(fout === 0 ? 'ok  alle verwijzingen kloppen en het bestand bestaat' : 'FOUT: ' + fout + ' probleem(en)');
  if (fout) process.exit(1);
}
