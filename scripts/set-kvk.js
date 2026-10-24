#!/usr/bin/env node
/*
 * set-kvk.js
 * Zet het KvK-nummer en het btw-identificatienummer in data/bedrijf.json en
 * laat config-sync.js de footer van alle pagina's bijwerken. Of haalt ze er
 * weer uit.
 *
 * Art. 3:15d BW verplicht een online dienstverlener om identiteit,
 * KvK-nummer en btw-identificatienummer eenvoudig, direct en permanent
 * toegankelijk te maken. Zolang de onderneming niet is ingeschreven bestaan
 * die nummers niet. Dan is geen vermelding beter dan een invulmarkering;
 * config-sync.js laat het zinsdeel weg zolang de waarde leeg is.
 *
 * Sinds oktober 2026 staat de footerregel in een cfg-blok (footer-gegevens
 * en footer-gegevens-en) en komt hij uit data/bedrijf.json. Dit script doet
 * daarom niets meer met de HTML zelf; het vult de config en draait de sync.
 * Het commando is hetzelfde gebleven, zodat docs/TODO-kvk-btw.md klopt.
 *
 * Gebruik:
 *   node scripts/set-kvk.js --kvk 12345678 --btw NL123456789B01
 *   node scripts/set-kvk.js --kvk 12345678 --kor      (kleineondernemersregeling, geen btw-id in de footer)
 *   node scripts/set-kvk.js --verwijder
 *   voeg --dry toe om alleen te tonen wat er zou gebeuren
 *
 * Het btw-identificatienummer (NL + 9 cijfers + B + 2 cijfers) is het nummer
 * dat je publiceert. Het omzetbelastingnummer NIET: dat bevat bij een
 * eenmanszaak je BSN.
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const CONFIG = path.join(ROOT, 'data', 'bedrijf.json');
const DRY = process.argv.indexOf('--dry') !== -1;
const VERWIJDER = process.argv.indexOf('--verwijder') !== -1;
const KOR = process.argv.indexOf('--kor') !== -1;

function arg(naam) {
  const i = process.argv.indexOf('--' + naam);
  return i !== -1 ? process.argv[i + 1] : null;
}
const KVK = arg('kvk');
const BTW = arg('btw');

if (!VERWIJDER) {
  if (!KVK || (!BTW && !KOR)) {
    console.error('Gebruik: node scripts/set-kvk.js --kvk <8 cijfers> --btw <NL...B01>');
    console.error('     of: node scripts/set-kvk.js --kvk <8 cijfers> --kor');
    console.error('     of: node scripts/set-kvk.js --verwijder');
    process.exit(1);
  }
  if (!/^\d{8}$/.test(KVK)) {
    console.error('KvK-nummer moet 8 cijfers zijn, kreeg: ' + KVK);
    process.exit(1);
  }
  if (BTW && !/^NL\d{9}B\d{2}$/.test(BTW)) {
    console.error('Btw-id moet de vorm NL123456789B01 hebben, kreeg: ' + BTW);
    console.error('Let op: gebruik het btw-identificatienummer, niet het omzetbelastingnummer.');
    process.exit(1);
  }
}

const cfg = JSON.parse(fs.readFileSync(CONFIG, 'utf8'));
const voor = JSON.stringify(cfg.placeholders);
if (VERWIJDER) {
  cfg.placeholders.KVK_NUMMER = '';
  cfg.placeholders.BTW_ID = '';
  cfg.placeholders.KOR = null;
} else {
  cfg.placeholders.KVK_NUMMER = KVK;
  cfg.placeholders.BTW_ID = BTW || '';
  cfg.placeholders.KOR = KOR ? true : (BTW ? false : cfg.placeholders.KOR);
}

console.log((DRY ? '[dry] ' : '') + (VERWIJDER ? 'KvK en btw-id leeg gemaakt' : 'KvK ' + KVK + (BTW ? ' / btw-id ' + BTW : '') + (KOR ? ' / KOR' : '')));
if (JSON.stringify(cfg.placeholders) === voor) { console.log('Niets veranderd in data/bedrijf.json.'); }
if (DRY) process.exit(0);

fs.writeFileSync(CONFIG, JSON.stringify(cfg, null, 2) + '\n');
const r = spawnSync(process.execPath, [path.join(__dirname, 'config-sync.js')], { stdio: 'inherit' });
if (r.status !== 0) process.exit(r.status || 1);

/* controle: elke footer moet de nummers nu dragen, of juist niet meer */
let fout = 0;
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.git' || e.name === 'node_modules' || e.name === 'intern') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { walk(p); continue; }
    if (e.name !== 'index.html') continue;
    const s = fs.readFileSync(p, 'utf8');
    const m = s.match(/<!-- cfg:footer-gegevens(?:-en)? -->([\s\S]*?)<!-- \/cfg/);
    if (!m) continue;
    const r2 = path.relative(ROOT, p).split(path.sep).join('/');
    if (VERWIJDER && m[1].indexOf('KvK') !== -1) { console.error('KvK nog in de footer van ' + r2); fout++; }
    if (!VERWIJDER && m[1].indexOf('KvK: ' + KVK) === -1) { console.error('KvK ontbreekt in de footer van ' + r2); fout++; }
  }
})(ROOT);
console.log(fout === 0 ? '\nok  alle footers kloppen' : '\nFOUT: ' + fout + ' footer(s)');
if (fout) process.exit(1);
