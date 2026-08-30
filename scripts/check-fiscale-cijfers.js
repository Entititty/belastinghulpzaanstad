#!/usr/bin/env node
/*
 * check-fiscale-cijfers.js
 * Eén bron van waarheid: data/fiscale-cijfers.json.
 * Dit script faalt (exit 1) als:
 *   - een VEROUDERDE fiscale waarde nog in de HTML staat, of
 *   - een waarde in fiscale-cijfers.json geen geldige bron-URL of raadpleegdatum heeft.
 * Zo voorkom je dat oude cijfers (bv. 36,93% of ouderenkorting €2.035) terugsluipen,
 * en dat niemand nog weet waar een bedrag vandaan komt of hoe oud het is.
 *
 * Gebruik:  node scripts/check-fiscale-cijfers.js
 * Er is geen build op de server; draai dit vóór elke push (of in een pre-commit hook).
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'fiscale-cijfers.json'), 'utf8'));

/* ---------- 1. herkomst per waarde ----------
 * Elke waarde hoort een bron-URL en een raadpleegdatum te hebben. Een waarde
 * zonder URL mag alleen blijven staan met "bron_url_todo": true; die telt als
 * openstaand werk en niet als fout, zodat de bestaande achterstand het script
 * niet blokkeert. Ouder dan 12 maanden geeft een waarschuwing, want fiscale
 * bedragen wijzigen meestal per 1 januari.
 */
const MAAND_MS = 30.44 * 24 * 60 * 60 * 1000;
const DATUM_PATROON = /^\d{4}-\d{2}-\d{2}$/;
const nu = Date.now();

const fouten = [];
const waarschuwingen = [];
let zonderUrl = 0;

for (const [key, c] of Object.entries(data.cijfers)) {
  if (!c.gecontroleerd_op) {
    fouten.push(key + ': "gecontroleerd_op" ontbreekt (verwacht JJJJ-MM-DD)');
  } else if (!DATUM_PATROON.test(c.gecontroleerd_op) || isNaN(Date.parse(c.gecontroleerd_op))) {
    fouten.push(key + ': "gecontroleerd_op" is geen geldige datum: ' + c.gecontroleerd_op);
  } else {
    const maanden = (nu - Date.parse(c.gecontroleerd_op)) / MAAND_MS;
    if (maanden > 12) {
      waarschuwingen.push(key + ' (' + c.waarde + '): laatst gecontroleerd op ' +
        c.gecontroleerd_op + ', ' + Math.floor(maanden) + ' maanden geleden');
    }
  }

  if (!c.bron_url) {
    if (c.bron_url_todo) zonderUrl++;
    else fouten.push(key + ': "bron_url" ontbreekt. Vul de URL in, of zet "bron_url_todo": true');
  } else if (c.bron_url.indexOf('https://') !== 0) {
    fouten.push(key + ': "bron_url" moet met https:// beginnen, nu: ' + c.bron_url);
  }
}

/* ---------- 2. verouderde waarden in de HTML ---------- */
const guards = [];
for (const [key, c] of Object.entries(data.cijfers)) {
  (c.verouderd || []).forEach(function (old) { guards.push({ key: key, old: old, correct: c.waarde }); });
}

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      walk(path.join(dir, e.name), acc);
    } else if (e.name.endsWith('.html')) {
      acc.push(path.join(dir, e.name));
    }
  }
  return acc;
}

const files = walk(ROOT, []);
let hits = 0;
for (const f of files) {
  const lines = fs.readFileSync(f, 'utf8').split(/\r?\n/);
  lines.forEach(function (ln, i) {
    for (const g of guards) {
      if (ln.indexOf(g.old) !== -1) {
        hits++;
        console.log('STALE  ' + path.relative(ROOT, f) + ':' + (i + 1) + '  "' + g.old + '"  -> gebruik ' + g.correct + '  (' + g.key + ')');
      }
    }
  });
}

/* ---------- 3. uitkomst ---------- */
const aantalWaarden = Object.keys(data.cijfers).length;

if (waarschuwingen.length) {
  console.log('\nWAARSCHUWING: ' + waarschuwingen.length + ' van de ' + aantalWaarden +
    ' waarden zijn langer dan 12 maanden niet gecontroleerd:');
  waarschuwingen.forEach(function (w) { console.log('  ! ' + w); });
}
if (zonderUrl) {
  console.log('\nOpenstaand: ' + zonderUrl + ' van de ' + aantalWaarden +
    ' waarden hebben nog geen bron_url (gemarkeerd met bron_url_todo).');
}

console.log('\nGescand: ' + files.length + ' HTML-bestanden, ' + guards.length +
  ' verouderde waarden bewaakt (belastingjaar ' + data.belastingjaar + ').');

if (fouten.length) {
  console.error('\nFAIL: ' + fouten.length + ' waarde(n) in data/fiscale-cijfers.json missen een geldige bron of datum:');
  fouten.forEach(function (e) { console.error('  - ' + e); });
  process.exit(1);
}
if (hits) {
  console.error('FAIL: ' + hits + ' verouderde waarde(n) gevonden. Corrigeer ze of werk data/fiscale-cijfers.json bij.');
  process.exit(1);
}
console.log('OK: geen verouderde fiscale waarden in de HTML, en elke waarde heeft een datum.');
