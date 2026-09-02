#!/usr/bin/env node
/*
 * vind-losse-bedragen.js
 * Zoekt bedragen en percentages in de HTML die NIET in fiscale-cijfers.json staan.
 *
 * WAAROM
 * check-fiscale-cijfers.js kijkt van de lijst naar de site: het zoekt naar de
 * waarden die in "verouderd" staan. Dat vangt alleen wat wij ooit hebben
 * opgeschreven. In september 2026 bleek waar dat op stukloopt: op de pagina's
 * stond de vermogensgrens zorgtoeslag als €140.231, terwijl in "verouderd"
 * €140.213 stond. Dezelfde cijfers, twee omgewisseld. De controle bleef groen
 * terwijl er een fout bedrag op een levende pagina stond. Hetzelfde gold voor
 * €131 en €250 als maximale zorgtoeslag: die hebben nooit in een lijst gestaan.
 *
 * Dit script kijkt de andere kant op: van de site naar de lijst. Elk bedrag dat
 * niet herleidbaar is tot fiscale-cijfers.json komt in het rapport. Het is
 * nadrukkelijk GEEN faalcontrole voor de deploy: rekenvoorbeelden met een
 * hypotheek van €340.000 horen er ook in te staan. Het is een leeslijst.
 *
 * GEBRUIK
 *   node scripts/vind-losse-bedragen.js              alles, gesorteerd op verdenking
 *   node scripts/vind-losse-bedragen.js --verdacht   alleen wat op een parameter lijkt
 *   node scripts/vind-losse-bedragen.js --permutatie alleen de cijferpermutaties
 *
 * DE DRIE SIGNALEN
 * 1. permutatie   dezelfde cijfers als een bekende waarde, andere volgorde.
 *                 Dit is het patroon van €140.231 en het zwaarste signaal.
 * 2. bijna        één cijfer verschil met een bekende waarde.
 * 3. context      een woord als grens, korting, forfait of maximaal op dezelfde
 *                 regel. Dat maakt van een getal een parameter.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ALLEEN_VERDACHT = process.argv.includes('--verdacht');
const ALLEEN_PERMUTATIE = process.argv.includes('--permutatie');

const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'fiscale-cijfers.json'), 'utf8'));

/* woorden die van een getal een fiscale parameter maken */
const CONTEXTWOORDEN = [
  'grens', 'korting', 'forfait', 'drempel', 'tarief', 'maximaal', 'maximale',
  'vrijstelling', 'heffingvrij', 'vermogen', 'inkomen mag', 'niet hoger dan',
  'toeslag', 'aftrek', 'boete', 'schijf', 'limit', 'threshold', 'credit',
  'exemption', 'allowance', 'no higher than', 'at most', 'up to',
];

/* Niet: regels overslaan die opmaak bevatten. Dat was de eerste opzet en die
   sloeg precies de tabellen over, want elke <td> draagt een inline padding.
   In plaats daarvan strippen we de tags en houden we de tekst over, plus de
   inhoud van content="..." zodat meta descriptions meedoen. Wat overblijft is
   de CSS in het <style>-blok en de scripts; die slaan we per blok over. */

/* ---------- bekende waarden verzamelen ----------
   Bedragen en percentages krijgen elk hun eigen ruimte. Anders is 26% "één
   cijfer af" van het box 3-tarief van 36%, en dat zegt niets: elk tweecijferig
   percentage lijkt op elk ander. Alleen bedragen van drie cijfers of meer
   dragen genoeg informatie om een verschrijving zichtbaar te maken. */
const bekend = new Map();   /* genormaliseerd bedrag -> [sleutels] */
const bekendPct = new Map();/* genormaliseerd percentage -> [sleutels] */
function onthoud(getal, sleutel) {
  const isPct = String(getal).indexOf('%') !== -1;
  const k = normaliseer(getal);
  if (!k) return;
  const doel = isPct ? bekendPct : bekend;
  if (!doel.has(k)) doel.set(k, []);
  if (doel.get(k).indexOf(sleutel) === -1) doel.get(k).push(sleutel);
}
/* "€140.231" en "€140,231" en "140231" worden allemaal "140231" */
function normaliseer(s) {
  const kaal = String(s).replace(/&euro;|€|&nbsp;|\s/g, '').replace(/%$/, '');
  /* een bedrag met een decimaalteken: laatste scheider met 2 cijfers erachter */
  const m = kaal.match(/^(\d[\d.,]*?)([.,]\d{2})?$/);
  if (!m) return null;
  const heel = m[1].replace(/[.,]/g, '');
  const deel = m[2] ? m[2].slice(1) : '';
  return deel ? heel + '.' + deel : heel;
}

for (const [sleutel, c] of Object.entries(data.cijfers)) {
  onthoud(c.waarde, sleutel);
  for (const oud of c.verouderd || []) onthoud(oud, sleutel + ' (verouderd)');
}

/* ---------- signalen ---------- */
function cijfers(s) { return String(s).replace(/[^0-9]/g, '').split('').sort().join(''); }

const permutatieKaart = new Map(); /* gesorteerde cijfers -> [genormaliseerde waarden] */
for (const k of bekend.keys()) {
  const c = cijfers(k);
  if (c.length < 4) continue; /* onder de vier cijfers is een permutatie toeval */
  if (!permutatieKaart.has(c)) permutatieKaart.set(c, []);
  permutatieKaart.get(c).push(k);
}

function eenCijferAf(a, b) {
  const x = String(a).replace(/[^0-9]/g, '');
  const y = String(b).replace(/[^0-9]/g, '');
  if (x.length !== y.length || x.length < 4) return false;
  let n = 0;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) n++;
  return n === 1;
}

/* ---------- de HTML doorlopen ---------- */
function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}
const files = walk(ROOT, []);

/* €1.234 / € 1.234,56 / &euro;1,234 / 37,56% / 5%
   Het percentage mag niet midden in een groter getal beginnen, anders leest
   "100%" als "00%". Vandaar de blik op het teken ervoor. */
const RE_BEDRAG = /(?:&euro;|€)\s*(?:&nbsp;)?\s*(\d{1,3}(?:[.,]\d{3})+(?:[.,]\d{2})?|\d{3,6}(?:[.,]\d{2})?)/g;
const RE_PROCENT = /(?:^|[^0-9.,])(\d{1,3}(?:,\d{1,2})?)\s*%/g;

const vondsten = new Map(); /* genormaliseerd -> {rauw:Set, plekken:[], context:bool} */

for (const f of files) {
  const rel = path.relative(ROOT, f).split(path.sep).join('/');
  const regels = fs.readFileSync(f, 'utf8').split(/\r?\n/);
  let inStyle = false;
  let inScript = false; /* alleen gewone scripts; JSON-LD willen we juist wel */

  regels.forEach(function (ruw, n) {
    /* blokken bijhouden: CSS staat vol met 100% en 50% en zegt niets */
    if (/<style[\s>]/i.test(ruw)) inStyle = true;
    if (/<script(?![^>]*application\/ld\+json)/i.test(ruw)) inScript = true;
    const dichtStyle = /<\/style>/i.test(ruw);
    const dichtScript = /<\/script>/i.test(ruw);
    const slaOver = inStyle || inScript;
    if (dichtStyle) inStyle = false;
    if (dichtScript) inScript = false;
    if (slaOver) return;

    /* tags eruit, maar de inhoud van content="..." erbij, anders vallen de
       meta descriptions buiten beeld */
    const uitContent = (ruw.match(/content="([^"]*)"/g) || [])
      .map((c) => c.slice(9, -1)).join(' ');
    const regel = ruw.replace(/<[^>]*>/g, ' ') + ' ' + uitContent;

    const laag = regel.toLowerCase();
    const heeftContext = CONTEXTWOORDEN.some((w) => laag.indexOf(w) !== -1);

    const pak = function (re, soort) {
      let m;
      re.lastIndex = 0;
      while ((m = re.exec(regel)) !== null) {
        const rauw = (soort === '%' ? m[1] + '%' : m[0]).trim();
        const norm = normaliseer(m[1]);
        if (!norm) continue;
        const sleutel = soort === '%' ? norm + '%' : norm;
        if (soort === '%' ? bekendPct.has(norm) : bekend.has(norm)) continue;
        if (!vondsten.has(sleutel)) {
          vondsten.set(sleutel, { soort, rauw: new Set(), plekken: [], context: false });
        }
        const v = vondsten.get(sleutel);
        v.rauw.add(rauw);
        v.plekken.push(rel + ':' + (n + 1));
        if (heeftContext) v.context = true;
      }
    };
    pak(RE_BEDRAG, '€');
    pak(RE_PROCENT, '%');
  });
}

/* ---------- beoordelen ---------- */
const rijen = [];
for (const [norm, v] of vondsten) {
  const kaal = norm.replace('%', '');
  /* percentages vergelijken we niet op permutatie of afstand: te weinig
     cijfers, dus alleen ruis. Voor die groep telt de context. */
  const isPct = v.soort === '%';
  const permutaties = isPct ? [] : (permutatieKaart.get(cijfers(kaal)) || []).filter((k) => k !== kaal);
  const bijna = [];
  if (!isPct) for (const k of bekend.keys()) if (eenCijferAf(kaal, k)) bijna.push(k);

  const bestanden = new Set(v.plekken.map((p) => p.split(':')[0]));
  let score = 0;
  if (permutaties.length) score += 100;
  if (bijna.length) score += 40;
  if (v.context) score += 20;
  score += Math.min(bestanden.size, 15);

  rijen.push({
    norm, v, permutaties, bijna, score,
    bestanden: bestanden.size,
    voorkomens: v.plekken.length,
  });
}
rijen.sort((a, b) => b.score - a.score);

/* ---------- rapport ---------- */
function toonWaarde(k) {
  const sleutels = bekend.get(k) || [];
  return k + (sleutels.length ? '  = ' + sleutels.join(', ') : '');
}

let getoond = 0;
console.log('Bedragen en percentages in de HTML die niet in fiscale-cijfers.json staan.\n');

for (const r of rijen) {
  if (ALLEEN_PERMUTATIE && !r.permutaties.length) continue;
  if (ALLEEN_VERDACHT && !r.permutaties.length && !r.bijna.length && !r.v.context) continue;
  getoond++;

  const merk = r.permutaties.length ? '!! PERMUTATIE' : (r.bijna.length ? '!  BIJNA' : (r.v.context ? '?  CONTEXT' : '   '));
  console.log(merk.padEnd(14) + [...r.v.rauw].join(' / ').padEnd(22) +
    r.voorkomens + 'x in ' + r.bestanden + ' bestand(en)');
  for (const p of r.permutaties) console.log('               permutatie van  ' + toonWaarde(p));
  for (const b of r.bijna.slice(0, 3)) console.log('               één cijfer af van ' + toonWaarde(b));
  console.log('               ' + r.v.plekken.slice(0, 3).join('  ') + (r.voorkomens > 3 ? '  ...' : ''));
  console.log('');
}

const perm = rijen.filter((r) => r.permutaties.length).length;
const bij = rijen.filter((r) => !r.permutaties.length && r.bijna.length).length;
const ctx = rijen.filter((r) => !r.permutaties.length && !r.bijna.length && r.v.context).length;
console.log('--- samenvatting ---');
console.log('bestanden gescand      : ' + files.length);
console.log('bekende waarden        : ' + bekend.size + ' (actueel plus verouderd)');
console.log('losse bedragen gevonden: ' + rijen.length + ', getoond: ' + getoond);
console.log('  permutatie van een bekende waarde : ' + perm);
console.log('  één cijfer af van een bekende     : ' + bij);
console.log('  alleen fiscale context            : ' + ctx);
console.log('  rest (rekenvoorbeelden en dergelijke): ' + (rijen.length - perm - bij - ctx));
console.log('\nDit script faalt nooit; het is een leeslijst, geen poortwachter.');
