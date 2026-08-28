#!/usr/bin/env node
/*
 * tellingen-rapport.js — leest de conversiemeting en maakt er een overzicht van.
 *
 * nginx schrijft per dag een bestand met JSON-regels (zie
 * server-setup/nginx-tellingen.conf):
 *     {"t":"2026-08-28T14:00","e":"whatsapp","p":"/senioren/","v":""}
 *
 * Waarom losse regels en geen database: append-only. De kernel schrijft met
 * O_APPEND, dus twee gelijktijdige klikken kunnen elkaar niet overschrijven.
 * Bij een handvol regels per dag is een database gereedschap zonder werk, en
 * SQLite zou een module zijn die op de VPS gebouwd moet worden.
 *
 * Gebruik:
 *     node scripts/tellingen-rapport.js
 *     node scripts/tellingen-rapport.js --bron /var/log/belastinghulp/tellingen
 *     node scripts/tellingen-rapport.js --opruimen     # retentie toepassen
 *
 * Draait net zo goed op de server als op je eigen machine na een scp.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function arg(naam, standaard) {
  const i = process.argv.indexOf(naam);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : standaard;
}
const BRON     = path.resolve(arg('--bron', path.join(ROOT, 'data', 'tellingen')));
const UIT      = path.resolve(arg('--uit', path.join(ROOT, 'intern', 'tellingen', 'index.html')));
const OPRUIMEN = process.argv.indexOf('--opruimen') !== -1;
const BEWAAR   = 90;   /* dagen ruwe regels; daarna alleen nog dagtotalen */

/* De vijf dingen die we meten. Andere waarden zijn ongeldig. */
const EVENTS = ['whatsapp', 'tel', 'mail', 'form_submit', 'form_abandon'];
const LABEL = {
  whatsapp:     'WhatsApp aangeklikt',
  tel:          'Telefoonnummer aangeklikt',
  mail:         'E-mailadres aangeklikt',
  form_submit:  'Formulier verstuurd (poging)',
  form_abandon: 'Formulier halverwege verlaten'
};
const KORT = {
  whatsapp: 'whatsapp', tel: 'telefoon', mail: 'e-mail',
  form_submit: 'verstuurd', form_abandon: 'afgehaakt'
};

/* ------------------------------------------------------------------
 * De whitelist met veldnamen staat op EEN plek: js/tellingen.js. Hier
 * lezen we hem daar letterlijk uit, zodat de meting en dit rapport nooit
 * uit elkaar kunnen lopen. Lukt dat niet, dan stoppen we; stilletjes alles
 * doorlaten zou betekenen dat er van alles in het overzicht kan komen wat
 * niemand heeft goedgekeurd.
 * ------------------------------------------------------------------ */
function leesWhitelist() {
  const f = path.join(ROOT, 'js', 'tellingen.js');
  const s = fs.readFileSync(f, 'utf8');
  const m = /VELDEN-BEGIN\s*\*\/\s*var\s+VELDEN\s*=\s*\[([^\]]*)\]/.exec(s);
  if (!m) {
    console.error('FOUT: de whitelist is niet te lezen uit js/tellingen.js.');
    console.error('Zoek daar naar de markering VELDEN-BEGIN en var VELDEN = [...].');
    process.exit(2);
  }
  const lijst = m[1].split(',')
    .map(function (x) { return x.trim().replace(/^['"]|['"]$/g, ''); })
    .filter(Boolean);
  if (!lijst.length) {
    console.error('FOUT: lege whitelist in js/tellingen.js.');
    process.exit(2);
  }
  return lijst;
}
const VELDEN = leesWhitelist();

/* ---------------- inlezen ---------------- */
const RE_UUR = /^\d{4}-\d{2}-\d{2}T\d{2}:00$/;
const RE_PAD = /^\/[a-z0-9/._-]{0,80}$/;

function schoonPad(p) {
  let d = p || '';
  try { d = decodeURIComponent(d); } catch (e) { return 'overig'; }
  d = d.toLowerCase();
  if (!d) return 'overig';
  return RE_PAD.test(d) ? d : 'overig';
}

function schoonVeld(v) {
  let d = v || '';
  try { d = decodeURIComponent(d); } catch (e) { return 'overig'; }
  d = d.toLowerCase();
  if (!d) return '';
  return VELDEN.indexOf(d) !== -1 ? d : 'overig';
}

function bestanden() {
  if (!fs.existsSync(BRON)) return [];
  return fs.readdirSync(BRON)
    .filter(function (n) { return /^\d{4}-\d{2}-\d{2}\.ndjson$/.test(n); })
    .sort();
}

const dagen = {};      /* dag  -> { event -> aantal } */
const perPagina = {};  /* pad  -> { event -> aantal } */
const perVeld = {};    /* veld -> aantal */
let regels = 0, ongeldig = 0;
const dagbestanden = bestanden();

for (const naam of dagbestanden) {
  const dag = naam.slice(0, 10);
  const tekst = fs.readFileSync(path.join(BRON, naam), 'utf8');
  for (const regel of tekst.split('\n')) {
    if (!regel.trim()) continue;
    let r;
    try { r = JSON.parse(regel); } catch (e) { ongeldig++; continue; }
    if (!RE_UUR.test(r.t || '') || EVENTS.indexOf(r.e) === -1) { ongeldig++; continue; }
    regels++;
    const p = schoonPad(r.p);
    dagen[dag] = dagen[dag] || {};
    dagen[dag][r.e] = (dagen[dag][r.e] || 0) + 1;
    perPagina[p] = perPagina[p] || {};
    perPagina[p][r.e] = (perPagina[p][r.e] || 0) + 1;
    if (r.e === 'form_abandon') {
      const v = schoonVeld(r.v) || 'overig';
      perVeld[v] = (perVeld[v] || 0) + 1;
    }
  }
}

/* ---------------- dagtotalen van vroeger erbij ---------------- */
const TOTALEN = path.join(BRON, 'dagtotalen.json');
let bewaard = { start: null, dagen: {} };
if (fs.existsSync(TOTALEN)) {
  try { bewaard = JSON.parse(fs.readFileSync(TOTALEN, 'utf8')); } catch (e) {}
}
bewaard.dagen = bewaard.dagen || {};
for (const d of Object.keys(bewaard.dagen)) {
  if (!dagen[d]) dagen[d] = bewaard.dagen[d];
}

/* ---------------- vanaf wanneer meten we ----------------
 * Het START-bestand wordt bij het uitrollen gezet (zie DEPLOY.md). Dat is
 * betrouwbaarder dan de eerste meetdag: gebeurt er drie dagen niets, dan zou
 * die eerste dag ten onrechte als startdatum gelden en lijkt "de eerste week"
 * over vier dagen te gaan. */
let start = null, startBron = '';
const F_START = path.join(BRON, 'START');
if (fs.existsSync(F_START)) {
  const m = /(\d{4}-\d{2}-\d{2})/.exec(fs.readFileSync(F_START, 'utf8'));
  if (m) { start = m[1]; startBron = 'START-bestand'; }
}
if (!start && bewaard.start) { start = bewaard.start; startBron = 'dagtotalen.json'; }
const alleDagen = Object.keys(dagen).sort();
if (!start && alleDagen.length) { start = alleDagen[0]; startBron = 'eerste meetdag'; }

/* ---------------- rekenen ---------------- */
const vandaag = new Date().toISOString().slice(0, 10);
function minDagen(n) {
  const d = new Date(vandaag + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() - n);
  return d.toISOString().slice(0, 10);
}
function somVanaf(vanaf) {
  const t = {};
  for (const d of alleDagen) {
    if (vanaf && d < vanaf) continue;
    for (const e of EVENTS) t[e] = (t[e] || 0) + (dagen[d][e] || 0);
  }
  return t;
}
function totaal(t) {
  return EVENTS.reduce(function (a, e) { return a + (t[e] || 0); }, 0);
}
const tot7  = somVanaf(minDagen(6));
const tot30 = somVanaf(minDagen(29));
const totAl = somVanaf(null);

const paginas = Object.keys(perPagina).map(function (p) {
  return { pad: p, n: totaal(perPagina[p]), d: perPagina[p] };
}).sort(function (a, b) { return b.n - a.n; });

function dagenSinds(d) {
  if (!d) return 0;
  return Math.round((Date.parse(vandaag) - Date.parse(d)) / 86400000) + 1;
}

/* ---------------- terminal ---------------- */
function tabel(rijen) {
  const w = rijen[0].map(function (_, i) {
    return Math.max.apply(null, rijen.map(function (r) { return String(r[i]).length; }));
  });
  return rijen.map(function (r) {
    return r.map(function (c, i) {
      return i === 0 ? String(c).padEnd(w[i]) : String(c).padStart(w[i]);
    }).join('  ');
  }).join('\n');
}

console.log('');
console.log('CONVERSIEMETING belastinghulpzaanstad.nl');
console.log('----------------------------------------');
if (!start) {
  console.log('Er is nog niets gemeten. Bron: ' + BRON);
} else {
  console.log('Gemeten vanaf ' + start + ' (' + startBron + '), dat is ' +
              dagenSinds(start) + ' dagen tot en met ' + vandaag + '.');
  console.log('Vergelijk dit niet met een periode van voor die datum; daar zijn geen cijfers van.');
  console.log('');
  console.log(tabel([['gebeurtenis', '7 dgn', '30 dgn', 'totaal']].concat(
    EVENTS.map(function (e) { return [LABEL[e], tot7[e] || 0, tot30[e] || 0, totAl[e] || 0]; })
  )));
  console.log('');
  console.log('Bovenste pagina:');
  console.log(tabel([['pagina', 'totaal']].concat(
    paginas.slice(0, 15).map(function (p) { return [p.pad, p.n]; })
  )));
  if (Object.keys(perVeld).length) {
    console.log('');
    console.log('Afgehaakt bij veld:');
    console.log(tabel([['veld', 'aantal']].concat(
      Object.keys(perVeld).sort(function (a, b) { return perVeld[b] - perVeld[a]; })
        .map(function (v) { return [v, perVeld[v]]; })
    )));
  }
  console.log('');
  console.log(regels + ' regels gelezen, ' + ongeldig + ' overgeslagen, ' +
              dagbestanden.length + ' dagbestanden.');
}

/* ---------------- HTML ---------------- */
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function rij(cellen, tag) {
  const t = tag || 'td';
  return '<tr>' + cellen.map(function (c) {
    return '<' + t + '>' + esc(c) + '</' + t + '>';
  }).join('') + '</tr>';
}

const balkMax = Math.max.apply(null, [1].concat(alleDagen.slice(-30).map(function (d) {
  return totaal(dagen[d]);
})));

const kop = [
  '<!doctype html>',
  '<html lang="nl">',
  '<meta charset="utf-8">',
  '<meta name="robots" content="noindex,nofollow">',
  '<meta name="viewport" content="width=device-width,initial-scale=1">',
  '<title>Conversiemeting — belastinghulpzaanstad.nl</title>',
  '<style>',
  ' body{font:16px/1.6 system-ui,sans-serif;max-width:940px;margin:0 auto;padding:24px;color:#1f2421;background:#faf8f4}',
  ' h1{font-size:1.6rem;margin:0 0 4px} h2{font-size:1.15rem;margin:34px 0 10px}',
  ' table{border-collapse:collapse;width:100%;margin:0 0 8px}',
  ' th,td{padding:7px 10px;border-bottom:1px solid #ddd8ce;text-align:right}',
  ' th:first-child,td:first-child{text-align:left}',
  ' thead th{background:#efece4;border-bottom:2px solid #c9c3b6}',
  ' .start{background:#e6f5f3;border-left:4px solid #14695f;padding:12px 16px;margin:16px 0}',
  ' .leeg{background:#fff3d6;border-left:4px solid #8b5a00;padding:12px 16px}',
  ' .bar{display:inline-block;height:10px;background:#14695f;vertical-align:middle}',
  ' footer{margin-top:40px;font-size:.92rem;color:#3d433e;border-top:1px solid #ddd8ce;padding-top:14px}',
  ' code{background:#efece4;padding:1px 5px;border-radius:3px}',
  '</style>',
  '<h1>Conversiemeting</h1>',
  '<p>Gemaakt op ' + esc(new Date().toISOString().slice(0, 16).replace('T', ' ')) +
    '. Bron: <code>' + esc(BRON) + '</code>.</p>'
].join('\n');

const startblok = start
  ? '<p class="start"><strong>Er wordt gemeten vanaf ' + esc(start) + '</strong> (' +
    esc(startBron) + '), dat is ' + dagenSinds(start) + ' dagen tot en met ' + esc(vandaag) +
    '. Van de periode daarvoor zijn geen cijfers. Zet deze getallen dus niet naast een ' +
    'eerdere maand: een verschil met die maand is geen daling of stijging, maar een ' +
    'periode zonder meting.</p>'
  : '<p class="leeg">Er is nog niets gemeten. Controleer of <code>' + esc(BRON) +
    '</code> bestaat en of nginx erin mag schrijven.</p>';

let body = '';
if (start) {
  body += '\n<h2>Wat er gebeurde</h2>\n<table>\n<thead>' +
    rij(['gebeurtenis', 'laatste 7 dagen', 'laatste 30 dagen', 'hele periode'], 'th') +
    '</thead>\n<tbody>\n' +
    EVENTS.map(function (e) {
      return rij([LABEL[e], tot7[e] || 0, tot30[e] || 0, totAl[e] || 0]);
    }).join('\n') + '\n' +
    rij(['alles bij elkaar', totaal(tot7), totaal(tot30), totaal(totAl)], 'th') +
    '\n</tbody>\n</table>\n';

  body += '\n<h2>Per pagina</h2>\n<table>\n<thead>' +
    rij(['pagina'].concat(EVENTS.map(function (e) { return KORT[e]; })).concat(['totaal']), 'th') +
    '</thead>\n<tbody>\n' +
    paginas.slice(0, 25).map(function (p) {
      return rij([p.pad].concat(EVENTS.map(function (e) { return p.d[e] || 0; })).concat([p.n]));
    }).join('\n') +
    '\n</tbody>\n</table>\n' +
    '<p>Alleen de dagen waarvan de ruwe regels er nog zijn (' + BEWAAR +
    ' dagen). Oudere dagen tellen wel mee in de tabel hierboven, maar niet per pagina.</p>\n';

  body += '\n<h2>Waar mensen afhaken</h2>\n';
  const velden = Object.keys(perVeld).sort(function (a, b) { return perVeld[b] - perVeld[a]; });
  body += velden.length
    ? '<table>\n<thead>' + rij(['laatst aangeraakte veld', 'aantal'], 'th') + '</thead>\n<tbody>\n' +
      velden.map(function (v) { return rij([v, perVeld[v]]); }).join('\n') + '\n</tbody>\n</table>\n'
    : '<p>Nog niemand is halverwege een formulier weggegaan.</p>\n';
  body += '<p>Alleen de <em>naam</em> van het veld, nooit wat erin stond. Een naam die niet ' +
    'op de lijst in <code>js/tellingen.js</code> staat, komt hier als <code>overig</code>.</p>\n';

  body += '\n<h2>Per dag, laatste 30</h2>\n<table>\n<thead>' +
    rij(['dag'].concat(EVENTS.map(function (e) { return KORT[e]; })).concat(['totaal', '']), 'th') +
    '</thead>\n<tbody>\n' +
    alleDagen.slice(-30).reverse().map(function (d) {
      const n = totaal(dagen[d]);
      return '<tr><td>' + esc(d) + '</td>' +
        EVENTS.map(function (e) { return '<td>' + (dagen[d][e] || 0) + '</td>'; }).join('') +
        '<td>' + n + '</td><td style="text-align:left"><span class="bar" style="width:' +
        Math.round(120 * n / balkMax) + 'px"></span></td></tr>';
    }).join('\n') +
    '\n</tbody>\n</table>\n';
}

const voet = [
  '',
  '<footer>',
  '<p><strong>Wat hier wel en niet in zit.</strong> Geteld wordt een klik op WhatsApp,',
  'op een telefoonnummer of op een e-mailadres, het versturen van een formulier, en het',
  'halverwege verlaten van een formulier. Paginaweergaven worden niet geteld: daardoor',
  'vallen crawlers vanzelf af, want die klikken niet.</p>',
  '<p><strong>Verstuurd is een poging.</strong> Of Formspree het bericht heeft aangenomen',
  'weten we hier niet; dat staat in je mailbox.</p>',
  '<p><strong>Geen persoonsgegevens.</strong> Een regel bevat het uur, de gebeurtenis, het',
  'pad en bij afhaken een veldnaam. Geen IP-adres, geen user-agent, geen sessie, geen',
  'verwijzende pagina, geen cookie. Daarom is er geen toestemming nodig en staat deze',
  'meting los van de cookiebalk.</p>',
  '<p><strong>Bewaartermijn.</strong> Ruwe regels ' + BEWAAR + ' dagen',
  '(<code>node scripts/tellingen-rapport.js --opruimen</code>). Daarna blijven alleen de',
  'dagtotalen per gebeurtenis over, zonder pagina en zonder veld.</p>',
  '<p><strong>Eigen bezoek.</strong> Twee filters: <code>?mijzelf=1</code> zet dit apparaat',
  'uit, en nginx laat alles vanaf de IP-adressen in',
  '<code>/etc/nginx/conf.d/eigen-ip.map</code> helemaal geen regel maken.</p>',
  '<p>' + regels + ' regels gelezen, ' + ongeldig + ' overgeslagen omdat ze niet klopten.</p>',
  '</footer>',
  '</html>',
  ''
].join('\n');

fs.mkdirSync(path.dirname(UIT), { recursive: true });
fs.writeFileSync(UIT, kop + '\n' + startblok + '\n' + body + voet);
console.log('Overzicht geschreven: ' + UIT);

/* ---------------- retentie ---------------- */
if (OPRUIMEN) {
  const grens = minDagen(BEWAAR);
  let weg = 0;
  if (!bewaard.start && start) bewaard.start = start;
  for (const naam of dagbestanden) {
    const dag = naam.slice(0, 10);
    if (dag >= grens) continue;
    bewaard.dagen[dag] = dagen[dag] || {};
    fs.unlinkSync(path.join(BRON, naam));
    weg++;
  }
  bewaard.bijgewerkt = new Date().toISOString().slice(0, 10);
  fs.writeFileSync(TOTALEN, JSON.stringify(bewaard, null, 1));
  console.log('Opgeruimd: ' + weg + ' dagbestand(en) ouder dan ' + BEWAAR +
              ' dagen samengevat in dagtotalen.json en verwijderd.');
}
