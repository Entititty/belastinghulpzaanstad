#!/usr/bin/env node
/*
 * plaats-zoekcijfers.js
 * Zoekcijfers per plaatspagina uit de Search Console-export in data/gsc/.
 *
 * WAAROM
 * De negen plaatspagina's haalden in de zomer van 2026 samen 1.143 vertoningen
 * en nul klikken, waarvan 98% op diensten die wij niet leveren: taxatie,
 * waardebepaling, hypotheekadvies. Op 30 augustus 2026 zijn ze op
 * belastingintentie gezet. Het beslismoment staat op 1 juni 2027; draai dit
 * script dan opnieuw en vergelijk met de nulmeting in
 * docs/plaatspagina-zoekcijfers.md.
 *
 * Verander de filterlijst NIET zonder het in dat document te noteren, anders
 * vergelijkt u straks appels met peren.
 *
 * GEBRUIK
 *   node scripts/plaats-zoekcijfers.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const GSC = path.join(ROOT, 'data', 'gsc');
const PLAATSEN = ['zaandam', 'krommenie', 'assendelft', 'wormerveer',
  'koog-aan-de-zaan', 'zaandijk', 'westzaan', 'wormerland', 'oostzaan'];

/* Zoekopdrachten voor diensten die wij niet leveren. */
const NIET_ONZE = [/taxa/i, /taxer/i, /waardebepaling/i, /makelaar/i, /hypotheek/i,
  /notaris/i, /woningwaarde/i, /huis verkopen/i, /huis kopen/i, /verhuisbedrijf/i,
  /verhuizer/i, /incasso/i, /deurwaarder/i, /schuldhulp/i, /bewindvoer/i,
  /juridisch advies/i, /advocaat/i, /ontheffing/i, /vergunning/i];

function splitsCsv(regel) {
  const uit = []; let cur = '', inQ = false;
  for (const c of regel) {
    if (c === '"') { inQ = !inQ; continue; }
    if (c === ',' && !inQ) { uit.push(cur); cur = ''; continue; }
    cur += c;
  }
  uit.push(cur); return uit;
}

const bestanden = fs.readdirSync(GSC).filter((f) => /^\d{4}-\d{2}-\d{2}\.csv$/.test(f)).sort();
const perPagina = new Map();
for (const b of bestanden) {
  for (const r of fs.readFileSync(path.join(GSC, b), 'utf8').split(/\r?\n/).slice(1)) {
    if (!r.trim()) continue;
    const v = splitsCsv(r);
    if (v.length < 7) continue;
    const page = v[2].replace('https://belastinghulpzaanstad.nl', '');
    const q = v[1], clicks = Number(v[3]) || 0, imp = Number(v[4]) || 0, pos = Number(v[6]) || 0;
    if (!perPagina.has(page)) perPagina.set(page, new Map());
    const m = perPagina.get(page);
    if (!m.has(q)) m.set(q, { imp: 0, clicks: 0, posSom: 0 });
    const o = m.get(q);
    o.imp += imp; o.clicks += clicks; o.posSom += pos * imp;
  }
}

console.log('Periode: ' + bestanden[0].replace('.csv', '') + ' t/m ' +
  bestanden[bestanden.length - 1].replace('.csv', '') + ' (' + bestanden.length + ' dagen)\n');

console.log('| Pagina | Vert. | Klik | Gem. pos | Niet onze diensten | Relevante vert. |');
console.log('| --- | ---: | ---: | ---: | ---: | ---: |');

const detail = [];
for (const p of PLAATSEN) {
  const m = perPagina.get('/' + p + '/') || new Map();
  let imp = 0, clicks = 0, posSom = 0, impNiet = 0;
  const relevant = [];
  for (const [q, o] of m) {
    imp += o.imp; clicks += o.clicks; posSom += o.posSom;
    if (NIET_ONZE.some((re) => re.test(q))) impNiet += o.imp;
    else relevant.push({ q: q, imp: o.imp, pos: o.imp ? o.posSom / o.imp : 0, clicks: o.clicks });
  }
  const pos = imp ? (posSom / imp) : 0;
  const pctNiet = imp ? Math.round(100 * impNiet / imp) : 0;
  relevant.sort((a, b) => b.imp - a.imp);
  console.log('| /' + p + '/ | ' + imp + ' | ' + clicks + ' | ' + (imp ? pos.toFixed(1) : '-') +
    ' | ' + impNiet + ' (' + pctNiet + '%) | ' + (imp - impNiet) + ' |');
  detail.push({ p: p, imp: imp, clicks: clicks, pos: pos, impNiet: impNiet, pctNiet: pctNiet, relevant: relevant });
}

console.log('\n\n## Top 5 relevante zoekopdrachten per pagina\n');
for (const d of detail) {
  console.log('### /' + d.p + '/');
  if (!d.relevant.length) { console.log('_geen enkele relevante zoekopdracht in deze periode_\n'); continue; }
  console.log('| Zoekopdracht | Vert. | Pos | Klik |');
  console.log('| --- | ---: | ---: | ---: |');
  for (const r of d.relevant.slice(0, 5)) {
    console.log('| ' + r.q + ' | ' + r.imp + ' | ' + r.pos.toFixed(1) + ' | ' + r.clicks + ' |');
  }
  console.log('');
}
