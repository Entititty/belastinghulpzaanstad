#!/usr/bin/env node
/*
 * gsc-report.js
 * Leest het archief in data/gsc/ en schrijft reports/gsc-week-NN.md.
 * Vier tabellen, zoals in SEO-GEO-plan paragraaf 3:
 *   1. keywords op positie 4-20   -> CTR-kansen
 *   2. keywords op positie 21-50  -> content-kansen
 *   3. pagina's met veel vertoningen en minder dan 1% CTR
 *   4. week-op-week positieverandering per cluster
 *
 * Gebruik:
 *   node scripts/gsc-report.js              # laatste 28 dagen vs de 28 daarvoor
 *   node scripts/gsc-report.js --dagen 7
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BRON = path.join(ROOT, 'data', 'gsc');
const UIT = path.join(ROOT, 'reports');

function arg(naam, standaard) {
  const i = process.argv.indexOf('--' + naam);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : standaard;
}
const VENSTER = parseInt(arg('dagen', '28'), 10);

/* ---------- verwachte CTR per positie (NL, ter kalibratie) ---------- */
const VERWACHT = { 1: 0.28, 2: 0.15, 3: 0.11, 4: 0.08, 5: 0.06, 6: 0.05, 7: 0.04, 8: 0.035, 9: 0.03, 10: 0.025 };
function verwachteCtr(pos) {
  const p = Math.round(pos);
  if (p <= 10) return VERWACHT[Math.max(1, p)];
  if (p <= 20) return 0.008 + (20 - p) * 0.0015;
  if (p <= 30) return 0.003 + (30 - p) * 0.0005;
  return 0.002;
}

/* ---------- clusters ---------- */
const CLUSTER_WOORDEN = {
  toeslagen: ['toeslag', 'huurtoeslag', 'zorgtoeslag', 'kinderopvang', 'kindgebonden'],
  senioren: ['aow', 'pensioen', 'senior', 'ouderen', 'heffingskorting'],
  box3: ['box 3', 'box3', 'spaargeld', 'spaartaks', 'vermogen', 'sparen'],
  woning: ['hypotheek', 'eigen woning', 'eigenwoning', 'woz', 'voorlopige teruggave'],
  aangifte: ['aangifte', 'belastingaangifte', 'teruggave', 'uitstel', 'deadline', 'jaaropgave', 'loonstrook'],
  aftrek: ['aftrek', 'zorgkosten', 'giften', 'aftrekpost'],
  gemeente: ['kwijtschelding', 'gemeente', 'afvalstoffen', 'rioolheffing', 'ozb']
};
function clusterVan(q) {
  const s = q.toLowerCase();
  for (const naam of Object.keys(CLUSTER_WOORDEN)) {
    if (CLUSTER_WOORDEN[naam].some(function (w) { return s.indexOf(w) !== -1; })) return naam;
  }
  return 'overig';
}

/* ---------- csv lezen ---------- */
function cells(l) {
  const o = []; let c = '', q = false;
  for (let i = 0; i < l.length; i++) {
    const ch = l[i];
    if (q) { if (ch === '"') { if (l[i + 1] === '"') { c += '"'; i++; } else q = false; } else c += ch; }
    else { if (ch === '"') q = true; else if (ch === ',') { o.push(c); c = ''; } else c += ch; }
  }
  o.push(c); return o;
}

function lees(bestanden) {
  const rijen = [];
  for (const f of bestanden) {
    const regels = fs.readFileSync(path.join(BRON, f), 'utf8').trim().split(/\r?\n/);
    if (regels.length < 2) continue;
    for (const r of regels.slice(1)) {
      const c = cells(r);
      if (c.length < 7) continue;
      rijen.push({
        datum: c[0], query: c[1], page: c[2],
        clicks: +c[3], impressions: +c[4], ctr: +c[5], position: +c[6]
      });
    }
  }
  return rijen;
}

/* ---------- samenvoegen ---------- */
function groepeer(rijen, sleutel) {
  const m = new Map();
  for (const r of rijen) {
    const k = sleutel(r);
    let a = m.get(k);
    if (!a) { a = { k: k, clicks: 0, impressions: 0, posGewogen: 0 }; m.set(k, a); }
    a.clicks += r.clicks;
    a.impressions += r.impressions;
    a.posGewogen += r.position * r.impressions;   // wegen op vertoningen
  }
  const uit = [];
  m.forEach(function (a) {
    uit.push({
      k: a.k, clicks: a.clicks, impressions: a.impressions,
      ctr: a.impressions ? a.clicks / a.impressions : 0,
      position: a.impressions ? a.posGewogen / a.impressions : 0
    });
  });
  return uit;
}

/* ---------- rapport ---------- */
function tbl(head, rows) {
  if (!rows.length) return '_Geen._\n';
  return '| ' + head.join(' | ') + ' |\n| ' + head.map(function () { return '---'; }).join(' | ') + ' |\n' +
    rows.map(function (r) { return '| ' + r.map(function (c) { return String(c).replace(/\|/g, '\\|'); }).join(' | ') + ' |'; }).join('\n') + '\n';
}
function pct(x) { return (x * 100).toFixed(2) + '%'; }
function weeknr(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7));
  return Math.ceil((((t - new Date(Date.UTC(t.getUTCFullYear(), 0, 1))) / 86400000) + 1) / 7);
}

/* ---------- hoofdprogramma ---------- */
if (!fs.existsSync(BRON)) {
  console.error('Nog geen data in data/gsc/. Draai eerst: node scripts/gsc-export.js');
  process.exit(1);
}
const alle = fs.readdirSync(BRON).filter(function (f) { return /^\d{4}-\d{2}-\d{2}\.csv$/.test(f); }).sort();
if (!alle.length) {
  console.error('Nog geen data in data/gsc/. Draai eerst: node scripts/gsc-export.js');
  process.exit(1);
}

const nuBestanden = alle.slice(-VENSTER);
const vorigeBestanden = alle.slice(-(VENSTER * 2), -VENSTER);
const nu = lees(nuBestanden);
const vorige = lees(vorigeBestanden);

if (!nu.length) { console.error('Geen rijen in de laatste ' + VENSTER + ' dagen.'); process.exit(1); }

const perQuery = groepeer(nu, function (r) { return r.query; });
const perPage = groepeer(nu, function (r) { return r.page; });

/* ---------- echte totalen ----------
 * De rijen met een query-dimensie missen de geanonimiseerde zoekopdrachten.
 * Voor de KPI's gebruiken we daarom totals.csv, dat zonder die dimensie is
 * opgehaald. Verschil is groot: vaak zie je maar de helft van de vertoningen.
 */
function leesTotalen() {
  const f = path.join(BRON, 'totals.csv');
  if (!fs.existsSync(f)) return null;
  const m = new Map();
  fs.readFileSync(f, 'utf8').trim().split(/\r?\n/).slice(1).forEach(function (l) {
    const c = l.split(',');
    if (c[0]) m.set(c[0], { clicks: +c[1], impressions: +c[2], position: +c[4] });
  });
  return m;
}
const totalen = leesTotalen();

function somTotalen(bestanden) {
  if (!totalen) return null;
  let klik = 0, imp = 0, posG = 0, dagen = 0;
  for (const b of bestanden) {
    const t = totalen.get(b.slice(0, 10));
    if (!t) continue;
    klik += t.clicks; imp += t.impressions; posG += t.position * t.impressions; dagen++;
  }
  return dagen ? { clicks: klik, impressions: imp, position: imp ? posG / imp : 0, dagen: dagen } : null;
}

const echtNu = somTotalen(nuBestanden);
const echtVorige = somTotalen(vorigeBestanden);

const qKlik = nu.reduce(function (s, r) { return s + r.clicks; }, 0);
const qImp = nu.reduce(function (s, r) { return s + r.impressions; }, 0);

const totKlik = echtNu ? echtNu.clicks : qKlik;
const totImp = echtNu ? echtNu.impressions : qImp;
const gemPos = echtNu ? echtNu.position
  : (qImp ? nu.reduce(function (s, r) { return s + r.position * r.impressions; }, 0) / qImp : 0);

const periode = nuBestanden[0].slice(0, 10) + ' t/m ' + nuBestanden[nuBestanden.length - 1].slice(0, 10);
const wk = weeknr(new Date(nuBestanden[nuBestanden.length - 1].slice(0, 10) + 'T00:00:00Z'));

let md = '';
md += '# Search Console — week ' + wk + '\n\n';
md += 'Periode: ' + periode + ' (' + nuBestanden.length + ' dagen). Gegenereerd door `node scripts/gsc-report.js`.\n\n';

md += '## Samenvatting\n\n';
const rijenSam = [
  ['Klikken', totKlik],
  ['Vertoningen', totImp],
  ['CTR', pct(totImp ? totKlik / totImp : 0)],
  ['Gemiddelde positie', gemPos.toFixed(1)],
  ['Unieke keywords', perQuery.length],
  ['Unieke pagina\'s', perPage.length]
];
if (echtVorige) {
  rijenSam.push(['Klikken vorige periode', echtVorige.clicks + '  (' + (totKlik - echtVorige.clicks >= 0 ? '+' : '') + (totKlik - echtVorige.clicks) + ')']);
  rijenSam.push(['Vertoningen vorige periode', echtVorige.impressions + '  (' + (totImp - echtVorige.impressions >= 0 ? '+' : '') + (totImp - echtVorige.impressions) + ')']);
  rijenSam.push(['Positie vorige periode', echtVorige.position.toFixed(1) + '  (' + (gemPos - echtVorige.position <= 0 ? '' : '+') + (gemPos - echtVorige.position).toFixed(1) + ')']);
}
md += tbl(['Metric', 'Waarde'], rijenSam);

if (echtNu) {
  md += '\nDe cijfers hierboven komen uit `totals.csv`, zonder query-dimensie, dus dit zijn de echte totalen. ';
  md += 'De tabellen hieronder gebruiken data per zoekopdracht. Search Console laat zeldzame zoekopdrachten weg, ';
  md += 'dus daar tel je maar **' + Math.round(100 * qImp / (totImp || 1)) + '% van de vertoningen** en **' +
    Math.round(100 * qKlik / (totKlik || 1)) + '% van de klikken** terug. Dat is normaal; vergelijk die tabellen dus onderling, niet met de KPI\'s.\n';
}

md += '\n## 1. Keywords op positie 4-20 — CTR-kansen\n';
md += 'Hier sta je al hoog genoeg om klikken te winnen met een betere title en description.\n\n';
md += tbl(['Keyword', 'Pos', 'Vert.', 'Klik', 'CTR', 'Verwacht', 'Oordeel'],
  perQuery.filter(function (q) { return q.position >= 4 && q.position <= 20 && q.impressions >= 10; })
    .sort(function (a, b) { return b.impressions - a.impressions; }).slice(0, 30)
    .map(function (q) {
      const v = verwachteCtr(q.position);
      return [q.k, q.position.toFixed(1), q.impressions, q.clicks, pct(q.ctr), pct(v),
        q.ctr < v * 0.6 ? 'onder de maat' : 'ok'];
    }));

md += '\n## 2. Keywords op positie 21-50 — content-kansen\n';
md += 'Te laag voor klikken, maar Google toont je al. Betere content brengt deze naar pagina 1.\n\n';
md += tbl(['Keyword', 'Pos', 'Vert.', 'Cluster'],
  perQuery.filter(function (q) { return q.position > 20 && q.position <= 50 && q.impressions >= 10; })
    .sort(function (a, b) { return b.impressions - a.impressions; }).slice(0, 30)
    .map(function (q) { return [q.k, q.position.toFixed(1), q.impressions, clusterVan(q.k)]; }));

md += '\n## 3. Pagina\'s met veel vertoningen en minder dan 1% CTR\n';
md += 'Deze pagina\'s worden gezien maar niet aangeklikt. Kijk naar de title en de description.\n\n';
md += tbl(['Pagina', 'Vert.', 'Klik', 'CTR', 'Pos'],
  perPage.filter(function (p) { return p.impressions >= 50 && p.ctr < 0.01; })
    .sort(function (a, b) { return b.impressions - a.impressions; }).slice(0, 25)
    .map(function (p) { return [p.k.replace('https://belastinghulpzaanstad.nl', ''), p.impressions, p.clicks, pct(p.ctr), p.position.toFixed(1)]; }));

md += '\n## 4. Week-op-week per cluster\n';
if (!vorige.length) {
  md += '_Nog te weinig historie. Deze tabel vult zich zodra er ' + (VENSTER * 2) + ' dagen data staan._\n';
} else {
  function perCluster(rijen) {
    const m = new Map();
    for (const r of rijen) {
      const c = clusterVan(r.query);
      let a = m.get(c);
      if (!a) { a = { imp: 0, klik: 0, posG: 0 }; m.set(c, a); }
      a.imp += r.impressions; a.klik += r.clicks; a.posG += r.position * r.impressions;
    }
    return m;
  }
  const a = perCluster(nu), b = perCluster(vorige);
  const namen = Array.from(new Set(Array.from(a.keys()).concat(Array.from(b.keys())))).sort();
  md += tbl(['Cluster', 'Vert. nu', 'Vert. vorige', 'Pos nu', 'Pos vorige', 'Verschil'],
    namen.map(function (n) {
      const x = a.get(n) || { imp: 0, klik: 0, posG: 0 };
      const y = b.get(n) || { imp: 0, klik: 0, posG: 0 };
      const px = x.imp ? x.posG / x.imp : 0, py = y.imp ? y.posG / y.imp : 0;
      const d = (px && py) ? (px - py) : 0;
      return [n, x.imp, y.imp, px ? px.toFixed(1) : '-', py ? py.toFixed(1) : '-',
        d ? ((d <= 0 ? '' : '+') + d.toFixed(1) + (d < 0 ? ' (beter)' : d > 0 ? ' (slechter)' : '')) : '-'];
    }));
}

md += '\n---\n\nBron: `data/gsc/` (' + alle.length + ' dagen gearchiveerd, ' +
  alle[0].slice(0, 10) + ' t/m ' + alle[alle.length - 1].slice(0, 10) + ')\n';

fs.mkdirSync(UIT, { recursive: true });
const naam = 'gsc-week-' + String(wk).padStart(2, '0') + '.md';
fs.writeFileSync(path.join(UIT, naam), md, 'utf8');
console.log('OK  reports/' + naam + '  (' + periode + ', ' + totKlik + ' klikken, ' + totImp + ' vertoningen, pos ' + gemPos.toFixed(1) + ')');
