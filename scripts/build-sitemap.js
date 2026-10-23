#!/usr/bin/env node
/*
 * build-sitemap.js
 * Bouwt sitemap.xml als index, met vier deelsitemaps:
 *   sitemap-diensten.xml, sitemap-kennisbank.xml, sitemap-lokaal.xml, sitemap-overig.xml
 *
 * lastmod is eerst de datum die de pagina zelf noemt: "Laatst bijgewerkt" of
 * "Last updated", met een <time datetime> of als tekst ("4 augustus 2026").
 * Die datum gaat alleen omhoog bij een inhoudelijke wijziging. Een commit die
 * op alle pagina's tegelijk het menu, de footer of de JSON-LD van het bedrijf
 * aanpaste, gaf voorheen elke pagina dezelfde lastmod; zo'n sitemap gelooft
 * Google niet. Noemt de pagina geen datum, dan geldt de laatste commit die
 * het bestand raakte, of vandaag als het nog niet-gecommitte wijzigingen
 * heeft (die versie gaat zo de deur uit).
 *
 * Na het schrijven controleert het script de XML: namespace, één <loc> en één
 * <lastmod> per <url>, absolute https-adressen, geen dubbele adressen.
 *
 * Draai dit NA het committen en VOOR het uitrollen.
 * Gebruik: node scripts/build-sitemap.js [--dry]
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const ORIGIN = 'https://belastinghulpzaanstad.nl';
const DRY = process.argv.indexOf('--dry') !== -1;
const VANDAAG = new Date().toISOString().slice(0, 10);

/* ---------- pagina's verzamelen ---------- */
function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      walk(path.join(dir, e.name), acc);
    } else if (e.name === 'index.html') acc.push(path.join(dir, e.name));
  }
  return acc;
}

function url(file) {
  let rel = path.relative(ROOT, file).split(path.sep).join('/');
  rel = rel.replace(/index\.html$/, '');
  return ORIGIN + '/' + rel;
}

/* ---------- indexeerbaar? ---------- */
function indexeerbaar(html, u) {
  const robots = (html.match(/<meta[^>]+name=["']robots["'][^>]*>/i) || [''])[0];
  if (/noindex/i.test(robots)) return false;
  // Een canonical naar een andere URL betekent: niet zelf indexeren.
  const c = html.match(/<link[^>]+rel=["']canonical["'][^>]*href=["']([^"']+)["']/i);
  if (c && c[1].replace(/\/$/, '') !== u.replace(/\/$/, '')) return false;
  return true;
}

/* ---------- lastmod ---------- */
function git(args) {
  try { return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim(); }
  catch (e) { return ''; }
}
const gewijzigd = new Set(
  git(['status', '--porcelain']).split(/\r?\n/)
    .map(function (l) { return l.slice(3).trim(); })
    .filter(Boolean)
);
const MAANDEN = {
  januari: 1, februari: 2, maart: 3, april: 4, mei: 5, juni: 6, juli: 7, augustus: 8,
  september: 9, oktober: 10, november: 11, december: 12,
  january: 1, february: 2, march: 3, may: 5, june: 6, july: 7, august: 8, october: 10
};
function paginaDatum(html) {
  const t = html.match(/(?:laatst bijgewerkt|last updated)[^<]{0,20}<time datetime="(\d{4}-\d{2}-\d{2})"/i);
  if (t) return t[1];
  const m = html.match(/(?:laatst bijgewerkt|last updated):?\s*(\d{1,2})\s+([a-z]+)\s+(\d{4})/i);
  const maand = m && MAANDEN[m[2].toLowerCase()];
  return maand ? m[3] + '-' + String(maand).padStart(2, '0') + '-' + m[1].padStart(2, '0') : null;
}
const herkomst = { pagina: 0, git: 0 };
function lastmod(file, html) {
  const rel = path.relative(ROOT, file).split(path.sep).join('/');
  const p = paginaDatum(html);
  if (p) {
    herkomst.pagina++;
    if (p > VANDAAG) { console.warn('  ! ' + rel + ': "Laatst bijgewerkt" ligt in de toekomst (' + p + '), vandaag gebruikt'); return VANDAAG; }
    return p;
  }
  herkomst.git++;
  if (gewijzigd.has(rel)) return VANDAAG;
  const d = git(['log', '-1', '--format=%cs', '--', rel]);
  return /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : VANDAAG;
}

/* ---------- groepen ---------- */
function groepVan(u) {
  const p = u.replace(ORIGIN, '');
  if (/^\/(en\/)?blog\//.test(p)) return 'kennisbank';
  if (/\/(diensten|services)\//.test(p)) return 'diensten';
  if (/^\/(en\/)?(zaandam|koog-aan-de-zaan|wormerveer|krommenie|assendelft|westzaan|zaandijk|oostzaan|wormerland)\//.test(p)) return 'lokaal';
  return 'overig';
}

const PRIORITEIT = {
  '/': '1.0', '/en/': '0.9',
  diensten: '0.9', lokaal: '0.8', kennisbank: '0.7', overig: '0.5'
};
const FREQ = { diensten: 'monthly', lokaal: 'monthly', kennisbank: 'monthly', overig: 'yearly' };

/* ---------- bouwen ---------- */
const groepen = { diensten: [], kennisbank: [], lokaal: [], overig: [] };
let overgeslagen = 0;

for (const file of walk(ROOT, []).sort()) {
  const html = fs.readFileSync(file, 'utf8');
  const u = url(file);
  if (!indexeerbaar(html, u)) { overgeslagen++; continue; }
  const g = groepVan(u);
  const p = u.replace(ORIGIN, '');
  groepen[g].push({
    loc: u,
    lastmod: lastmod(file, html),
    changefreq: FREQ[g],
    priority: PRIORITEIT[p] || PRIORITEIT[g]
  });
}

function xmlEsc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function urlset(items) {
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    items.map(function (i) {
      return '  <url>\n' +
        '    <loc>' + xmlEsc(i.loc) + '</loc>\n' +
        '    <lastmod>' + i.lastmod + '</lastmod>\n' +
        '    <changefreq>' + i.changefreq + '</changefreq>\n' +
        '    <priority>' + i.priority + '</priority>\n' +
        '  </url>';
    }).join('\n') + '\n</urlset>\n';
}

const bestanden = [];
for (const g of Object.keys(groepen)) {
  if (!groepen[g].length) continue;
  const naam = 'sitemap-' + g + '.xml';
  bestanden.push({
    naam: naam,
    aantal: groepen[g].length,
    lastmod: groepen[g].map(function (i) { return i.lastmod; }).sort().pop(),
    inhoud: urlset(groepen[g])
  });
}

const index = '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
  bestanden.map(function (b) {
    return '  <sitemap>\n' +
      '    <loc>' + ORIGIN + '/' + b.naam + '</loc>\n' +
      '    <lastmod>' + b.lastmod + '</lastmod>\n' +
      '  </sitemap>';
  }).join('\n') + '\n</sitemapindex>\n';

/* ---------- controle van de eigen uitvoer ----------
   De XML komt uit dit script, dus de controle is op opbouw, niet met een
   volledige parser: gelijke aantallen open- en sluittags, de juiste
   namespace, per <url> precies één <loc> en één <lastmod>. */
const NS = 'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"';
const problemen = [];
const alleLocs = new Set();
function controleer(naam, xml, wortel, item) {
  if (xml.indexOf('<?xml version="1.0" encoding="UTF-8"?>\n<' + wortel + ' ' + NS + '>') !== 0) problemen.push(naam + ': kop of namespace klopt niet');
  ['loc', 'lastmod', item, wortel].forEach(function (tag) {
    const open = (xml.match(new RegExp('<' + tag + '[ >]', 'g')) || []).length;
    const dicht = (xml.match(new RegExp('</' + tag + '>', 'g')) || []).length;
    if (open !== dicht) problemen.push(naam + ': ' + open + 'x <' + tag + '> tegen ' + dicht + 'x </' + tag + '>');
  });
  const blokken = xml.split('<' + item + '>').slice(1);
  blokken.forEach(function (b) {
    const locs = b.match(/<loc>([^<]*)<\/loc>/g) || [];
    const data = b.match(/<lastmod>(\d{4}-\d{2}-\d{2})<\/lastmod>/g) || [];
    if (locs.length !== 1 || data.length !== 1) { problemen.push(naam + ': een <' + item + '> zonder precies één loc en één lastmod'); return; }
    const loc = locs[0].replace(/<\/?loc>/g, '');
    if (loc.indexOf(ORIGIN + '/') !== 0) problemen.push(naam + ': geen absoluut https-adres: ' + loc);
    if (item === 'url') { if (alleLocs.has(loc)) problemen.push(naam + ': dubbel adres ' + loc); alleLocs.add(loc); }
  });
  if (/&(?!amp;|lt;|gt;|quot;|apos;)/.test(xml)) problemen.push(naam + ': losse & in de XML');
}
bestanden.forEach(function (b) { controleer(b.naam, b.inhoud, 'urlset', 'url'); });
controleer('sitemap.xml', index, 'sitemapindex', 'sitemap');
if (problemen.length) {
  console.error('FOUT in de sitemap, niets geschreven:');
  problemen.forEach(function (p) { console.error('  - ' + p); });
  process.exit(1);
}

if (!DRY) {
  bestanden.forEach(function (b) { fs.writeFileSync(path.join(ROOT, b.naam), b.inhoud, 'utf8'); });
  fs.writeFileSync(path.join(ROOT, 'sitemap.xml'), index, 'utf8');
}

console.log((DRY ? '[dry] ' : '') + 'sitemap.xml (index) + ' + bestanden.length + ' deelsitemaps, XML gecontroleerd');
bestanden.forEach(function (b) { console.log('  ' + b.naam.padEnd(26) + String(b.aantal).padStart(3) + ' url\'s, laatste wijziging ' + b.lastmod); });
console.log('  lastmod uit "Laatst bijgewerkt" op de pagina: ' + herkomst.pagina + ', uit git: ' + herkomst.git);
console.log('  overgeslagen (noindex of andere canonical): ' + overgeslagen);
