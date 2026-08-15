#!/usr/bin/env node
/*
 * build-sitemap.js
 * Bouwt sitemap.xml als index, met vier deelsitemaps:
 *   sitemap-diensten.xml, sitemap-kennisbank.xml, sitemap-lokaal.xml, sitemap-overig.xml
 *
 * lastmod komt uit git: de datum van de laatste commit die het bestand raakte.
 * Heeft een bestand nog niet-gecommitte wijzigingen, dan wordt het vandaag,
 * want dan gaat die versie zo de deur uit. Zo blijft lastmod eerlijk;
 * een sitemap waarin alles "vandaag" is, gelooft Google namelijk niet.
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
function lastmod(file) {
  const rel = path.relative(ROOT, file).split(path.sep).join('/');
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
    lastmod: lastmod(file),
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

if (!DRY) {
  bestanden.forEach(function (b) { fs.writeFileSync(path.join(ROOT, b.naam), b.inhoud, 'utf8'); });
  fs.writeFileSync(path.join(ROOT, 'sitemap.xml'), index, 'utf8');
}

console.log((DRY ? '[dry] ' : '') + 'sitemap.xml (index) + ' + bestanden.length + ' deelsitemaps');
bestanden.forEach(function (b) { console.log('  ' + b.naam.padEnd(26) + String(b.aantal).padStart(3) + ' url\'s, laatste wijziging ' + b.lastmod); });
console.log('  overgeslagen (noindex of andere canonical): ' + overgeslagen);
