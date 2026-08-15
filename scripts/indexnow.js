#!/usr/bin/env node
/*
 * indexnow.js
 * Meldt gewijzigde URL's aan bij IndexNow. Bing pakt dat op, en Bing voedt
 * de zoekresultaten van ChatGPT. Daarom staat dit in het plan onder GEO
 * en niet onder "leuk als het lukt".
 *
 * De sleutel is het .txt-bestand in de root; de naam ervan is de sleutel.
 * Dat bestand moet publiek bereikbaar blijven, anders weigert IndexNow.
 *
 * Gebruik:
 *   node scripts/indexnow.js --sinds HEAD~1     # URL's uit de laatste commit
 *   node scripts/indexnow.js --alles            # alles uit de sitemap
 *   node scripts/indexnow.js /blog/x/ /diensten/y/
 *   voeg --dry toe om alleen te tonen wat er gestuurd zou worden
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const HOST = 'belastinghulpzaanstad.nl';
const ORIGIN = 'https://' + HOST;
const DRY = process.argv.indexOf('--dry') !== -1;
const MAX = 10000;   // limiet van IndexNow per verzoek

/* ---------- sleutel ---------- */
function vindSleutel() {
  const kandidaten = fs.readdirSync(ROOT).filter(function (f) { return /^[0-9a-f]{8,128}\.txt$/i.test(f); });
  if (!kandidaten.length) return null;
  const bestand = kandidaten[0];
  const sleutel = bestand.replace(/\.txt$/i, '');
  const inhoud = fs.readFileSync(path.join(ROOT, bestand), 'utf8').trim();
  if (inhoud !== sleutel) {
    console.error('Let op: ' + bestand + ' bevat niet exact de sleutel. IndexNow weigert dat.');
    return null;
  }
  return sleutel;
}

/* ---------- welke URL's ---------- */
function padNaarUrl(rel) {
  if (!/index\.html$/.test(rel)) return null;
  return ORIGIN + '/' + rel.replace(/index\.html$/, '');
}

function uitGit(sinds) {
  const uit = execFileSync('git', ['diff', '--name-only', sinds, 'HEAD'], { cwd: ROOT, encoding: 'utf8' });
  return uit.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean)
    .map(padNaarUrl).filter(Boolean);
}

function uitSitemaps() {
  const uit = [];
  for (const f of fs.readdirSync(ROOT)) {
    if (!/^sitemap.*\.xml$/.test(f)) continue;
    const x = fs.readFileSync(path.join(ROOT, f), 'utf8');
    if (/<sitemapindex/.test(x)) continue;
    for (const m of x.matchAll(/<loc>([^<]+)<\/loc>/g)) uit.push(m[1]);
  }
  return uit;
}

function arg(naam) {
  const i = process.argv.indexOf('--' + naam);
  return i !== -1 ? (process.argv[i + 1] || true) : null;
}

let urls;
if (arg('alles')) urls = uitSitemaps();
else if (arg('sinds')) urls = uitGit(arg('sinds'));
else {
  urls = process.argv.slice(2).filter(function (a) { return a.indexOf('-') !== 0; })
    .map(function (p) { return /^https?:/.test(p) ? p : ORIGIN + (p[0] === '/' ? p : '/' + p); });
}
urls = Array.from(new Set(urls)).filter(Boolean).slice(0, MAX);

if (!urls.length) {
  console.log('Geen URL\'s om te melden.');
  process.exit(0);
}

const sleutel = vindSleutel();
if (!sleutel) {
  console.error('Geen geldig sleutelbestand in de root gevonden. Maak <sleutel>.txt met de sleutel erin.');
  process.exit(1);
}

console.log('host    : ' + HOST);
console.log('sleutel : ' + sleutel);
console.log('urls    : ' + urls.length);
urls.slice(0, 10).forEach(function (u) { console.log('   ' + u); });
if (urls.length > 10) console.log('   ... en nog ' + (urls.length - 10));

if (DRY) { console.log('\n[dry] niets verstuurd'); process.exit(0); }

(async function () {
  const res = await fetch('https://api.indexnow.org/indexnow', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      host: HOST,
      key: sleutel,
      keyLocation: ORIGIN + '/' + sleutel + '.txt',
      urlList: urls
    })
  });
  const tekst = await res.text();
  // 200 = ok, 202 = geaccepteerd maar sleutel wordt nog gecontroleerd
  if (res.status === 200 || res.status === 202) {
    console.log('\nOK (' + res.status + ')' + (res.status === 202 ? ' — sleutel wordt nog geverifieerd' : ''));
  } else {
    console.error('\nMislukt (' + res.status + '): ' + tekst.slice(0, 300));
    process.exit(1);
  }
})().catch(function (e) {
  console.error('\nMislukt: ' + e.message);
  process.exit(1);
});
