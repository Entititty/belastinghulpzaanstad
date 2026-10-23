#!/usr/bin/env node
/*
 * blog-kaarten-sync.js
 * Zet de titel van elke kaart op het blogoverzicht gelijk aan de <title> van
 * de pagina waar de kaart naartoe linkt.
 *
 * WAAROM
 * De kaarttitels op /blog/ en /en/blog/ waren met de hand geschreven en liepen
 * achter: na een nieuwe paginatitel bleef op het overzicht de oude staan (een
 * kaart noemde in oktober 2026 nog "Belastingaangifte 2025"). Nu is er één bron:
 * de <title> van het artikel, dezelfde tekst die Google in de zoekresultaten
 * toont. De korte omschrijving onder de titel blijft handwerk.
 *
 * Hetzelfde voor de linkteksten in de sectie "Blog artikelen" van llms.txt.
 *
 * WAT HET OOK CONTROLEERT
 * - twee kaarten naar dezelfde pagina op één overzicht (fout)
 * - een kaart naar een pagina die niet bestaat of op noindex staat, zoals een
 *   samengevoegd artikel dat alleen nog doorstuurt (fout)
 *
 * GEBRUIK
 *   node scripts/blog-kaarten-sync.js            schrijft de kaarttitels
 *   node scripts/blog-kaarten-sync.js --check    schrijft niets; exit 1 bij een afwijking
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CHECK = process.argv.includes('--check');
const OVERZICHTEN = ['blog/index.html', 'en/blog/index.html'];

const fouten = [];
let kaarten = 0, gewijzigd = 0;

for (const rel of OVERZICHTEN) {
  const bestand = path.join(ROOT, rel);
  if (!fs.existsSync(bestand)) continue;
  const voor = fs.readFileSync(bestand, 'utf8');
  const gezien = new Map();
  const na = voor.replace(/(<a href="([^"]+)" class="blog-card">[\s\S]*?<h3>)([\s\S]*?)(<\/h3>)/g, function (heel, begin, href, titel, eind) {
    kaarten++;
    const doelPad = href.startsWith('/') ? path.join(ROOT, href) : path.join(path.dirname(bestand), href);
    const doel = path.join(doelPad, 'index.html');
    const sleutel = path.relative(ROOT, doel);
    if (gezien.has(sleutel)) fouten.push(rel + ': twee kaarten naar ' + href + ' (ook als kaart ' + gezien.get(sleutel) + ')');
    else gezien.set(sleutel, kaarten);
    if (!fs.existsSync(doel)) { fouten.push(rel + ': kaart naar ' + href + ', maar die pagina bestaat niet'); return heel; }
    const html = fs.readFileSync(doel, 'utf8');
    const robots = (html.match(/<meta name="robots" content="([^"]*)"/) || [])[1] || '';
    if (/noindex/.test(robots)) { fouten.push(rel + ': kaart naar ' + href + ', maar die pagina staat op noindex (samengevoegd?)'); return heel; }
    const t = (html.match(/<title>([^<]*)<\/title>/) || [])[1];
    if (!t) { fouten.push(rel + ': ' + href + ' heeft geen <title>'); return heel; }
    if (titel.trim() === t.trim()) return heel;
    gewijzigd++;
    if (CHECK) console.log('  wijkt af  ' + rel + '  ' + href + '\n            kaart: ' + titel.trim() + '\n            title: ' + t.trim());
    return begin + t.trim() + eind;
  });
  if (!CHECK && na !== voor) fs.writeFileSync(bestand, na);
}

/* ---------- llms.txt, sectie "Blog artikelen" ----------
   Dezelfde lijst artikelen, als markdown: "- [titel](url)". Ook hier liep de
   titel achter op de pagina. Alleen deze sectie; bij Diensten en Pagina's zijn
   de linkteksten bewust beschrijvend. Een link naar een pagina op noindex of
   naar een pagina die niet bestaat, is een fout. */
function platteTekst(s) {
  return s.replace(/&amp;/g, '&').replace(/&euro;/g, '€').replace(/&rsquo;/g, '’').replace(/&ndash;/g, '–')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ').trim();
}
const LLMS = path.join(ROOT, 'llms.txt');
let llmsLinks = 0;
if (fs.existsSync(LLMS)) {
  const voor = fs.readFileSync(LLMS, 'utf8');
  const begin = voor.indexOf('\n## Blog artikelen');
  if (begin === -1) fouten.push('llms.txt: sectie "## Blog artikelen" niet gevonden');
  else {
    const eindRel = voor.slice(begin + 1).search(/\n## /);
    const eind = eindRel === -1 ? voor.length : begin + 1 + eindRel;
    const sectie = voor.slice(begin, eind).replace(/^(- \[)([^\]]*)(\]\(https:\/\/belastinghulpzaanstad\.nl(\/[^)]*)\))/gm, function (heel, a, titel, b, pad) {
      llmsLinks++;
      const doel = path.join(ROOT, pad, 'index.html');
      if (!fs.existsSync(doel)) { fouten.push('llms.txt: link naar ' + pad + ', maar die pagina bestaat niet'); return heel; }
      const html = fs.readFileSync(doel, 'utf8');
      if (/noindex/.test((html.match(/<meta name="robots" content="([^"]*)"/) || [])[1] || '')) { fouten.push('llms.txt: link naar ' + pad + ', maar die pagina staat op noindex'); return heel; }
      const t = platteTekst((html.match(/<title>([^<]*)<\/title>/) || [])[1] || '');
      if (!t || t === titel) return heel;
      gewijzigd++;
      if (CHECK) console.log('  wijkt af  llms.txt  ' + pad + '\n            tekst: ' + titel + '\n            title: ' + t);
      return a + t + b;
    });
    const na = voor.slice(0, begin) + sectie + voor.slice(eind);
    if (!CHECK && na !== voor) fs.writeFileSync(LLMS, na);
  }
}

console.log('blog-kaarten-sync: ' + kaarten + ' kaarten op ' + OVERZICHTEN.length + ' overzichten en ' + llmsLinks + ' artikellinks in llms.txt, ' + gewijzigd + ' titel(s) ' + (CHECK ? 'wijken af' : 'bijgewerkt'));
if (fouten.length) {
  console.error('\nFOUT:');
  fouten.forEach(function (f) { console.error('  - ' + f); });
  process.exit(1);
}
if (CHECK && gewijzigd) {
  console.error('\nFAIL: draai node scripts/blog-kaarten-sync.js');
  process.exit(1);
}
