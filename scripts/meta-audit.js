#!/usr/bin/env node
/*
 * meta-audit.js
 * Leest per HTML-pagina de title, de meta description en het aantal H1's uit,
 * en markeert:
 *   - title langer dan 60 tekens
 *   - meta description langer dan 155 tekens (of geen)
 *   - niet precies één H1
 *   - dezelfde title of meta description op meer dan één pagina
 *
 * Google kort een title af op breedte (ongeveer 580 px), niet op tekens. Een
 * title van 62 tekens met veel smalle letters blijft vaak heel; daarom staat er
 * een geschatte breedte bij (Arial 20 px, zoals in de zoekresultaten). De
 * markering op 60 tekens is een signaal om te kijken, geen fout.
 *
 * Pagina's op noindex (doorverwijzingen, 404) staan apart: die hoeven geen
 * omschrijving en tellen niet mee voor dubbelen.
 *
 * GEBRUIK
 *   node scripts/meta-audit.js                  samenvatting en de gemarkeerde pagina's
 *   node scripts/meta-audit.js --md <bestand>   schrijft ook de volledige tabel als markdown
 *
 * Exit 1 bij een indexeerbare pagina zonder precies één H1, zonder title, of met
 * een dubbele title of omschrijving. Lengtes zijn een waarschuwing.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const mdIndex = process.argv.indexOf('--md');
const MD = mdIndex !== -1 ? path.resolve(process.argv[mdIndex + 1] || path.join(ROOT, 'reports', 'meta-audit.md')) : null;
const MAX_TITLE = 60, MAX_META = 155;

/* breedte per teken in Arial, in duizendsten van de lettergrootte */
const W = { a: 556, b: 556, c: 500, d: 556, e: 556, f: 278, g: 556, h: 556, i: 222, j: 222, k: 500, l: 222, m: 833, n: 556, o: 556, p: 556, q: 556, r: 333, s: 500, t: 278, u: 556, v: 500, w: 722, x: 500, y: 500, z: 500,
  A: 667, B: 667, C: 722, D: 722, E: 667, F: 611, G: 778, H: 722, I: 278, J: 500, K: 667, L: 556, M: 833, N: 722, O: 778, P: 667, Q: 778, R: 722, S: 667, T: 611, U: 722, V: 667, W: 944, X: 667, Y: 667, Z: 611,
  ' ': 278, '.': 278, ',': 278, ':': 278, ';': 278, '-': 333, '–': 556, '—': 1000, '|': 260, '?': 556, '!': 278, '€': 556, '&': 667, '(': 333, ')': 333, '/': 278, "'": 191, '"': 355, '%': 889, '+': 584, '’': 222 };
function px(s) { let u = 0; for (const ch of s) u += W[ch] || W[ch.normalize('NFD')[0]] || 556; return Math.round(u / 1000 * 20); }
function tekst(s) {
  return s.replace(/&amp;/g, '&').replace(/&euro;/g, '€').replace(/&rsquo;/g, '’').replace(/&lsquo;/g, '‘').replace(/&ndash;/g, '–')
    .replace(/&mdash;/g, '—').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ').replace(/&eacute;/g, 'é').replace(/&euml;/g, 'ë').trim();
}

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['.git', 'node_modules', 'docs', 'reports', 'data', 'intern'].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc); else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}

const rijen = [];
for (const f of walk(ROOT, []).sort()) {
  const html = fs.readFileSync(f, 'utf8');
  const kop = html.split('</head>')[0];
  const lichaam = html.slice(kop.length);
  const robots = (kop.match(/<meta name="robots" content="([^"]*)"/) || [])[1] || '';
  rijen.push({
    url: '/' + path.relative(ROOT, f).split(path.sep).join('/').replace(/index\.html$/, ''),
    title: tekst((kop.match(/<title>([^<]*)<\/title>/) || [])[1] || ''),
    meta: tekst((kop.match(/<meta name="description" content="([^"]*)"/) || [])[1] || ''),
    h1: (lichaam.match(/<h1[\s>]/gi) || []).length,
    noindex: /noindex/.test(robots)
  });
}

const indexeerbaar = rijen.filter((r) => !r.noindex);
const telTitle = new Map(), telMeta = new Map();
indexeerbaar.forEach((r) => {
  if (r.title) telTitle.set(r.title, (telTitle.get(r.title) || 0) + 1);
  if (r.meta) telMeta.set(r.meta, (telMeta.get(r.meta) || 0) + 1);
});
let fouten = 0;
for (const r of rijen) {
  r.vlag = [];
  if (!r.title) r.vlag.push('geen title');
  else if (r.title.length > MAX_TITLE) r.vlag.push('title > ' + MAX_TITLE);
  if (r.noindex) { r.vlag.push('noindex'); continue; }
  if (!r.meta) r.vlag.push('geen meta');
  else if (r.meta.length > MAX_META) r.vlag.push('meta > ' + MAX_META);
  if (r.h1 !== 1) r.vlag.push('H1 = ' + r.h1);
  if (telTitle.get(r.title) > 1) r.vlag.push('dubbele title');
  if (telMeta.get(r.meta) > 1) r.vlag.push('dubbele meta');
  if (!r.title || r.h1 !== 1 || telTitle.get(r.title) > 1 || telMeta.get(r.meta) > 1) fouten++;
}

const cel = (s) => String(s).replace(/\|/g, '\\|');
const kopregel = '| Pagina | Title | Tekens | px | Meta description | Tekens | H1 | Markering |\n| --- | --- | ---: | ---: | --- | ---: | ---: | --- |\n';
const rij = (r) => '| ' + r.url + ' | ' + cel(r.title) + ' | ' + r.title.length + ' | ' + px(r.title) + ' | ' + cel(r.meta) + ' | ' + r.meta.length + ' | ' + r.h1 + ' | ' + r.vlag.join(', ') + ' |';

const gemarkeerd = indexeerbaar.filter((r) => r.vlag.length);
const n = (v) => indexeerbaar.filter((r) => r.vlag.includes(v)).length;
console.log('meta-audit: ' + rijen.length + ' HTML-pagina\'s, waarvan ' + indexeerbaar.length + ' indexeerbaar en ' + (rijen.length - indexeerbaar.length) + ' op noindex');
console.log('  title > ' + MAX_TITLE + ' tekens: ' + n('title > ' + MAX_TITLE) + ' (breder dan 580 px: ' + indexeerbaar.filter((r) => px(r.title) > 580).length + ')');
console.log('  meta > ' + MAX_META + ' tekens: ' + n('meta > ' + MAX_META) + ', geen meta: ' + n('geen meta'));
console.log('  H1 ≠ 1: ' + indexeerbaar.filter((r) => r.h1 !== 1).length);
console.log('  dubbele title: ' + n('dubbele title') + ', dubbele meta: ' + n('dubbele meta'));
if (gemarkeerd.length) {
  console.log('\nGemarkeerde indexeerbare pagina\'s:');
  gemarkeerd.forEach((r) => console.log('  ' + r.url + '  [' + r.vlag.join(', ') + ']  title ' + r.title.length + ' tekens / ' + px(r.title) + ' px, meta ' + r.meta.length));
}
if (MD) {
  const md = '# Meta-audit\n\nGemaakt met `node scripts/meta-audit.js --md`. Title > ' + MAX_TITLE + ' en meta > ' + MAX_META +
    ' tekens zijn een signaal; Google kort af op breedte (ongeveer 580 px).\n\n## Indexeerbare pagina\'s (' + indexeerbaar.length + ')\n\n' +
    kopregel + indexeerbaar.map(rij).join('\n') + '\n\n## Noindex (' + (rijen.length - indexeerbaar.length) + ')\n\n' +
    kopregel + rijen.filter((r) => r.noindex).map(rij).join('\n') + '\n';
  fs.mkdirSync(path.dirname(MD), { recursive: true });
  fs.writeFileSync(MD, md);
  console.log('\nVolledige tabel: ' + path.relative(ROOT, MD));
}
process.exit(fouten ? 1 : 0);
