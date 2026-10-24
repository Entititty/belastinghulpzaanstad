#!/usr/bin/env node
/*
 * bouw.js
 * Eén commando voor elke uitrol: zet de gegevens uit data/bedrijf.json in de
 * HTML, zet de kaarttitels op het blogoverzicht gelijk aan de paginatitels,
 * maakt de stylesheetnaam kloppend en draait alle controles.
 *
 * WAAROM
 * De site heeft geen build. De controles bestonden wel, maar los, en de lijst
 * in server-setup/DEPLOY.md liep achter op de scripts. Dit script is die lijst.
 * Lege placeholders in data/bedrijf.json (KvK-nummer, btw of KOR,
 * Google-reviewlink) zijn een waarschuwing en geen fout: de site klopt dan,
 * er staat alleen minder op. Ze worden onderaan nog eens samengevat, zodat ze
 * niet wegvallen tussen de andere uitvoer.
 *
 * GEBRUIK
 *   node scripts/bouw.js           schrijft (config-sync, blog-kaarten-sync, hash-css) en controleert
 *   node scripts/bouw.js --check   schrijft niets; faalt als de HTML afwijkt
 *
 * Exit 1 zodra een stap faalt. De sitemap (scripts/build-sitemap.js) hoort
 * hier niet bij: die leest de commitdatums en draait na het committen.
 */
const { spawnSync } = require('child_process');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CHECK = process.argv.includes('--check');

const STAPPEN = [
  ['config-sync', CHECK ? ['--check'] : []],
  ['blog-kaarten-sync', CHECK ? ['--check'] : []],
  ['hash-css', CHECK ? ['--dry'] : []],
  ['check-html', []],
  ['check-knoppen', []],
  ['check-formulieren', []],
  ['check-fiscale-cijfers', []],
  ['check-rekenvoorbeelden', []],
  ['check-jsonld', []],
  ['check-links', ['.']],
  ['check-hreflang', ['.']],
  ['check-contrast', []],
  ['crawl-audit', []]
];

const mislukt = [];
let placeholders = [];
for (const [naam, args] of STAPPEN) {
  const r = spawnSync(process.execPath, [path.join('scripts', naam + '.js')].concat(args), { cwd: ROOT, encoding: 'utf8' });
  const uit = (r.stdout || '') + (r.stderr || '');
  const goed = r.status === 0;
  console.log('\n=== ' + naam + (goed ? '' : '  (FOUT)'));
  console.log(uit.trim());
  if (!goed) mislukt.push(naam);
  if (naam === 'config-sync') placeholders = uit.split('\n').filter((l) => /^\s*!\s/.test(l));
}

console.log('\n=== samenvatting');
console.log(STAPPEN.length + ' stappen, ' + mislukt.length + ' fout' + (mislukt.length ? ': ' + mislukt.join(', ') : ''));
if (placeholders.length) {
  console.log('\nWAARSCHUWING: ' + placeholders.length + ' open punt(en) in data/bedrijf.json:');
  placeholders.forEach((l) => console.log(l));
}
if (!CHECK && !mislukt.length) console.log('\nCommit de wijzigingen en draai daarna: node scripts/build-sitemap.js');
process.exit(mislukt.length ? 1 : 0);
