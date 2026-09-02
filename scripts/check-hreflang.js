#!/usr/bin/env node
/*
 * check-hreflang.js
 * Wijzen de hreflang-verwijzingen naar elkaar terug, en bestaan de doelen?
 * Faalt met exitcode 1 bij een probleem.
 *
 * WAAROM
 * Een hreflang-cluster werkt alleen als het wederzijds is: wijst de
 * Nederlandse pagina naar de Engelse, dan moet de Engelse terugwijzen, en
 * beide moeten ook naar zichzelf verwijzen. Google negeert het hele cluster
 * zodra dat niet klopt, zonder waarschuwing. Bij elke nieuwe pagina en bij
 * elke samenvoeging is dat opnieuw met de hand goed te zetten, dus telt het
 * script het liever na.
 *
 * Gecontroleerd wordt: bestaat het doelbestand, heeft dat doel zelf hreflang,
 * en staat de eigen canonical in het rijtje van de tegenhanger. x-default doet
 * niet mee aan de wederkerigheidseis; die mag naar de voorkeurstaal wijzen.
 *
 * GEBRUIK
 *   node scripts/check-hreflang.js .
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const BASIS = 'https://belastinghulpzaanstad.nl';

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name === 'index.html') acc.push(p);
  }
  return acc;
}

function urlNaarBestand(u) {
  const pad = u.replace(BASIS, '').replace(/^\//, '');
  return path.join(ROOT, pad, 'index.html');
}

const files = walk(ROOT, []);
const kaart = new Map(); /* url -> {nl, en, xdefault, self} */

for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  const canon = (s.match(/<link rel="canonical" href="([^"]+)"/) || [])[1];
  if (!canon) continue;
  const alts = {};
  const re = /<link rel="alternate" hreflang="([^"]+)" href="([^"]+)"/g;
  let m;
  while ((m = re.exec(s)) !== null) alts[m[1]] = m[2];
  if (!Object.keys(alts).length) continue;
  kaart.set(canon, { bestand: f, alts });
}

let fout = 0;
for (const [url, info] of kaart) {
  const a = info.alts;
  const rel = path.relative(ROOT, info.bestand).split(path.sep).join('/');

  /* verwijst de pagina naar zichzelf? */
  const zelf = Object.values(a).indexOf(url) !== -1;
  if (!zelf) { console.log('GEEN ZELFVERWIJZING  ' + rel); fout++; }

  for (const [taal, doel] of Object.entries(a)) {
    if (taal === 'x-default') continue;
    if (doel === url) continue;
    /* bestaat het doel? */
    if (!fs.existsSync(urlNaarBestand(doel))) {
      console.log('DOEL BESTAAT NIET    ' + rel + '  -> ' + doel); fout++; continue;
    }
    /* wijst het doel terug? */
    const terug = kaart.get(doel);
    if (!terug) { console.log('DOEL HEEFT GEEN HREFLANG  ' + rel + ' -> ' + doel); fout++; continue; }
    if (Object.values(terug.alts).indexOf(url) === -1) {
      console.log('NIET WEDERZIJDS      ' + rel + '  -> ' + doel + '  (dat wijst niet terug)');
      fout++;
    }
  }
}

console.log('\n' + kaart.size + ' pagina\'s met hreflang, ' + fout + ' probleem(en).');
process.exit(fout ? 1 : 0);
