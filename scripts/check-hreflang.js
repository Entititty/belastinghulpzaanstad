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
 * niet mee aan de wederkerigheidseis; die mag naar de voorkeurstaal wijzen,
 * maar moet er wel zijn en in beide talen hetzelfde zijn. De taalknop
 * (NL | EN) bovenaan moet naar dezelfde vertaling gaan als hreflang.
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
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'intern') continue;
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

  /* x-default hoort in elk cluster, en beide talen wijzen naar dezelfde */
  if (!a['x-default']) { console.log('GEEN X-DEFAULT      ' + rel); fout++; }
  const tegen = Object.entries(a).find(([t, d]) => t !== 'x-default' && d !== url);
  if (tegen && kaart.get(tegen[1]) && kaart.get(tegen[1]).alts['x-default'] !== a['x-default']) {
    console.log('X-DEFAULT VERSCHILT  ' + rel + '  en ' + tegen[1]); fout++;
  }

  /* De taalknop (NL | EN) moet naar dezelfde vertaling gaan als hreflang.
     Op acht Engelse artikelen ging "NL" in oktober 2026 naar de Engelse
     pagina zelf; hreflang klopte wel, dus deze controle zag het niet. */
  if (tegen) {
    const html = fs.readFileSync(info.bestand, 'utf8');
    const knop = (html.match(/<div class="lang-toggle">([\s\S]*?)<\/div>/) || [])[1] || '';
    const tekst = /<html lang="en"/.test(html) ? 'NL' : 'EN';
    const href = (knop.match(new RegExp('<a href="([^"]*)"[^>]*>' + tekst + '</a>')) || [])[1];
    if (href !== undefined && href.replace(BASIS, '') !== tegen[1].replace(BASIS, '')) {
      console.log('TAALKNOP WIJKT AF    ' + rel + '  ' + tekst + ' -> ' + href + ', hreflang -> ' + tegen[1]); fout++;
    }
  }

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
