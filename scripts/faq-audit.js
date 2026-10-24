#!/usr/bin/env node
/*
 * faq-audit.js
 * Wat zou faq-sync.js per pagina veranderen? Toont per pagina welke vragen uit
 * het FAQPage-schema verdwijnen en welke zichtbare vragen erbij komen.
 *
 * WAAROM
 * faq-sync.js schrijft het schema opnieuw op basis van de zichtbare FAQ. Dat is
 * de juiste richting, maar het is een eenrichtingsactie: een vraag die alleen
 * in het schema stond, is daarna weg. In september 2026 bleek dat 22 pagina's
 * zulke vragen droegen, 36 in totaal. Sommige daarvan hadden een antwoord dat
 * inhoudelijk klopte en op de pagina thuishoorde; andere noemden bedragen die
 * nergens te bevestigen waren, en één op /en/blog/rent-benefit/ noemde
 * huurgrenzen van rond 2023.
 *
 * Daarom eerst dit overzicht, en pas daarna faq-sync. Verdwijnende vragen
 * krijgen hun antwoord erbij, want daarover moet een mens beslissen: weggooien,
 * of eerst als zichtbare vraag op de pagina zetten.
 *
 * GEBRUIK
 *   node scripts/faq-audit.js .           volledig, met de antwoorden
 *   node scripts/faq-audit.js . --kort    één regel per pagina
 *
 * Een verschil in leestekens telt apart van een echt verzonnen vraag: dat
 * eerste is een streepje of een puntkomma, dat tweede is inhoud.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const KORT = process.argv.includes('--kort');

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'intern') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name === 'index.html') acc.push(p);
  }
  return acc;
}
function ontdoe(t) {
  return t.replace(/<span class="faq-arrow">[\s\S]*?<\/span>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&euro;/g, '€').replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&rsquo;/g, "'")
    .replace(/&rarr;/g, '->').replace(/&ndash;/g, '-').replace(/&middot;/g, '.')
    .replace(/\s+/g, ' ').trim();
}
function kaal(q) {
  return q.toLowerCase().replace(/[^a-z0-9áéíóúëïöüè ]/g, ' ').replace(/\s+/g, ' ').trim();
}

const files = walk(ROOT, []);
let paginas = 0, verzonnenTotaal = 0, cosmetisch = 0, toegevoegd = 0;
const zwaar = [];

for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  /* alle JSON-LD-blokken parsen en het FAQPage-blok eruit pakken; een
     niet-gulzige match op één blok knipt het bij het eerste accolade-einde af
     en levert onleesbare JSON */
  const blokken = s.match(/<script type="application\/ld\+json">[\s\S]*?<\/script>/g) || [];
  let schema = null;
  for (const b of blokken) {
    const body = b.replace(/^<script[^>]*>/, '').replace(/<\/script>$/, '');
    if (body.indexOf('FAQPage') === -1) continue;
    try { schema = JSON.parse(body); } catch (e) {
      console.log('ONLEESBAAR SCHEMA  ' + path.relative(ROOT, f) + ': ' + e.message.slice(0, 60));
    }
    break;
  }
  if (!schema) continue;
  const schemaVragen = (schema.mainEntity || []).map((q) => ({
    vraag: q.name,
    antwoord: (q.acceptedAnswer && q.acceptedAnswer.text) || '',
  }));

  const zichtbaar = [];
  const re = /class="faq-question"[^>]*>([\s\S]*?)<\/button>\s*<div class="faq-answer">([\s\S]*?)<\/div>/gi;
  let m;
  while ((m = re.exec(s)) !== null) {
    zichtbaar.push({ vraag: ontdoe(m[1]), antwoord: ontdoe(m[2]) });
  }
  if (!zichtbaar.length) { console.log('SCHEMA ZONDER ZICHTBARE FAQ  ' + path.relative(ROOT, f)); continue; }

  const zKaal = zichtbaar.map((z) => kaal(z.vraag));
  const sKaal = schemaVragen.map((q) => kaal(q.vraag));

  const verdwijnt = schemaVragen.filter((q, i) => zKaal.indexOf(sKaal[i]) === -1);
  const komtErbij = zichtbaar.filter((z) => sKaal.indexOf(kaal(z.vraag)) === -1);
  if (!verdwijnt.length && !komtErbij.length) continue;

  /* leestekenverschil of echt verzonnen? */
  const echtWeg = verdwijnt.filter((q) => {
    const b = kaal(q.vraag).split(' ').slice(0, 4).join(' ');
    return !zKaal.some((z) => z.split(' ').slice(0, 4).join(' ') === b);
  });

  paginas++;
  verzonnenTotaal += echtWeg.length;
  toegevoegd += komtErbij.length;
  if (!echtWeg.length) { cosmetisch++; }

  const rel = '/' + path.relative(ROOT, f).split(path.sep).join('/').replace(/index\.html$/, '');
  if (KORT) {
    console.log(rel.padEnd(46) + 'zichtbaar ' + zichtbaar.length + ' / schema ' + schemaVragen.length +
      '  weg: ' + verdwijnt.length + ' (echt ' + echtWeg.length + ')  erbij: ' + komtErbij.length);
  } else {
    console.log('\n=== ' + rel + '   zichtbaar ' + zichtbaar.length + ', schema ' + schemaVragen.length);
    verdwijnt.forEach((q) => {
      const soort = echtWeg.indexOf(q) !== -1 ? 'WEG (verzonnen)' : 'weg (leestekens)';
      console.log('  - ' + soort + ': ' + q.vraag);
      if (echtWeg.indexOf(q) !== -1) console.log('      antwoord: ' + q.antwoord.slice(0, 200));
    });
    komtErbij.forEach((z) => console.log('  + erbij: ' + z.vraag));
  }
  if (echtWeg.length) zwaar.push([rel, echtWeg]);
}

console.log('\n--- samenvatting ---');
console.log("pagina's die wijzigen        : " + paginas);
console.log('  waarvan alleen leestekens  : ' + cosmetisch);
console.log('  waarvan verzonnen vragen   : ' + (paginas - cosmetisch));
console.log('verzonnen vragen totaal      : ' + verzonnenTotaal);
console.log('zichtbare vragen die erbij komen: ' + toegevoegd);
