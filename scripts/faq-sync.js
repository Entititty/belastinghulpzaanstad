#!/usr/bin/env node
/*
 * faq-sync.js
 * Schrijft het FAQPage-schema van een pagina opnieuw, op basis van de FAQ die
 * er zichtbaar staat.
 *
 * WAAROM
 * Google eist dat een FAQPage-blok overeenkomt met wat de bezoeker ziet. Op de
 * homepage en op /blog/zorgkosten-aftrekken/ was dat uit elkaar gelopen: het
 * schema noemde vragen en bedragen die nergens op de pagina stonden.
 * check-fiscale-cijfers.js faalt daar nu op; dit script repareert het.
 *
 * GEBRUIK
 *   node scripts/faq-sync.js <bestand>            toont wat het zou doen
 *   node scripts/faq-sync.js <bestand> --schrijf   voert het door
 *
 * Het script leest .faq-question en .faq-answer, ontdoet de tekst van tags en
 * entiteiten, en vervangt het bestaande FAQPage-blok. Staat er geen zichtbare
 * FAQ, gebruik het dan niet: dan hoort er ook geen FAQPage-schema te staan.
 */
const fs = require('fs');

const FILE = process.argv[2];
const SCHRIJF = process.argv.includes('--schrijf');
const src = fs.readFileSync(FILE, 'utf8');
const eol = src.includes('\r\n') ? '\r\n' : '\n';

function ontdoe(html) {
  let t = html
    .replace(/<span class="faq-arrow">[\s\S]*?<\/span>/gi, ' ')
    .replace(/<[^>]+>/g, ' ');
  const ent = {
    '&amp;': '&', '&euro;': '€', '&nbsp;': ' ', '&ndash;': '–', '&mdash;': '—',
    '&rsquo;': '’', '&lsquo;': '‘', '&ldquo;': '“', '&rdquo;': '”',
    '&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>', '&middot;': '·',
    '&hellip;': '…', '&eacute;': 'é', '&rarr;': '→', '&#10003;': '✓',
  };
  for (const [k, v] of Object.entries(ent)) t = t.split(k).join(v);
  t = t.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
  return t.replace(/\s+/g, ' ').trim();
}

/* zichtbare vragen en antwoorden ophalen */
const items = [];
const itemRe = /<div class="faq-item">([\s\S]*?)<\/div>\s*<\/div>/g;
let m;
while ((m = itemRe.exec(src)) !== null) {
  const blok = m[1];
  const vraagM = blok.match(/<button[^>]*class="faq-question"[^>]*>([\s\S]*?)<\/button>/i);
  const antwM = blok.match(/<div class="faq-answer">([\s\S]*?)$/i);
  if (!vraagM || !antwM) continue;
  items.push({ vraag: ontdoe(vraagM[1]), antwoord: ontdoe(antwM[1]) });
}

console.log('Zichtbare vragen: ' + items.length);
items.forEach((i, n) => console.log('  ' + (n + 1) + '. ' + i.vraag));

/* FAQPage-blok vinden */
const blokRe = /<script type="application\/ld\+json">\s*\{\s*"@context": "https:\/\/schema\.org",\s*"@type": "FAQPage",[\s\S]*?<\/script>/;
const gevonden = src.match(blokRe);
if (!gevonden) { console.error('Geen FAQPage-blok gevonden.'); process.exit(1); }

const nieuw = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: items.map((i) => ({
    '@type': 'Question',
    name: i.vraag,
    acceptedAnswer: { '@type': 'Answer', text: i.antwoord },
  })),
};

const nieuwBlok = '<script type="application/ld+json">' + eol +
  JSON.stringify(nieuw, null, 2).split('\n').join(eol) + eol +
  '</script>';

if (!SCHRIJF) {
  console.log('\n--- nieuw blok (proefdraai, niets geschreven) ---');
  console.log(nieuwBlok.slice(0, 900) + '\n...');
} else {
  fs.writeFileSync(FILE, src.replace(blokRe, nieuwBlok));
  console.log('\nFAQPage-schema bijgewerkt: ' + items.length + ' vragen.');
}
