#!/usr/bin/env node
/*
 * check-jsonld.js
 * Controleert de JSON-LD op de velden die Google en schema.org verwachten.
 * Faalt (exit 1) bij een fout.
 *
 * WAAROM
 * check-links.js kijkt alleen of een blok geldige JSON is. Dat een FAQPage
 * een vraag zonder antwoord heeft, een openingstijd "18.00" in plaats van
 * "18:00", een AggregateOffer met een lowPrice boven de highPrice, of een
 * Article zonder datum, ziet het niet. Google laat zo'n blok stil vallen.
 * Dit script is geen volledige validator; het toetst wat op deze site
 * voorkomt. Na een uitrol kun je een pagina nog los testen op
 * https://search.google.com/test/rich-results
 *
 * GEBRUIK
 *   node scripts/check-jsonld.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DAGEN = new Set(['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']);
const TIJD = /^([01]\d|2[0-3]):[0-5]\d$/;
const DATUM = /^\d{4}-\d{2}-\d{2}/;
const URL_RE = /^https:\/\/belastinghulpzaanstad\.nl\//;
/* Het bedrijfsblok is ProfessionalService + AccountingService; beide zijn een LocalBusiness. */
const BEDRIJF = new Set(['LocalBusiness', 'ProfessionalService', 'AccountingService']);
/* Elk @type moet een bestaand schema.org-type zijn; een tikfout laat Google het
   blok stil vallen. Deze lijst is op 23 oktober 2026 nagelopen tegen
   https://schema.org/version/latest/schemaorg-current-https-types.csv: alle
   typen die de site gebruikt, plus PropertyValue (KvK-nummer) en een paar die
   voor de hand liggen. Een nieuw type? Controleer het daar en zet het erbij. */
const TYPEN = new Set(['AboutPage', 'AccountingService', 'AdministrativeArea', 'AggregateOffer', 'Answer', 'Article',
  'BlogPosting', 'BreadcrumbList', 'City', 'CollectionPage', 'ContactPoint', 'FAQPage', 'HowTo', 'ImageObject', 'ItemList',
  'ListItem', 'LocalBusiness', 'Offer', 'OfferCatalog', 'OpeningHoursSpecification', 'Organization', 'Person',
  'PostalAddress', 'PriceSpecification', 'ProfessionalService', 'ProfilePage', 'PropertyValue', 'Question', 'Service',
  'SpeakableSpecification', 'WebApplication', 'WebPage', 'WebSite']);

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'intern') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}
const rel = (f) => path.relative(ROOT, f).split(path.sep).join('/');
const typen = (o) => [].concat(o && o['@type'] || []);
const tekstGevuld = (v) => typeof v === 'string' && v.trim().length > 0;

const fouten = [];
const telling = {};

function toets(o, f) {
  if (!o || typeof o !== 'object') return;
  if (Array.isArray(o)) { o.forEach((x) => toets(x, f)); return; }
  const t = typen(o);
  const fout = (m) => fouten.push(rel(f) + ': ' + (t.join('/') || 'object') + ': ' + m);
  t.forEach((x) => { telling[x] = (telling[x] || 0) + 1; if (!TYPEN.has(x)) fout('onbekend @type "' + x + '" (geen schema.org-type uit de lijst bovenin)'); });

  /* een verwijzing naar het bedrijfsblok (provider op een dienstpagina) heeft alleen @type, @id en name */
  const verwijzing = Object.keys(o).every((k) => ['@type', '@id', 'name'].includes(k));
  if (t.some((x) => BEDRIJF.has(x)) && !verwijzing) {
    if (!tekstGevuld(o.name)) fout('name ontbreekt');
    if (!o.address || !o.address.addressLocality || !o.address.addressCountry) fout('address mist plaats of land');
    if (!/^\+31\d{9}$/.test(o.telephone || '')) fout('telephone niet in de vorm +31...');
    if (!tekstGevuld(o.priceRange) || o.priceRange.length > 100) fout('priceRange ontbreekt of is te lang');
    [].concat(o.openingHoursSpecification || []).forEach((s) => {
      [].concat(s.dayOfWeek || []).forEach((d) => { if (!DAGEN.has(d)) fout('onbekende dag: ' + d); });
      if (!TIJD.test(s.opens || '') || !TIJD.test(s.closes || '')) fout('openingstijd niet in de vorm UU:MM');
    });
    [].concat(o.areaServed || []).forEach((a) => { if (!a['@type'] || !tekstGevuld(a.name)) fout('areaServed zonder type of naam'); });
  }
  if (t.includes('FAQPage')) {
    const vragen = o.mainEntity || [];
    if (!vragen.length) fout('geen vragen');
    vragen.forEach((q, i) => {
      if (!typen(q).includes('Question') || !tekstGevuld(q.name)) fout('vraag ' + (i + 1) + ' zonder tekst');
      if (!q.acceptedAnswer || !tekstGevuld(q.acceptedAnswer.text)) fout('vraag ' + (i + 1) + ' zonder antwoord');
    });
  }
  if (t.includes('BreadcrumbList')) {
    (o.itemListElement || []).forEach((it, i) => {
      if (it.position !== i + 1) fout('positie ' + it.position + ' op plek ' + (i + 1));
      if (!tekstGevuld(it.name) || !URL_RE.test(it.item || '')) fout('kruimel ' + (i + 1) + ' zonder naam of geldige url');
    });
  }
  if (t.includes('Article')) {
    if (!tekstGevuld(o.headline) || o.headline.length > 110) fout('headline ontbreekt of is langer dan 110 tekens');
    if (!DATUM.test(o.datePublished || '') || !DATUM.test(o.dateModified || '')) fout('datePublished of dateModified ontbreekt');
    if (o.datePublished && o.dateModified && o.dateModified < o.datePublished) fout('dateModified ligt voor datePublished');
    if (!o.author) fout('author ontbreekt');
  }
  if (t.includes('Offer')) {
    if (o.price !== undefined && !/^\d+(\.\d+)?$/.test(String(o.price))) fout('price is geen getal: ' + o.price);
    if (o.price !== undefined && o.priceCurrency !== 'EUR') fout('priceCurrency ontbreekt');
  }
  if (t.includes('AggregateOffer')) {
    const lo = Number(o.lowPrice), hi = Number(o.highPrice);
    if (isNaN(lo) || isNaN(hi) || lo > hi) fout('lowPrice/highPrice kloppen niet: ' + o.lowPrice + '-' + o.highPrice);
    if (o.priceCurrency !== 'EUR') fout('priceCurrency ontbreekt');
  }
  if (t.includes('Service') && !o.provider) fout('provider ontbreekt');

  for (const [k, v] of Object.entries(o)) {
    if (k === '@context') continue;
    if (v && typeof v === 'object') toets(v, f);
  }
}

/* ---------- eisen per pagina ----------
   - nergens Review of AggregateRating: er zijn nog geen echte reviews
   - elke indexeerbare pagina een BreadcrumbList, behalve de twee homepages
     (een kruimelpad van één stap zegt niets)
   - elke indexeerbare pagina het bedrijfsblok (#business)
   - artikelen: een Article met als auteur een Person met naam en url
   - dienstpagina's: een Service met minstens één Offer */
function knopen(o, acc) {
  if (!o || typeof o !== 'object') return acc;
  if (Array.isArray(o)) { o.forEach((x) => knopen(x, acc)); return acc; }
  acc.push(o);
  for (const v of Object.values(o)) if (v && typeof v === 'object') knopen(v, acc);
  return acc;
}
function toetsPagina(f, s, alle) {
  const r = rel(f);
  const fout = (m) => fouten.push(r + ': ' + m);
  const heeft = (type) => alle.some((n) => typen(n).includes(type));
  if (heeft('Review') || heeft('AggregateRating') || alle.some((n) => n.review || n.aggregateRating)) fout('Review of AggregateRating gevonden; er zijn nog geen echte reviews');
  const robots = (s.match(/<meta name="robots" content="([^"]*)"/) || [])[1] || '';
  if (/noindex/.test(robots) || !/<link rel="canonical"/.test(s)) return;
  if (r !== 'index.html' && r !== 'en/index.html' && !heeft('BreadcrumbList')) fout('BreadcrumbList ontbreekt');
  if (!alle.some((n) => n['@id'] === 'https://belastinghulpzaanstad.nl/#business' && n.address)) fout('bedrijfsblok (#business) ontbreekt');
  if (/^(en\/)?blog\/[^/]+\/index\.html$/.test(r)) {
    const a = alle.find((n) => typen(n).includes('Article'));
    if (!a) fout('artikel zonder Article');
    else if (!typen(a.author).includes('Person') || !tekstGevuld(a.author.name) || !URL_RE.test(a.author.url || '')) fout('Article zonder auteur (Person met naam en url)');
  }
  if (/^(en\/)?(diensten|services)\/[^/]+\/index\.html$/.test(r)) {
    const sv = alle.find((n) => typen(n).includes('Service'));
    if (!sv) fout('dienstpagina zonder Service');
    else if (![].concat(sv.offers || []).length) fout('Service zonder Offer');
  }
}

let blokken = 0, ongeldig = 0;
for (const f of walk(ROOT, [])) {
  const s = fs.readFileSync(f, 'utf8');
  const re = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/g;
  const alle = [];
  let m;
  while ((m = re.exec(s)) !== null) {
    blokken++;
    let j;
    try { j = JSON.parse(m[1]); } catch (e) { fouten.push(rel(f) + ': ongeldige JSON'); ongeldig++; continue; }
    if ([].concat(j).some((x) => x['@context'] !== 'https://schema.org')) fouten.push(rel(f) + ': blok zonder "@context": "https://schema.org"');
    toets(j, f);
    knopen(j, alle);
  }
  toetsPagina(f, s, alle);
}

console.log('JSON-LD: ' + blokken + ' blokken; ' + Object.entries(telling).sort((a, b) => b[1] - a[1]).map((x) => x[0] + ' ' + x[1]).join(', '));
if (fouten.length) {
  console.error('FAIL: ' + fouten.length + ' probleem(en):');
  fouten.slice(0, 40).forEach((e) => console.error('  - ' + e));
  process.exit(1);
}
console.log('OK: alle gecontroleerde velden kloppen.');
