#!/usr/bin/env node
/*
 * config-sync.js
 * Schrijft de prijzen en bedrijfsgegevens uit data/bedrijf.json in de HTML,
 * en waarschuwt voor elke placeholder die nog leeg is.
 *
 * WAAROM
 * De prijzen stonden los op de homepage, /tarieven/, de dienstpagina's en in
 * de JSON-LD. Een prijswijziging was zoeken en hopen dat je niets vergat, en
 * de JSON-LD liep al eens uit de pas (correctie: highPrice 69 terwijl de
 * partnerprijs 99 is). De site heeft geen build, dus maken we er geen sjabloon
 * van: dit script vervangt de tekst op gemarkeerde plekken, net als
 * set-fiscale-cijfers.js dat voor de fiscale bedragen doet.
 *
 * WAT HET RAAKT
 * 1. Elementen met data-prijs="sleutel" of data-prijs="sleutel.partner".
 *    Alleen het getal binnen het element wordt vervangen; de schrijfwijze
 *    eromheen (€59, &euro; 59, &euro;&nbsp;59) blijft staan.
 * 2. Blokken tussen <!-- cfg:naam --> en <!-- /cfg:naam -->. De inhoud wordt
 *    opnieuw opgebouwd uit de sjablonen hieronder. Een lege placeholder geeft
 *    geen leeg veld op de site: het zinsdeel wordt weggelaten.
 * 3. JSON-LD: een Offer met "@id" op #prijs-sleutel krijgt "price", een
 *    AggregateOffer op #prijzen-sleutel krijgt lowPrice/highPrice/offerCount,
 *    en elke "priceRange" wordt de laagste tot de hoogste prijs met
 *    in_prijsrange: true.
 *
 * GEBRUIK
 *   node scripts/config-sync.js            schrijft, en waarschuwt voor lege placeholders
 *   node scripts/config-sync.js --check    schrijft niets; exit 1 als de HTML afwijkt
 *
 * Lege placeholders zijn een waarschuwing, geen fout: de site klopt dan nog
 * steeds, er staat alleen minder op. Een placeholder in de verkeerde vorm
 * (een KvK-nummer van 7 cijfers) is wel een fout.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CONFIG = path.join(ROOT, 'data', 'bedrijf.json');
const CHECK = process.argv.includes('--check');
const cfg = JSON.parse(fs.readFileSync(CONFIG, 'utf8'));
const P = cfg.placeholders;
const B = cfg.bedrijf;

const fouten = [];
const waarschuwingen = [];

/* ---------- placeholders controleren ---------- */
function leeg(v) { return v === null || v === undefined || v === ''; }

if (leeg(P.KVK_NUMMER)) waarschuwingen.push('KVK_NUMMER is leeg: de footer toont nog geen KvK-nummer.');
else if (!/^\d{8}$/.test(P.KVK_NUMMER)) fouten.push('KVK_NUMMER moet 8 cijfers zijn, nu: ' + P.KVK_NUMMER);

if (leeg(P.BTW_ID) && P.KOR !== true) waarschuwingen.push('BTW_ID is leeg en KOR is niet true: de footer toont geen btw-id of KOR-vermelding.');
if (!leeg(P.BTW_ID) && !/^NL\d{9}B\d{2}$/.test(P.BTW_ID)) {
  fouten.push('BTW_ID moet de vorm NL123456789B01 hebben, nu: ' + P.BTW_ID +
    ' (het btw-identificatienummer, niet het omzetbelastingnummer)');
}
if (P.KOR !== null && P.KOR !== true && P.KOR !== false) fouten.push('KOR moet true, false of null zijn, nu: ' + P.KOR);
if (P.KOR === null) waarschuwingen.push('KOR is nog niet bepaald (true/false): btw-vermelding kan nog niet kloppen.');

if (leeg(P.BAV)) waarschuwingen.push('BAV is leeg: geen vermelding van een beroepsaansprakelijkheidsverzekering in de footer.');
if (!leeg(P.BAV) && leeg(P.BAV_EN)) waarschuwingen.push('BAV_EN is leeg: de Engelse footer toont de BAV-vermelding nog niet.');

if (leeg(P.FEE_BOX3)) {
  waarschuwingen.push('FEE_BOX3 is leeg: de box 3-pagina en /tarieven/ noemen nog geen percentage.');
} else if (typeof P.FEE_BOX3 !== 'number' || P.FEE_BOX3 <= 0 || P.FEE_BOX3 >= 100) {
  fouten.push('FEE_BOX3 moet een getal tussen 0 en 100 zijn (15 = 15%), nu: ' + P.FEE_BOX3);
} else if (leeg(P.FEE_BOX3_GRONDSLAG)) {
  waarschuwingen.push('FEE_BOX3_GRONDSLAG is leeg: de tekst zegt nu "van wat de opgaaf u oplevert".');
}
['FEE_BOX3_MIN', 'FEE_BOX3_MAX'].forEach(function (k) {
  if (!leeg(P[k]) && (typeof P[k] !== 'number' || P[k] < 0)) fouten.push(k + ' moet een bedrag in hele euro\'s zijn of null, nu: ' + P[k]);
});
if (!leeg(P.FEE_BOX3_MIN) && !leeg(P.FEE_BOX3_MAX) && P.FEE_BOX3_MIN > P.FEE_BOX3_MAX) fouten.push('FEE_BOX3_MIN is hoger dan FEE_BOX3_MAX.');

if (leeg(P.VAT_NOTE)) waarschuwingen.push('VAT_NOTE is leeg: bij de tarieven staat nog niet of de prijzen inclusief btw zijn.');
if (leeg(P.GOOGLE_REVIEW_URL)) waarschuwingen.push('GOOGLE_REVIEW_URL is leeg: /beoordeling/ toont nog geen knop naar Google.');
else if (P.GOOGLE_REVIEW_URL.indexOf('https://') !== 0) fouten.push('GOOGLE_REVIEW_URL moet met https:// beginnen, nu: ' + P.GOOGLE_REVIEW_URL);
if (leeg(P.ACHTERGROND_STAN)) waarschuwingen.push('ACHTERGROND_STAN is leeg: /over-ons/ toont nog geen achtergrond.');
if (leeg(P.EINDDATUM_CORRECTIE_2021)) waarschuwingen.push('EINDDATUM_CORRECTIE_2021 is leeg: de correctiepagina noemt geen einddatum voor 2021.');

const VANDAAG = new Date().toISOString().slice(0, 10);
const sk = cfg.startkorting || {};
const startkortingLoopt = sk.actief === true && (!sk.geldig_tot || VANDAAG <= sk.geldig_tot);
if (sk.actief === true && sk.geldig_tot && VANDAAG > sk.geldig_tot) {
  waarschuwingen.push('startkorting is verlopen sinds ' + sk.geldig_tot + ': zet actief op false en haal de teksten op de site weg.');
}

/* ---------- prijzen ---------- */
const prijzen = cfg.prijzen;
/* "aangifte" = de prijs, "aangifte.partner" = samen met de fiscaal partner,
   "aangifte.extra" = wat de partner erbij kost (partner min alleen). */
function prijs(sleutel) {
  const [k, sub] = sleutel.split('.');
  if (k === 'startkorting') return sk.bedrag;
  const p = prijzen[k];
  if (!p || k === '_doc') return undefined;
  if (sub === 'partner') return p.partner;
  if (sub === 'extra') return typeof p.partner === 'number' ? p.partner - p.bedrag : undefined;
  return p.bedrag;
}
const inRange = [];
for (const [k, p] of Object.entries(prijzen)) {
  if (k === '_doc' || !p.in_prijsrange) continue;
  [p.bedrag, p.partner].forEach(function (v) { if (typeof v === 'number') inRange.push(v); });
}
const PRICE_RANGE = '€' + Math.min.apply(null, inRange) + '–€' + Math.max.apply(null, inRange);

/* ---------- sjablonen voor de cfg-blokken ---------- */
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function euro(n) { return '&euro;' + n; }

function feeZin(taal) {
  const nl = taal === 'nl';
  if (leeg(P.FEE_BOX3)) {
    return nl
      ? '<strong>No cure no pay.</strong> U betaalt alleen als de Belastingdienst uw box 3-belasting verlaagt. Levert de opgaaf niets op, dan betaalt u niets. Hoeveel u betaalt, hoort u vooraf, en u tekent er zelf voor.'
      : '<strong>No cure, no pay.</strong> You only pay if the tax authority lowers your box 3 tax. If it yields nothing, you pay nothing. You hear the fee beforehand and sign for it yourself.';
  }
  const pct = String(P.FEE_BOX3).replace('.', nl ? ',' : '.') + '%';
  const grond = leeg(P.FEE_BOX3_GRONDSLAG)
    ? (nl ? 'van wat de opgaaf u oplevert' : 'of what the return yields for you')
    : esc(P.FEE_BOX3_GRONDSLAG);
  let grenzen = '';
  if (!leeg(P.FEE_BOX3_MIN) && !leeg(P.FEE_BOX3_MAX)) {
    grenzen = nl ? ', met een minimum van ' + euro(P.FEE_BOX3_MIN) + ' en een maximum van ' + euro(P.FEE_BOX3_MAX)
      : ', with a minimum of ' + euro(P.FEE_BOX3_MIN) + ' and a maximum of ' + euro(P.FEE_BOX3_MAX);
  } else if (!leeg(P.FEE_BOX3_MIN)) {
    grenzen = nl ? ', met een minimum van ' + euro(P.FEE_BOX3_MIN) : ', with a minimum of ' + euro(P.FEE_BOX3_MIN);
  } else if (!leeg(P.FEE_BOX3_MAX)) {
    grenzen = nl ? ', met een maximum van ' + euro(P.FEE_BOX3_MAX) : ', with a maximum of ' + euro(P.FEE_BOX3_MAX);
  }
  return nl
    ? '<strong>No cure no pay.</strong> U betaalt ' + pct + ' ' + grond + grenzen + '. U betaalt alleen als de Belastingdienst uw box 3-belasting verlaagt. Levert de opgaaf niets op, dan betaalt u niets.'
    : '<strong>No cure, no pay.</strong> You pay ' + pct + ' ' + grond + grenzen + '. You only pay if the tax authority lowers your box 3 tax. If it yields nothing, you pay nothing.';
}

function footerRegel(taal) {
  const nl = taal === 'nl';
  const delen = [esc(B.naam)];
  delen.push(nl ? 'gevestigd in ' + esc(B.vestigingsplaats) + ', gemeente ' + esc(B.gemeente)
    : 'based in ' + esc(B.vestigingsplaats) + ', ' + esc(B.gemeente) + ' municipality');
  delen.push('<a href="mailto:' + esc(B.email) + '" style="color:inherit;text-decoration:underline">' + esc(B.email) + '</a>');
  if (!leeg(P.KVK_NUMMER)) delen.push('KvK ' + esc(P.KVK_NUMMER));
  if (!leeg(P.BTW_ID)) delen.push((nl ? 'BTW-id ' : 'VAT ') + esc(P.BTW_ID));
  if (P.KOR === true) delen.push(nl ? 'kleineondernemersregeling: wij rekenen geen btw' : 'small business scheme (KOR): no VAT charged');
  /* De BAV-tekst is vrije tekst; die vertalen we niet zelf. */
  if (nl && !leeg(P.BAV)) delen.push(esc(P.BAV));
  if (!nl && !leeg(P.BAV_EN)) delen.push(esc(P.BAV_EN));
  delen.push(nl ? 'Bezoek uitsluitend op afspraak. Wij komen bij u thuis' : 'By appointment only. We come to your home');
  return '<span class="footer-gegevens" style="display:block;margin-bottom:6px;color:rgba(255,255,255,0.72);">' +
    delen.join(' &middot; ') + '</span>';
}

const SJABLONEN = {
  'footer-gegevens': function () { return footerRegel('nl'); },
  'footer-gegevens-en': function () { return footerRegel('en'); },
  'box3-tarief': function () { return feeZin('nl'); },
  'box3-tarief-en': function () { return feeZin('en'); },
  'btw-vermelding': function () {
    return leeg(P.VAT_NOTE) ? '' : '<p class="btw-vermelding" style="font-size:0.95rem;color:var(--clr-bark);margin:10px 0 0;line-height:1.6;">' + esc(P.VAT_NOTE) + '</p>';
  },
  'startkorting-tarieven': function () {
    if (!startkortingLoopt) return '';
    return '<p class="startkorting" style="font-size:1rem;color:var(--clr-deep);margin:14px 0 0;line-height:1.6;background:#FFF8E1;border:1px solid #F5B947;border-radius:10px;padding:12px 16px;">' +
      '<strong>Nieuw in 2026:</strong> bent u een nieuwe klant, dan krijgt u ' + euro(sk.bedrag) +
      ' korting op een aangifte of voorlopige teruggave. Dat gaat automatisch, u heeft geen code nodig.</p>';
  },
  'review-knop': function () {
    if (leeg(P.GOOGLE_REVIEW_URL)) {
      return '<p style="line-height:1.7;color:var(--clr-bark);margin:0;">Wilt u mij laten weten hoe het ging? Stuur een <a href="https://wa.me/31619711848" rel="nofollow" style="color:var(--clr-teal);font-weight:700;">WhatsApp</a> of een <a href="mailto:' + esc(B.email) + '" style="color:var(--clr-teal);font-weight:700;">e-mail</a>. Ik lees alles.</p>';
    }
    return '<a href="' + esc(P.GOOGLE_REVIEW_URL) + '" class="btn btn-primary" target="_blank" rel="noopener" style="display:inline-flex;min-height:48px;">Schrijf een review op Google &rarr;</a>';
  },
  'achtergrond-stan': function () {
    return leeg(P.ACHTERGROND_STAN) ? '' : '<p style="line-height:1.75;color:var(--clr-bark);font-size:1.02rem;margin-bottom:12px;">' + esc(P.ACHTERGROND_STAN) + '</p>';
  },
  'correctie-2021-einddatum': function () {
    return leeg(P.EINDDATUM_CORRECTIE_2021) ? '' : ' Voor 2021 kan dat tot en met ' + esc(P.EINDDATUM_CORRECTIE_2021) + '.';
  }
};

/* ---------- het LocalBusiness-blok ----------
   Elke pagina draagt hetzelfde blok met "@id": ".../#business". Het stond op
   98 pagina's als losse kopie, in vier varianten. Nu bouwen we het hier op. */
const BASIS_URL = 'https://belastinghulpzaanstad.nl';
function bedrijfsBlok() {
  const L = cfg.lokaal;
  const o = {
    '@context': 'https://schema.org',
    '@type': ['LocalBusiness', 'AccountingService'],
    '@id': BASIS_URL + '/#business',
    name: B.naam,
    url: BASIS_URL + '/',
    telephone: L.telefoon,
    email: B.email,
    image: L.afbeelding,
    address: { '@type': 'PostalAddress', addressLocality: L.adres.plaats, addressRegion: L.adres.regio, addressCountry: L.adres.land },
    priceRange: PRICE_RANGE,
    foundingDate: L.oprichtingsjaar,
    founder: { '@id': BASIS_URL + '/over-ons/#stan' },
    areaServed: L.werkgebied.map(function (n) { return { '@type': 'City', name: n }; }),
    serviceType: L.diensten,
    sameAs: L.sameAs,
    openingHoursSpecification: L.openingstijden.map(function (t) {
      return { '@type': 'OpeningHoursSpecification', dayOfWeek: t.dagen, opens: t.open, closes: t.dicht };
    })
  };
  if (!leeg(P.BTW_ID)) o.vatID = P.BTW_ID;
  if (!leeg(P.KVK_NUMMER)) o.identifier = { '@type': 'PropertyValue', propertyID: 'KvK', value: P.KVK_NUMMER };
  return '\n' + JSON.stringify(o, null, 2) + '\n';
}
const BEDRIJFSBLOK = bedrijfsBlok();

/* ---------- bestanden ---------- */
function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}
const rel = (f) => path.relative(ROOT, f).split(path.sep).join('/');

let geraakt = 0, prijsPlekken = 0, blokken = 0, ldPlekken = 0;
const afwijkend = [];

/* De inhoud van een plat JSON-object rond positie i: van de laatste { ervoor
   tot de eerste } erna. Offers in deze site zijn plat (geen geneste objecten). */
function objectRond(s, i) {
  const begin = s.lastIndexOf('{', i);
  const eind = s.indexOf('}', i);
  return [begin, eind + 1];
}
function zetVeld(obj, veld, waarde) {
  const re = new RegExp('("' + veld + '"\\s*:\\s*)"[^"]*"');
  return re.test(obj) ? obj.replace(re, '$1"' + waarde + '"') : obj;
}

for (const f of walk(ROOT, [])) {
  const voor = fs.readFileSync(f, 'utf8');
  let s = voor;

  /* 1. data-prijs. We onthouden welke oude prijs welke nieuwe werd: een
     FAQ-antwoord in de JSON-LD noemt dezelfde prijs, en die moet mee. */
  const oudNieuw = new Map();
  s = s.replace(/<([a-z][a-z0-9]*)(\s(?:[^>]*?\s)?data-prijs="([a-z_]+(?:\.partner|\.extra)?)"[^>]*)>([^<]*)<\/\1>/gi,
    function (heel, tag, attrs, sleutel, inhoud) {
      const v = prijs(sleutel);
      prijsPlekken++;
      if (typeof v !== 'number') { fouten.push(rel(f) + ': data-prijs="' + sleutel + '" heeft geen bedrag in data/bedrijf.json'); return heel; }
      if (!/\d/.test(inhoud)) { fouten.push(rel(f) + ': data-prijs="' + sleutel + '" bevat geen getal om te vervangen'); return heel; }
      const oud = inhoud.match(/\d+/)[0];
      if (oud !== String(v)) oudNieuw.set(oud, String(v));
      return '<' + tag + attrs + '>' + inhoud.replace(/\d+/, String(v)) + '</' + tag + '>';
    });

  /* 2. cfg-blokken */
  s = s.replace(/<!-- cfg:([a-z0-9-]+) -->([\s\S]*?)<!-- \/cfg:\1 -->/g, function (heel, naam) {
    blokken++;
    const sjabloon = SJABLONEN[naam];
    if (!sjabloon) { fouten.push(rel(f) + ': onbekend cfg-blok "' + naam + '"'); return heel; }
    return '<!-- cfg:' + naam + ' -->' + sjabloon() + '<!-- /cfg:' + naam + ' -->';
  });

  /* 3. JSON-LD */
  s = s.replace(/(<script type="application\/ld\+json">)([\s\S]*?)(<\/script>)/g, function (heel, open, body, sluit) {
    let b = body;
    /* het bedrijfsblok geheel opnieuw uit data/bedrijf.json */
    if (/"@id"\s*:\s*"https:\/\/belastinghulpzaanstad\.nl\/#business"/.test(b) && /"LocalBusiness"/.test(b)) {
      ldPlekken++;
      return open + BEDRIJFSBLOK + sluit;
    }
    /* FAQ-antwoorden: een gewijzigde prijs, in elke schrijfwijze die voorkomt */
    if (oudNieuw.size && /"FAQPage"/.test(b)) {
      for (const [oud, nieuw] of oudNieuw) {
        b = b.replace(new RegExp('(€\\s?|\\\\u20ac)' + oud + '(?!\\d)(?![.,]\\d)', 'g'), '$1' + nieuw)
          .replace(new RegExp('\\b' + oud + ' euro\\b', 'g'), nieuw + ' euro');
      }
    }
    b = b.replace(/("priceRange"\s*:\s*)"[^"]*"/g, function (m, kop) { ldPlekken++; return kop + '"' + PRICE_RANGE + '"'; });
    let i = 0, m;
    const idRe = /"@id"\s*:\s*"[^"]*#(prijs|prijzen)-([a-z_]+?)(-partner)?"/g;
    while ((m = idRe.exec(b)) !== null) {
      const [van, tot] = objectRond(b, m.index);
      let obj = b.slice(van, tot);
      const sleutel = m[2];
      const p = prijzen[sleutel];
      ldPlekken++;
      if (!p) { fouten.push(rel(f) + ': JSON-LD verwijst naar onbekende prijs "' + sleutel + '"'); continue; }
      if (m[1] === 'prijs') {
        const v = prijs(sleutel + (m[3] ? '.partner' : ''));
        if (typeof v !== 'number') { fouten.push(rel(f) + ': JSON-LD #prijs-' + sleutel + (m[3] || '') + ' heeft geen bedrag'); continue; }
        obj = zetVeld(obj, 'price', String(v));
      } else {
        obj = zetVeld(obj, 'lowPrice', String(p.bedrag));
        obj = zetVeld(obj, 'highPrice', String(typeof p.partner === 'number' ? p.partner : p.bedrag));
        obj = zetVeld(obj, 'offerCount', typeof p.partner === 'number' ? '2' : '1');
      }
      b = b.slice(0, van) + obj + b.slice(tot);
      idRe.lastIndex = van + obj.length;
      i++;
    }
    return open + b + sluit;
  });

  if (s !== voor) {
    geraakt++;
    afwijkend.push(rel(f));
    if (!CHECK) fs.writeFileSync(f, s);
  }
}

/* ---------- titles en meta: geen markers mogelijk, dus alleen controleren ----------
   Een title of description kan geen <span> bevatten. Na een prijswijziging
   blijft daar dus de oude prijs staan. Op de pagina's met prijzen moet elk
   bedrag tot €200 in de meta een prijs uit data/bedrijf.json zijn; hogere
   bedragen zijn hier fiscale bedragen of rekenvoorbeelden en doen niet mee. */
const bekendePrijzen = new Set([String(sk.bedrag)]);
for (const [k, p] of Object.entries(prijzen)) {
  if (k === '_doc') continue;
  ['', '.partner', '.extra'].forEach(function (sub) { const v = prijs(k + sub); if (typeof v === 'number') bekendePrijzen.add(String(v)); });
}
const PRIJSPAGINA = /^(index\.html|tarieven\/|senioren\/|diensten\/|en\/index\.html|en\/services\/|(en\/)?(zaandam|krommenie|assendelft|wormerveer|koog-aan-de-zaan|zaandijk|westzaan|wormerland|oostzaan)\/)/;
for (const f of walk(ROOT, [])) {
  const r = rel(f);
  if (!PRIJSPAGINA.test(r)) continue;
  const html = fs.readFileSync(f, 'utf8');
  const meta = [(html.match(/<title>([^<]*)<\/title>/) || [])[1] || ''];
  const re = /<meta (?:name|property)="(?:description|og:description|twitter:description|og:title|twitter:title|og:image:alt)" content="([^"]*)"/g;
  let m;
  while ((m = re.exec(html)) !== null) meta.push(m[1]);
  const gezien = new Set();
  meta.join(' ').replace(/€\s?(\d{2,3})(?!\d)(?![.,]\d)/g, function (heel, n) {
    if (Number(n) <= 200 && !bekendePrijzen.has(n) && !gezien.has(n)) {
      gezien.add(n);
      waarschuwingen.push(r + ': title of meta noemt €' + n + ', dat is geen prijs uit data/bedrijf.json. Pas de tekst met de hand aan.');
    }
  });
}

/* ---------- llms.txt: geen markers mogelijk, dus alleen controleren ---------- */
const llms = fs.readFileSync(path.join(ROOT, 'llms.txt'), 'utf8');
for (const [k, p] of Object.entries(prijzen)) {
  if (k === '_doc') continue;
  [p.bedrag, p.partner].forEach(function (v) {
    if (typeof v === 'number' && llms.indexOf('€' + v) === -1) {
      waarschuwingen.push('llms.txt noemt ' + k + ' (€' + v + ') niet; werk llms.txt met de hand bij.');
    }
  });
}

/* ---------- data/seizoen.json: teksten voor de seizoensbanner, alleen controleren ----------
   Geen markers mogelijk in JSON-tekst. Na een prijswijziging blijft daar dus de
   oude prijs staan; dit vangt elk bedrag tot €200 dat geen prijs meer is. Een
   bestaande prijs bij de verkeerde dienst ("voorlopige teruggave vanaf €49")
   ziet het niet: lees de teksten na bij elke prijswijziging. */
const seizoen = fs.readFileSync(path.join(ROOT, 'data', 'seizoen.json'), 'utf8').replace(/&euro;\s?/g, '€');
const gezienSeizoen = new Set();
seizoen.replace(/€\s?(\d{2,3})(?!\d)(?![.,]\d)/g, function (heel, n) {
  if (Number(n) <= 200 && !bekendePrijzen.has(n) && !gezienSeizoen.has(n)) {
    gezienSeizoen.add(n);
    waarschuwingen.push('data/seizoen.json noemt €' + n + ', dat is geen prijs uit data/bedrijf.json. Pas de tekst met de hand aan.');
  }
});

/* ---------- uitkomst ---------- */
console.log('config-sync: ' + prijsPlekken + ' prijsplekken, ' + blokken + ' cfg-blokken, ' + ldPlekken + ' JSON-LD-velden; priceRange ' + PRICE_RANGE);
if (waarschuwingen.length) {
  console.log('\nWAARSCHUWING: ' + waarschuwingen.length + ' open punt(en) in data/bedrijf.json:');
  waarschuwingen.forEach(function (w) { console.log('  ! ' + w); });
}
if (fouten.length) {
  console.error('\nFOUT:');
  fouten.forEach(function (e) { console.error('  - ' + e); });
  process.exit(1);
}
if (CHECK && geraakt) {
  console.error('\nFAIL: ' + geraakt + ' bestand(en) wijken af van data/bedrijf.json. Draai node scripts/config-sync.js.');
  afwijkend.slice(0, 20).forEach(function (r) { console.error('  - ' + r); });
  process.exit(1);
}
console.log('\n' + (CHECK ? 'OK: de HTML volgt data/bedrijf.json.' : (geraakt ? 'Bijgewerkt: ' + geraakt + ' bestand(en).' : 'Niets te wijzigen.')));
