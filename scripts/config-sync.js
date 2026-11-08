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
 * 2b. Jaartallen en einddatums uit data/datums.json: elementen met
 *    data-jaar="sleutel", titles en meta met data-tpl="sjabloon", en de
 *    seizoensbanners en de startkorting, die zichzelf in de browser op de
 *    juiste dag tonen of verbergen (data-van/data-tot).
 * 3. JSON-LD: een Offer met "@id" op #prijs-sleutel krijgt "price", een
 *    AggregateOffer op #prijzen-sleutel krijgt lowPrice/highPrice/offerCount,
 *    en elke "priceRange" wordt de laagste tot de hoogste prijs met
 *    in_prijsrange: true. Het bedrijfsblok (#business) wordt helemaal opnieuw
 *    opgebouwd; het Organization-blok (#organization) krijgt e-mail, telefoon
 *    en sameAs; een Offer op #tarief-box3 krijgt de tekst van het box 3-tarief.
 *
 * GEBRUIK
 *   node scripts/config-sync.js            schrijft, en waarschuwt voor lege placeholders
 *   node scripts/config-sync.js --check    schrijft niets; exit 1 als de HTML afwijkt
 *   --datum=2027-01-01                     bouwt alsof het die dag is (jaarwissel vooraf bekijken)
 *
 * Lege placeholders zijn een waarschuwing, geen fout: de site klopt dan nog
 * steeds, er staat alleen minder op. Een placeholder in de verkeerde vorm
 * (een KvK-nummer van 7 cijfers) is wel een fout.
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

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
if (leeg(P.GOOGLE_REVIEWS_URL)) waarschuwingen.push('GOOGLE_REVIEWS_URL is leeg: de homepages tonen nog geen blok "Ervaringen". Pas invullen als er echte reviews zijn.');
else if (P.GOOGLE_REVIEWS_URL.indexOf('https://') !== 0) fouten.push('GOOGLE_REVIEWS_URL moet met https:// beginnen, nu: ' + P.GOOGLE_REVIEWS_URL);
else if (P.GOOGLE_REVIEW_URL.indexOf('https://') !== 0) fouten.push('GOOGLE_REVIEW_URL moet met https:// beginnen, nu: ' + P.GOOGLE_REVIEW_URL);
if (leeg(P.ACHTERGROND_STAN)) waarschuwingen.push('ACHTERGROND_STAN is leeg: /over-ons/ toont nog geen achtergrond.');
if (!leeg(P.ACHTERGROND_STAN) && leeg(P.ACHTERGROND_STAN_EN)) waarschuwingen.push('ACHTERGROND_STAN_EN is leeg: /en/about-us/ toont de achtergrond nog niet.');
if (!leeg(P.FEE_BOX3) && leeg(P.FEE_BOX3_GRONDSLAG_EN)) waarschuwingen.push('FEE_BOX3_GRONDSLAG_EN is leeg: de Engelse box 3-pagina gebruikt een algemene formulering.');
if (leeg(P.EINDDATUM_CORRECTIE_2021)) waarschuwingen.push('EINDDATUM_CORRECTIE_2021 is leeg: de correctiepagina noemt geen einddatum voor 2021.');

/* ---------- datums: data/datums.json ----------
   De bouwdatum is vandaag in Nederland. Met --datum=JJJJ-MM-DD bouwt u de site
   alsof het die dag is, om een jaarwissel vooraf te bekijken. */
const DATUMS = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'datums.json'), 'utf8'));
const datumArg = (process.argv.find(function (a) { return a.indexOf('--datum=') === 0; }) || '').slice(8);
if (datumArg && !/^\d{4}-\d{2}-\d{2}$/.test(datumArg)) { console.error('--datum moet JJJJ-MM-DD zijn'); process.exit(1); }
const VANDAAG = datumArg || new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Amsterdam' }).format(new Date());
const PERIODE = DATUMS.perioden.filter(function (p) { return p.vanaf <= VANDAAG; }).pop();
if (!PERIODE) { console.error('data/datums.json: geen periode voor ' + VANDAAG); process.exit(1); }

/* "2027-01-01" -> "2027-01-01T00:00+01:00": middernacht in Nederland, zomer- of wintertijd */
function nlMiddernacht(datum) {
  const uur = Number(new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Amsterdam', hour: '2-digit', hourCycle: 'h23' })
    .format(new Date(datum + 'T00:00:00Z')));
  return datum + 'T00:00+0' + uur + ':00';
}
/* Toont of verbergt in de browser elk element met data-van/data-tot, ook als de
   site op die dag niet opnieuw gebouwd is. Staat direct na de elementen. */
const VERBERGER = '<script>(function(){var n=Date.now();[].forEach.call(document.querySelectorAll(\'[data-van],[data-tot]\'),function(e){var v=e.getAttribute(\'data-van\'),t=e.getAttribute(\'data-tot\');e.hidden=!!(v&&n<Date.parse(v))||!!(t&&n>=Date.parse(t));});})();</script>';
/* Een element dat alleen van..tot zichtbaar is. Al voorbij op de bouwdatum: weg.
   Nog niet begonnen: wel in de HTML, maar hidden tot de browser het toont. */
function tijdelijk(van, tot, html) {
  if (tot && VANDAAG >= tot) return '';
  const nog = van && VANDAAG < van;
  return '<div' + (van ? ' data-van="' + nlMiddernacht(van) + '"' : '') + (tot ? ' data-tot="' + nlMiddernacht(tot) + '"' : '') +
    (nog ? ' hidden' : '') + '>' + html + '</div>';
}
function dagErna(datum) {
  const d = new Date(datum + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}
const MAANDEN = { nl: ['januari', 'februari', 'maart', 'april', 'mei', 'juni', 'juli', 'augustus', 'september', 'oktober', 'november', 'december'],
  en: ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'] };
function datumTekst(datum, taal) {
  const [j, m, d] = datum.split('-').map(Number);
  return d + ' ' + MAANDEN[taal][m - 1] + ' ' + j;
}

/* Alle banners die nog komen of nu lopen, elk met hun eigen van/tot. Een banner
   zonder tekst voor deze soort (nl, nl_box3, en) slaat die pagina over. */
function banners(soort) {
  const html = DATUMS.banners.map(function (b) {
    const t = b[soort];
    if (!t) return '';
    return tijdelijk(b.van, b.tot, '<div class="dl-banner" style="max-width:860px;margin:0 auto 22px;background:#FFF8E1;border:2px solid #F5B947;border-radius:14px;padding:12px 18px;display:flex;flex-wrap:wrap;gap:4px 14px;align-items:center;">' +
      '<span style="color:var(--clr-deep);font-weight:700;line-height:1.5;">' + esc(t.tekst) + '</span>' +
      '<a href="' + esc(t.link) + '" style="color:var(--clr-teal);font-weight:700;text-decoration:underline;display:inline-flex;align-items:center;min-height:44px;">' + esc(t.linktekst) + ' &rarr;</a></div>');
  }).join('');
  return html ? html + VERBERGER : '';
}

const sk = cfg.startkorting || {};
const startkortingLoopt = sk.actief === true && (!sk.geldig_tot || VANDAAG <= sk.geldig_tot);
/* tot = de eerste dag zonder korting */
const SK_TOT = sk.geldig_tot ? dagErna(sk.geldig_tot) : null;
if (sk.actief === true && sk.geldig_tot && VANDAAG > sk.geldig_tot) {
  waarschuwingen.push('startkorting is verlopen sinds ' + sk.geldig_tot + ': de teksten zijn verborgen. Verlengen? Zet een nieuwe geldig_tot in data/bedrijf.json.');
}

/* De jaartallen die op de bouwdatum gelden (data-jaar="sleutel" en {sleutel} in data-tpl) */
const JAREN = Object.assign({}, PERIODE, {
  correctie_einddatum: '31 december ' + PERIODE.jaar,
  correctie_einddatum_en: '31 December ' + PERIODE.jaar,
  startkorting_tot: sk.geldig_tot ? datumTekst(sk.geldig_tot, 'nl') : '',
  startkorting_tot_en: sk.geldig_tot ? datumTekst(sk.geldig_tot, 'en') : ''
});
delete JAREN.vanaf;

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

/* ---------- aanvragen: data/aanvraag.json (formulieren, herinneringslijst) ---------- */
const AANVRAAG = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'aanvraag.json'), 'utf8'));
const RONDES = (AANVRAAG.herinnering && AANVRAAG.herinnering.rondes) || [];
if (!RONDES.length) fouten.push('data/aanvraag.json: herinnering.rondes is leeg');

/* ---------- sjablonen voor de cfg-blokken ---------- */
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function euro(n) { return '&euro;' + n; }
/* HTML uit een sjabloon als platte tekst voor een JSON-string in de JSON-LD */
function jsonTekst(html) {
  return html.replace(/<[^>]+>/g, '').replace(/&euro;/g, '€').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
    .replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function feeZin(taal) {
  const nl = taal === 'nl';
  if (leeg(P.FEE_BOX3)) {
    return nl
      ? '<strong>No cure no pay.</strong> U betaalt alleen als de Belastingdienst uw box 3-belasting verlaagt. Levert de opgaaf niets op, dan betaalt u niets. Hoeveel u betaalt, hoort u vooraf, en u tekent er zelf voor.'
      : '<strong>No cure, no pay.</strong> You only pay if the tax authority lowers your box 3 tax. If it yields nothing, you pay nothing. You hear the fee beforehand and sign for it yourself.';
  }
  const pct = String(P.FEE_BOX3).replace('.', nl ? ',' : '.') + '%';
  const eigen = nl ? P.FEE_BOX3_GRONDSLAG : P.FEE_BOX3_GRONDSLAG_EN;
  const grond = leeg(eigen)
    ? (nl ? 'van wat de opgaaf u oplevert' : 'of what the return yields for you')
    : esc(eigen);
  let grenzen = '';
  /* Het maximum geldt voor alle jaren samen (2021-2024), niet per jaar. */
  const alle = nl ? ' voor alle jaren samen' : ' for all years together';
  if (!leeg(P.FEE_BOX3_MIN) && !leeg(P.FEE_BOX3_MAX)) {
    grenzen = nl ? ', met een minimum van ' + euro(P.FEE_BOX3_MIN) + ' en een maximum van ' + euro(P.FEE_BOX3_MAX) + alle
      : ', with a minimum of ' + euro(P.FEE_BOX3_MIN) + ' and a maximum of ' + euro(P.FEE_BOX3_MAX) + alle;
  } else if (!leeg(P.FEE_BOX3_MIN)) {
    grenzen = nl ? ', met een minimum van ' + euro(P.FEE_BOX3_MIN) : ', with a minimum of ' + euro(P.FEE_BOX3_MIN);
  } else if (!leeg(P.FEE_BOX3_MAX)) {
    grenzen = nl ? ', met een maximum van ' + euro(P.FEE_BOX3_MAX) + alle : ', with a maximum of ' + euro(P.FEE_BOX3_MAX) + alle;
  }
  return nl
    ? '<strong>No cure no pay.</strong> U betaalt ' + pct + ' ' + grond + grenzen + '. U betaalt alleen als de Belastingdienst uw box 3-belasting verlaagt, en pas na die beslissing; krijgt u geld terug, dan pas als het op uw rekening staat. Levert de opgaaf niets op, dan betaalt u niets.'
    : '<strong>No cure, no pay.</strong> You pay ' + pct + ' ' + grond + grenzen + '. You only pay if the tax authority lowers your box 3 tax, and only after that decision; if you get money back, only once it is in your account. If it yields nothing, you pay nothing.';
}

function feeKort(taal) {
  const nl = taal === 'nl';
  if (leeg(P.FEE_BOX3)) return nl ? 'Hoeveel u betaalt, hoort u vooraf.' : 'You hear the fee beforehand.';
  /* zelfde opbouw als feeZin, zonder de vaste zinnen eromheen */
  const zin = feeZin(taal).replace(/^<strong>[^<]*<\/strong> /, '');
  return zin.slice(0, zin.indexOf('. ') + 1);
}

function footerRegel(taal) {
  const nl = taal === 'nl';
  const delen = [esc(B.naam)];
  delen.push(nl ? 'gevestigd in ' + esc(B.vestigingsplaats) + ', gemeente ' + esc(B.gemeente)
    : 'based in ' + esc(B.vestigingsplaats) + ', ' + esc(B.gemeente) + ' municipality');
  delen.push('<a href="mailto:' + esc(B.email) + '" style="color:inherit;text-decoration:underline">' + esc(B.email) + '</a>');
  if (!leeg(P.KVK_NUMMER)) delen.push('KvK: ' + esc(P.KVK_NUMMER));
  if (!leeg(P.BTW_ID)) delen.push((nl ? 'btw: ' : 'VAT: ') + esc(P.BTW_ID));
  if (P.KOR === true) delen.push(nl ? 'kleineondernemersregeling: wij rekenen geen btw' : 'small business scheme (KOR): no VAT charged');
  /* De afspraakregel apart en met punt: anders loopt hij door in de regel met het © eronder */
  return '<span class="footer-gegevens" style="display:block;margin-bottom:6px;color:rgba(255,255,255,0.72);">' +
    delen.join(' &middot; ') + '</span>' +
    '<span class="footer-afspraak" style="display:block;margin-bottom:14px;color:rgba(255,255,255,0.72);">' +
    (nl ? 'Bezoek uitsluitend op afspraak. Wij komen bij u thuis.' : 'By appointment only. We come to your home.') + '</span>';
}

function ervaringen(taal) {
  if (leeg(P.GOOGLE_REVIEWS_URL)) return '';
  const nl = taal === 'nl';
  return '<section id="ervaringen-google" style="padding:56px 0;"><div class="container" style="max-width:860px;">' +
    '<h2 style="font-family:var(--font-display);font-size:1.6rem;color:var(--clr-deep);margin:0 0 12px;">' + (nl ? 'Ervaringen van klanten' : 'What clients say') + '</h2>' +
    '<p style="line-height:1.7;color:var(--clr-bark);font-size:1.05rem;margin:0 0 8px;">' +
    (nl ? 'Wat klanten van Belastinghulp Zaanstad vinden, leest u op Google. Daar staan alleen echte reviews, en wij kunnen ze niet aanpassen.'
      : 'You can read what clients think of Belastinghulp Zaanstad on Google. Only genuine reviews appear there, and we cannot edit them.') + '</p>' +
    '<a href="' + esc(P.GOOGLE_REVIEWS_URL) + '" class="tekstlink" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;min-height:48px;font-size:1.05rem;">' +
    (nl ? 'Lees de reviews op Google' : 'Read the reviews on Google') + ' &rarr;</a></div></section>';
}

const SJABLONEN = {
  'footer-gegevens': function () { return footerRegel('nl'); },
  'footer-gegevens-en': function () { return footerRegel('en'); },
  'box3-tarief': function () { return feeZin('nl'); },
  'box3-tarief-en': function () { return feeZin('en'); },
  /* korte vorm voor het FAQ-antwoord en de tarieventabel */
  'box3-tarief-kort': function () { return feeKort('nl'); },
  'box3-tarief-kort-en': function () { return feeKort('en'); },
  'box3-tarief-cel': function () {
    if (leeg(P.FEE_BOX3)) return 'no cure no pay';
    return String(P.FEE_BOX3).replace('.', ',') + '%<br><span style="font-size:0.8rem;font-weight:600;color:var(--clr-bark);">no cure no pay' +
      (leeg(P.FEE_BOX3_MAX) ? '' : ', max. ' + euro(P.FEE_BOX3_MAX)) + '</span>';
  },
  /* kort, voor de dienstentegel op de homepage en de plaatspagina's */
  'box3-tarief-tegel': function () {
    if (leeg(P.FEE_BOX3)) return 'check gratis &middot; daarna no cure no pay';
    return 'check gratis &middot; daarna ' + String(P.FEE_BOX3).replace('.', ',') + '%' + (leeg(P.FEE_BOX3_MAX) ? '' : ', max. ' + euro(P.FEE_BOX3_MAX));
  },
  'btw-vermelding': function () {
    return leeg(P.VAT_NOTE) ? '' : '<p class="btw-vermelding" style="font-size:0.95rem;color:var(--clr-bark);margin:10px 0 0;line-height:1.6;">' + esc(P.VAT_NOTE) + '</p>';
  },
  /* De startkorting verdwijnt in de browser vanzelf na geldig_tot, en bij de eerstvolgende build ook uit de HTML */
  'startkorting-tarieven': function () {
    if (!startkortingLoopt) return '';
    return tijdelijk(null, SK_TOT, '<p class="startkorting" style="font-size:1rem;color:var(--clr-deep);margin:14px 0 0;line-height:1.6;background:#FFF8E1;border:1px solid #F5B947;border-radius:10px;padding:12px 16px;">' +
      '<strong>Startkorting:</strong> bent u een nieuwe klant, dan krijgt u ' + euro(sk.bedrag) +
      ' korting op een aangifte of voorlopige teruggave, tot en met ' + datumTekst(sk.geldig_tot, 'nl') + '. Dat gaat automatisch, u heeft geen code nodig.</p>') + VERBERGER;
  },
  /* korte versie voor het slot van de plaatspagina's */
  'startkorting-kort': function () {
    if (!startkortingLoopt) return '';
    return tijdelijk(null, SK_TOT, '<p class="slot-actie"><strong>Startkorting:</strong> bent u een nieuwe klant, dan krijgt u ' + euro(sk.bedrag) +
      ' korting op een aangifte of voorlopige teruggave, tot en met ' + datumTekst(sk.geldig_tot, 'nl') + ', automatisch en zonder code. Wij plaatsen geen verzonnen reviews; <a href="/over-ons/">lees waarom</a>.</p>') + VERBERGER;
  },
  /* De seizoensbanner bovenaan: per periode een andere tekst uit data/datums.json */
  'seizoensbanner': function () { return banners('nl'); },
  'seizoensbanner-box3': function () { return banners('nl_box3'); },
  'seizoensbanner-en': function () { return banners('en'); },
  /* het script dat data-van/data-tot uitvoert, voor elementen buiten een cfg-blok */
  'verberger': function () { return VERBERGER; },
  'review-knop': function () {
    if (leeg(P.GOOGLE_REVIEW_URL)) {
      return '<p style="line-height:1.7;color:var(--clr-bark);margin:0;">Wilt u ons laten weten hoe het ging? Stuur een <a href="https://wa.me/31619711848" rel="nofollow" style="color:var(--clr-teal);font-weight:700;">WhatsApp</a> of een <a href="mailto:' + esc(B.email) + '" style="color:var(--clr-teal);font-weight:700;">e-mail</a>. Wij lezen alles.</p>';
    }
    /* een tekstlink, geen knop: knoppen zijn alleen "Bel of app" en "Bel mij terug" (check-knoppen.js) */
    return '<a href="' + esc(P.GOOGLE_REVIEW_URL) + '" class="tekstlink" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;min-height:48px;font-size:1.05rem;">Schrijf een review op Google &rarr;</a>';
  },
  /* Ervaringen op de homepages: alleen een link naar de echte reviews op Google, geen
     citaten of sterren op de site zelf. Leeg tot GOOGLE_REVIEWS_URL is ingevuld. */
  'ervaringen': function () { return ervaringen('nl'); },
  'ervaringen-en': function () { return ervaringen('en'); },
  /* /review/: kort adres voor de WhatsApp-tekst na een klus. Gaat naar Google
     zodra GOOGLE_REVIEW_URL er is, en tot die tijd naar /beoordeling/. */
  'review-doorsturen': function () {
    var doel = leeg(P.GOOGLE_REVIEW_URL) ? 'https://belastinghulpzaanstad.nl/beoordeling/' : P.GOOGLE_REVIEW_URL;
    return '<meta http-equiv="refresh" content="0; url=' + esc(doel) + '"><script>window.location.replace(' + JSON.stringify(doel) + ');</script>';
  },
  'review-doorsturen-link': function () {
    var doel = leeg(P.GOOGLE_REVIEW_URL) ? 'https://belastinghulpzaanstad.nl/beoordeling/' : P.GOOGLE_REVIEW_URL;
    return '<a href="' + esc(doel) + '">Verder naar de reviewpagina &rarr;</a>';
  },
  'achtergrond-stan': function () {
    return leeg(P.ACHTERGROND_STAN) ? '' : '<p style="line-height:1.75;color:var(--clr-bark);font-size:1.02rem;margin-bottom:12px;">' + esc(P.ACHTERGROND_STAN) + '</p>';
  },
  'achtergrond-stan-en': function () {
    return leeg(P.ACHTERGROND_STAN_EN) ? '' : '<p style="line-height:1.75;color:var(--clr-bark);font-size:1.02rem;margin-bottom:12px;">' + esc(P.ACHTERGROND_STAN_EN) + '</p>';
  },
  'correctie-2021-einddatum': function () {
    return leeg(P.EINDDATUM_CORRECTIE_2021) ? '' : ' De uiterste datum is ' + esc(P.EINDDATUM_CORRECTIE_2021) + ': dan moet uw verzoek over 2021 bij de Belastingdienst binnen zijn. Wacht daarom niet tot de laatste week.';
  },
  /* Het aangiftejaar van de laatste herinneringsronde in data/aanvraag.json
   * ("Herinnering als de aangifte over 2026 opengaat"). Komt er een ronde
   * bij, dan schuift het jaartal op de pagina's vanzelf mee. */
  'herinnering-jaar': function () { return String(RONDES[RONDES.length - 1].aangiftejaar); },
  /* De bewaartermijn van aanvragen in het privacybeleid, uit dezelfde instelling als de app */
  'aanvraag-bewaartermijn': function () { return AANVRAAG.bewaren.aanvraag_maanden + ' maanden'; },
  'aanvraag-bewaartermijn-en': function () { return AANVRAAG.bewaren.aanvraag_maanden + ' months'; }
};

/* ---------- het bedrijfsblok ----------
   Elke pagina draagt hetzelfde blok met "@id": ".../#business". Het stond op
   98 pagina's als losse kopie, in vier varianten. Nu bouwen we het hier op.
   Type: ProfessionalService (een LocalBusiness), met AccountingService als
   specifiekere soort. Het adres heeft alleen plaats en land: wij werken aan
   huis en hebben geen bezoekadres. */
const BASIS_URL = 'https://belastinghulpzaanstad.nl';
function bedrijfsBlok() {
  const L = cfg.lokaal;
  const o = {
    '@context': 'https://schema.org',
    '@type': ['ProfessionalService', 'AccountingService'],
    '@id': BASIS_URL + '/#business',
    name: B.naam,
    url: BASIS_URL + '/',
    telephone: L.telefoon,
    email: B.email,
    image: L.afbeelding,
    address: { '@type': 'PostalAddress', addressLocality: L.adres.plaats, addressCountry: L.adres.land },
    priceRange: PRICE_RANGE,
    foundingDate: L.oprichtingsjaar,
    founder: { '@id': BASIS_URL + '/over-ons/#stan' },
    areaServed: L.werkgebied.map(function (n) { return { '@type': 'City', name: n }; }),
    /* knowsAbout en niet serviceType: dat veld bestaat niet op LocalBusiness (Schema Markup Validator). */
    knowsAbout: L.diensten,
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
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'intern') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}
const rel = (f) => path.relative(ROOT, f).split(path.sep).join('/');

let geraakt = 0, prijsPlekken = 0, blokken = 0, ldPlekken = 0;
/* pagina's waar een FAQ-item wegviel: het FAQPage-schema moet opnieuw */
const faqHerbouw = new Set();
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

  /* 1a. tijdelijke stukken. In de browser doet data-van/data-tot het werk (VERBERGER);
     bij een build na de datum gaat het stuk ook uit de HTML.
     <!-- tot:2027-01-01 -->...<!-- /tot -->           weg vanaf die dag
     <!-- van:2027-01-01 --><el data-van=".." hidden> zichtbaar vanaf die dag
     <!-- actie:startkorting -->...<!-- /actie -->    weg na startkorting.geldig_tot */
  s = s.replace(/<!-- tot:(\d{4}-\d{2}-\d{2}) -->[\s\S]*?<!-- \/tot -->/g, function (heel, tot) {
    if (VANDAAG < tot) return heel;
    if (/"FAQPage"/.test(voor)) faqHerbouw.add(f);
    return '';
  });
  s = s.replace(/<!-- actie:startkorting -->([\s\S]*?)<!-- \/actie -->/g, function (heel, x) {
    if (!startkortingLoopt) { if (/"FAQPage"/.test(voor)) faqHerbouw.add(f); return ''; }
    if (!/data-tot="/.test(x)) fouten.push(rel(f) + ': actie:startkorting zonder data-tot');
    return '<!-- actie:startkorting -->' + x.replace(/data-tot="[^"]*"/g, 'data-tot="' + nlMiddernacht(SK_TOT) + '"') + '<!-- /actie -->';
  });
  s = s.replace(/<!-- van:(\d{4}-\d{2}-\d{2}) -->(\s*<[a-z0-9]+)([^>]*)>/g, function (heel, van, tag, attrs) {
    return '<!-- van:' + van + ' -->' + tag + attrs.replace(/\shidden(?=\s|$)/, '') + (VANDAAG < van ? ' hidden' : '') + '>';
  });

  /* 1b. jaartallen: data-jaar="sleutel" krijgt de waarde uit de periode in data/datums.json */
  s = s.replace(/(<span\s[^>]*?data-jaar="([a-z0-9_]+)"[^>]*>)([^<]*)(<\/span>)/g, function (heel, open, sleutel, inhoud, sluit) {
    if (!(sleutel in JAREN)) { fouten.push(rel(f) + ': data-jaar="' + sleutel + '" staat niet in data/datums.json'); return heel; }
    return open + JAREN[sleutel] + sluit;
  });
  /* 1b2. vaste teksten uit data/bedrijf.json (de reactietijd), in de taal van de pagina */
  s = s.replace(/(<span\s[^>]*?data-tekst="([a-z_]+)"[^>]*>)([^<]*)(<\/span>)/g, function (heel, open, sleutel, inhoud, sluit) {
    const R = cfg.reactietijd || {};
    const taal = /^en\//.test(rel(f)) ? 'en' : 'nl';
    const k = sleutel === 'reactietijd' ? taal : sleutel === 'reactietijd_kort' ? taal + '_kort' : null;
    if (!k || leeg(R[k])) { fouten.push(rel(f) + ': data-tekst="' + sleutel + '" staat niet in data/bedrijf.json (reactietijd)'); return heel; }
    return open + R[k] + sluit;
  });
  /* andere reactietijden dan de afgesproken: alleen waarschuwen (de spoedaangifte binnen 24 uur is een dienst, geen reactietijd) */
  const tekstAlleen = s.replace(/<script[\s\S]*?<\/script>|<!--[\s\S]*?-->|<[^>]+>/g, ' ');
  tekstAlleen.replace(/[^.!?\n]{0,80}\b(binnen 24 uur|binnen een dag|24u|within 24 hours|24h)\b[^.!?\n]{0,60}/gi, function (zin, x, i) {
    if (/spoed|rush|urgent/i.test(tekstAlleen.slice(Math.max(0, i - 150), i + zin.length))) return zin;
    waarschuwingen.push(rel(f) + ': andere reactietijd dan "' + ((cfg.reactietijd || {}).nl || '') + '": "' + zin.trim().slice(0, 90) + '"');
    return zin;
  });

  /* 1c. title en meta: een title of content="" kan geen <span> bevatten. Daarom staat
     het sjabloon in een commentaar direct ervoor, met {jaartal} en {prijs:sleutel}:
       <!-- tpl: Box 3 over {box3_van}–{box3_tot} -->
       <!-- tpl: tekst nu || vanaf 2027-01-01: tekst vanaf die dag --> */
  s = s.replace(/(<!-- tpl: (.*?)(?: \|\| vanaf (\d{4}-\d{2}-\d{2}): (.*?))? -->\s*)(<title>[^<]*<\/title>|<meta [^>]*?content="[^"]*"[^>]*>)/g, function (heel, kop, tpl, tot, daarna, tag) {
    const tekst = (tot && VANDAAG >= tot ? daarna : tpl).replace(/\{(prijs:)?([a-z0-9_.]+)\}/g, function (m, isPrijs, k) {
      const v = isPrijs ? prijs(k) : JAREN[k];
      if (v === undefined || v === null || v === '') { fouten.push(rel(f) + ': tpl kent {' + (isPrijs || '') + k + '} niet'); return m; }
      return String(v);
    });
    if (/"/.test(tekst)) fouten.push(rel(f) + ': tpl bevat een aanhalingsteken');
    return kop + (tag.indexOf('<title>') === 0 ? '<title>' + tekst + '</title>' : tag.replace(/\scontent="[^"]*"/, ' content="' + tekst + '"'));
  });

  /* 2. cfg-blokken */
  s = s.replace(/<!-- cfg:([a-z0-9-]+) -->([\s\S]*?)<!-- \/cfg:\1 -->/g, function (heel, naam) {
    blokken++;
    const sjabloon = SJABLONEN[naam];
    if (!sjabloon) { fouten.push(rel(f) + ': onbekend cfg-blok "' + naam + '"'); return heel; }
    return '<!-- cfg:' + naam + ' -->' + sjabloon() + '<!-- /cfg:' + naam + ' -->';
  });

  /* 2c. het verbergscript werkt alleen op wat er al staat: dus na het laatste tijdelijke stuk */
  const laatsteTijd = Math.max(s.lastIndexOf('data-tot="'), s.lastIndexOf('data-van="'));
  if (laatsteTijd > -1 && s.lastIndexOf('<!-- cfg:verberger -->') < laatsteTijd) {
    if (!/<\/body>/.test(s)) fouten.push(rel(f) + ': tijdelijke stukken maar geen </body> voor het verbergscript');
    s = s.replace(/\n?<\/body>/, '\n<!-- cfg:verberger -->' + VERBERGER + '<!-- /cfg:verberger -->\n</body>');
  }

  /* 3. JSON-LD */
  s = s.replace(/(<script type="application\/ld\+json">)([\s\S]*?)(<\/script>)/g, function (heel, open, body, sluit) {
    let b = body;
    /* Het bedrijfsblok en het Organization-blok herkennen we aan hun eigen
       @id bovenaan. Een verwijzing ernaar (provider, worksFor, founder) staat
       ook in andere blokken; die blokken moeten blijven zoals ze zijn. */
    let top = null;
    try { top = JSON.parse(b); } catch (e) { /* check-links.js meldt ongeldige JSON */ }
    if (top && !Array.isArray(top) && top['@id'] === BASIS_URL + '/#business') {
      ldPlekken++;
      return open + BEDRIJFSBLOK + sluit;
    }
    if (top && !Array.isArray(top) && top['@id'] === BASIS_URL + '/#organization') {
      ldPlekken++;
      top.email = B.email;
      top.telephone = cfg.lokaal.telefoon;
      top.sameAs = cfg.lokaal.sameAs;
      return open + '\n' + JSON.stringify(top, null, 2) + '\n' + sluit;
    }
    /* Het box 3-tarief als Offer (no cure no pay) op de box 3-pagina's:
       de omschrijving komt uit dezelfde placeholders als de zichtbare tekst. */
    b = b.replace(/\{[^{}]*"@id"\s*:\s*"[^"]*#tarief-box3"[^{}]*\}/g, function (obj) {
      ldPlekken++;
      return zetVeld(obj, 'description', jsonTekst(feeZin(/\/en\//.test(f.split(path.sep).join('/')) ? 'en' : 'nl')));
    });
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

/* ---------- FAQ-schema waar een cfg-blok in een zichtbaar antwoord staat ----------
   Het FAQPage-schema moet gelijk zijn aan de zichtbare FAQ. Staat er een cfg-blok of
   een data-jaar in een antwoord (het box 3-tarief op de box 3-pagina), dan verandert die tekst met de
   config. faq-sync.js zet het schema dan opnieuw. Niet in --check: dan schrijven we niets. */
if (!CHECK) {
  for (const f of walk(ROOT, [])) {
    const html = fs.readFileSync(f, 'utf8');
    const jaarInFaq = /"FAQPage"/.test(html) && /<button class="faq-question"(?:(?!<\/button>)[\s\S])*data-(?:jaar|tekst)=|<div class="faq-answer">(?:(?!<\/div>)[\s\S])*data-(?:jaar|tekst)=/.test(html);
    if (!faqHerbouw.has(f) && !jaarInFaq && !/<div class="faq-answer">(?:(?!<\/div>)[\s\S])*<!-- cfg:/.test(html)) continue;
    const r = spawnSync(process.execPath, [path.join(__dirname, 'faq-sync.js'), f, '--schrijf'], { encoding: 'utf8' });
    if (r.status !== 0) fouten.push(rel(f) + ': faq-sync faalde: ' + String(r.stderr || r.stdout).trim().split('\n').pop());
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

/* ---------- "incl. btw" in teksten zonder marker ----------
   Een title of description kan geen cfg-blok bevatten. De plaatspagina's
   noemen sinds oktober 2026 "incl. btw" in hun omschrijving. Kiest de
   eigenaar voor de kleineondernemersregeling (KOR: true), of zegt VAT_NOTE
   niet meer dat de prijzen inclusief btw zijn, dan klopt die tekst niet meer. */
const btwKlopt = P.KOR !== true && (leeg(P.VAT_NOTE) || /inclusief btw/i.test(P.VAT_NOTE));
if (!btwKlopt) {
  for (const f of walk(ROOT, [])) {
    const html = fs.readFileSync(f, 'utf8').replace(/<!-- cfg:btw-vermelding -->[\s\S]*?<!-- \/cfg:btw-vermelding -->/g, '');
    if (/\b(?:incl\.|inclusief) btw\b/i.test(html)) {
      fouten.push(rel(f) + ': noemt "incl. btw", maar KOR of VAT_NOTE zegt dat er geen btw in de prijs zit. Pas de tekst met de hand aan.');
    }
  }
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
/* jaartallen en startkorting: llms.txt heeft geen markers, dus waarschuwen na een jaarwissel */
[['correctie', JAREN.correctie_van, JAREN.correctie_tot], ['box 3', JAREN.box3_van, JAREN.box3_tot]].forEach(function (r) {
  if (llms.indexOf(r[1] + '–' + r[2]) === -1) waarschuwingen.push('llms.txt noemt de jaren voor ' + r[0] + ' (' + r[1] + '–' + r[2] + ') niet; werk llms.txt met de hand bij.');
});
if (!startkortingLoopt && /startkorting/i.test(llms)) waarschuwingen.push('llms.txt noemt de startkorting nog, maar die loopt niet meer; haal de regel weg.');
if (startkortingLoopt && llms.indexOf(datumTekst(sk.geldig_tot, 'nl')) === -1) waarschuwingen.push('llms.txt noemt de einddatum van de startkorting (' + datumTekst(sk.geldig_tot, 'nl') + ') niet.');
if (!leeg(P.FEE_BOX3) && llms.indexOf(String(P.FEE_BOX3).replace('.', ',') + '%') === -1) {
  waarschuwingen.push('llms.txt noemt het box 3-tarief (' + P.FEE_BOX3 + '%) niet; werk llms.txt met de hand bij.');
}

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
