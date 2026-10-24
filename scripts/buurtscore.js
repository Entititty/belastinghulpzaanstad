#!/usr/bin/env node
/*
 * buurtscore.js — in welke buurten van Zaanstad, Oostzaan en Wormerland zit
 * de meeste kans per doelgroep? Voor het richten van flyers en lokale ads.
 *
 * WAAROM
 * Een flyer kost geld per brievenbus. Dit script rangschikt de buurten per
 * doelgroep met open data van het CBS, zodat de flyers daar komen waar de
 * meeste senioren, kopers, huurders of spaarders wonen. Er komen geen
 * persoonsgegevens aan te pas: alleen cijfers per buurt.
 *
 * BRONNEN
 * - CBS "Kerncijfers wijken en buurten <jaar>" via OData. Het tabelnummer
 *   zoekt het script op in de CBS-catalogus (2025 = 86165NED), en de
 *   kolomnamen komen uit DataProperties (ze krijgen elk jaar een ander
 *   volgnummer, zoals Koopwoningen_47).
 * - Is een cijfer in dat jaar (nog) leeg, dan neemt het script dezelfde buurt
 *   uit de tabel van het jaar ervoor, en anders van twee jaar ervoor. Zo komen
 *   inkomen en vermogen in 2025 uit de tabel van 2024; het CBS vult een jaar
 *   pas later aan. Per cijfer staat in de uitvoer uit welk jaar het komt.
 * - PDOK "CBS Wijken en Buurten <jaar>" voor de buurtgrenzen (RD-coördinaten).
 *   Is die kaart er nog niet, dan die van het jaar ervoor.
 *
 * SCORE (0-100) per doelgroep
 * Per indicator de percentielrang tussen de buurten (0 = laagste, 100 =
 * hoogste), gewogen opgeteld. De gewichten staan hieronder bij DOELGROEPEN.
 * Ontbreekt een indicator voor een buurt, dan tellen de andere zwaarder; is
 * minder dan de helft van het gewicht bekend, dan geen score. Buurten met
 * minder dan 50 huishoudens (bedrijventerrein, polder) vallen af.
 * Het is een INDICATIE: een hoge score zegt waar de doelgroep relatief veel
 * woont, niet dat daar klanten zitten.
 *
 * UITVOER in intern/buurtscore/<jaar>/ (staat in .gitignore: bedrijfsgegevens)
 * - buurtscore.csv   alle buurten, cijfers, scores, rang en QR-adres per doelgroep
 * - buurtscore.xlsx  een blad per doelgroep (gesorteerd), alle buurten, uitleg
 * - kaart.html       een kaart per doelgroep, met de top 10 genummerd
 * - top10.html       per doelgroep een printbare pagina met QR-codes
 * - qr/<doelgroep>/<buurt>.svg
 * De QR-codes wijzen naar de pagina voor de doelgroep, met
 * ?utm_source=flyer&utm_medium=print&utm_campaign=<buurt>&utm_content=<doelgroep>,
 * zodat /beheer/overzicht per buurt laat zien wat een flyer oplevert.
 *
 * GEBRUIK
 *   node scripts/buurtscore.js                  2025, uit de cache als die er is
 *   node scripts/buurtscore.js --jaar 2026      een ander jaar
 *   node scripts/buurtscore.js --vernieuw       alles opnieuw ophalen
 *   node scripts/buurtscore.js --prijs 0,12     flyerkosten per huishouden erbij
 *   node scripts/buurtscore.js --min-huishoudens 100   kleine buurten overslaan (standaard 50)
 *   node scripts/buurtscore.js --uit <map>      ergens anders wegschrijven
 *
 * Scan een QR-code altijd één keer met een telefoon voordat er iets naar de drukker gaat.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { xlsx } = require('../app/lib/export');
const qr = require('../app/lib/qr');

const ROOT = path.resolve(__dirname, '..');
const arg = (naam, std) => { const i = process.argv.indexOf(naam); return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : std; };
const JAAR = Number(arg('--jaar', '2025'));
const VERNIEUW = process.argv.includes('--vernieuw');
const PRIJS = arg('--prijs', '') ? Number(arg('--prijs', '').replace(',', '.')) : null;
const MIN_HH = Number(arg('--min-huishoudens', '50'));
const UIT = path.resolve(arg('--uit', path.join(ROOT, 'intern', 'buurtscore', String(JAAR))));
const CACHE = path.join(ROOT, 'intern', 'buurtscore', 'cache');
const SITE = 'https://belastinghulpzaanstad.nl';
const GEMEENTEN = { GM0479: 'Zaanstad', GM0431: 'Oostzaan', GM0880: 'Wormerland' };

/* CBS-kolom (zonder volgnummer) -> onze naam */
const KOLOMMEN = {
  inwoners: 'AantalInwoners', n2545: 'k_25Tot45Jaar', n65: 'k_65JaarOfOuder', huishoudens: 'HuishoudensTotaal',
  woningen: 'Woningvoorraad', nieuwbouw: 'NieuwbouwWoningen', woz: 'GemiddeldeWOZWaardeVanWoningen', koop: 'Koopwoningen',
  huur: 'HuurwoningenTotaal', corp: 'InBezitWoningcorporatie', recent: 'BouwjaarAfgelopenTienJaar',
  laag40: 'k_40HuishoudensMetLaagsteInkomen', hoog20: 'k_20HuishoudensMetHoogsteInkomen',
  vermogen: 'MediaanVermogenVanParticuliereHuish', armoede: 'PersonenInArmoede', aow: 'PersonenPerSoortUitkeringAOW',
  postcode: 'MeestVoorkomendePostcode'
};
/* ontbreekt een kolom in een jaar, dan de som van deze kolommen (vanaf 2026 is 65+ gesplitst) */
const VERVANGERS = { k_65JaarOfOuder: ['k_65JaarTot80Jaar', 'k_80JaarOfOuder'] };
/* afgeleide indicatoren */
const AFGELEID = {
  p65: (b) => (b.inwoners > 0 && b.n65 !== null ? (b.n65 / b.inwoners) * 100 : null),
  p2545: (b) => (b.inwoners > 0 && b.n2545 !== null ? (b.n2545 / b.inwoners) * 100 : null),
  nieuwbouwAandeel: (b) => (b.woningen > 0 && b.nieuwbouw !== null ? (b.nieuwbouw / b.woningen) * 100 : null)
};
const UITLEG = {
  p65: '% inwoners 65+', n65: 'aantal inwoners 65+', koop: '% koopwoningen', p2545: '% inwoners 25-45 jaar',
  recent: '% woningen gebouwd in de laatste 10 jaar', nieuwbouwAandeel: '% nieuwbouw in het jaar', nieuwbouw: 'aantal nieuwbouwwoningen in het jaar', huur: '% huurwoningen',
  corp: '% woningen van een corporatie', laag40: '% huishoudens in de laagste 40% inkomens', armoede: '% personen in armoede',
  vermogen: 'mediaan vermogen per huishouden', hoog20: '% huishoudens in de hoogste 20% inkomens'
};

const DOELGROEPEN = [
  { code: 'senioren', naam: 'Senioren (AOW, pensioen)', landing: '/senioren/', gewichten: { p65: 0.6, n65: 0.4 },
    schatting: (b) => b.n65, schattingUitleg: 'inwoners van 65 jaar of ouder' },
  { code: 'woningbezitters', naam: 'Kopers en woningbezitters (voorlopige teruggave)', landing: '/diensten/voorlopige-teruggave/',
    gewichten: { koop: 0.35, p2545: 0.25, nieuwbouw: 0.2, recent: 0.2 },
    schatting: (b) => (b.koop === null ? null : Math.round((b.huishoudens * b.koop) / 100)), schattingUitleg: 'huishoudens × % koopwoningen' },
  { code: 'toeslagen', naam: 'Huurders (toeslagen)', landing: '/diensten/toeslagen/', gewichten: { huur: 0.25, corp: 0.15, laag40: 0.35, armoede: 0.25 },
    schatting: (b) => (b.huur === null ? null : Math.round((b.huishoudens * b.huur) / 100)), schattingUitleg: 'huishoudens × % huurwoningen' },
  { code: 'box3', naam: 'Spaargeld en beleggingen (box 3)', landing: '/diensten/box-3-bezwaar/', gewichten: { vermogen: 0.5, hoog20: 0.25, p65: 0.25 },
    schatting: (b) => (b.hoog20 === null ? null : Math.round((b.huishoudens * b.hoog20) / 100)), schattingUitleg: 'huishoudens × % hoogste 20% inkomens' }
];

/* ---------------- ophalen, met cache (per naam; een ander adres haalt opnieuw) ---------------- */
async function haal(url, naam) {
  const f = path.join(CACHE, naam + '.json');
  if (!VERNIEUW && fs.existsSync(f)) {
    const c = JSON.parse(fs.readFileSync(f, 'utf8'));
    if (c.url === url) return c.data;
  }
  const r = await fetch(url, { headers: { Accept: 'application/json' } });
  const tekst = await r.text();
  if (!r.ok) throw Object.assign(new Error(url + ': HTTP ' + r.status + ' ' + tekst.slice(0, 200)), { status: r.status });
  const j = JSON.parse(tekst);
  fs.mkdirSync(CACHE, { recursive: true });
  fs.writeFileSync(f, JSON.stringify({ url, data: j }));
  return j;
}
const CBS = 'https://opendata.cbs.nl/ODataApi/odata/';
const PDOK = 'https://api.pdok.nl/cbs/wijken-en-buurten-';
const enc = encodeURIComponent;

async function tabelVoorJaar(jaar) {
  const j = await haal('https://opendata.cbs.nl/ODataCatalog/Tables?$format=json&$select=Identifier,Title&$filter=' +
    enc("Title eq 'Kerncijfers wijken en buurten " + jaar + "'"), 'catalogus-' + jaar);
  return j.value && j.value[0] ? j.value[0].Identifier : null;
}

/* per naam de CBS-sleutels in deze tabel (met volgnummer); meer dan één = optellen */
function kolomSleutels(props) {
  const sleutel = {};
  for (const p of props) if (p.Key) sleutel[p.Key.replace(/_\d+$/, '')] = p.Key;
  const uit = {};
  for (const [naam, k] of Object.entries(KOLOMMEN)) {
    if (sleutel[k]) uit[naam] = [sleutel[k]];
    else if (VERVANGERS[k] && VERVANGERS[k].every((d) => sleutel[d])) uit[naam] = VERVANGERS[k].map((d) => sleutel[d]);
  }
  return uit;
}

async function cbsTabel(jaar) {
  const tabel = await tabelVoorJaar(jaar);
  if (!tabel) return null;
  const velden = Object.entries(kolomSleutels((await haal(CBS + tabel + '/DataProperties?$format=json', tabel + '-dataproperties')).value));
  const rijen = [];
  const namen = {};
  for (const gm of Object.keys(GEMEENTEN)) {
    const g4 = gm.slice(2);
    const f = "startswith(WijkenEnBuurten,'BU" + g4 + "') or startswith(WijkenEnBuurten,'WK" + g4 + "')";
    const j = await haal(CBS + tabel + '/TypedDataSet?$format=json&$select=WijkenEnBuurten,' + velden.flatMap(([, ks]) => ks).join(',') + '&$filter=' + enc(f), tabel + '-' + gm);
    for (const r of j.value) {
      const o = { code: r.WijkenEnBuurten.trim() };
      for (const [naam, ks] of velden) {
        const delen = ks.map((k) => { const v = r[k]; return typeof v === 'string' ? v.trim() || null : v === undefined ? null : v; });
        o[naam] = delen.length === 1 ? delen[0] : delen.includes(null) ? null : delen.reduce((a, v) => a + v, 0);
      }
      rijen.push(o);
    }
    const d = await haal(CBS + tabel + '/WijkenEnBuurten?$format=json&$filter=' + enc("startswith(Key,'BU" + g4 + "') or startswith(Key,'WK" + g4 + "')"), tabel + '-namen-' + gm);
    for (const x of d.value) namen[x.Key.trim()] = x.Title.trim();
  }
  return { tabel, jaar, rijen, namen };
}

/* PDOK wisselt per jaar van veldnamen: 2025 gemeentecode/buurtcode, 2026 gm_code/bu_code */
const veld = (p, namen) => namen.map((n) => p[n]).find((v) => v !== undefined);
const buurtcodeVan = (p) => veld(p, ['buurtcode', 'bu_code']);
const gemeentecodeVan = (p) => veld(p, ['gemeentecode', 'gm_code']);
const RD = enc('http://www.opengis.net/def/crs/EPSG/0/28992');

async function pdokVelden(jaar, collectie) {
  return Object.keys((await haal(PDOK + jaar + '/ogc/v1/collections/' + collectie + '/queryables?f=json', 'pdok-' + jaar + '-' + collectie + '-velden')).properties || {});
}

/* de nieuwste buurtkaart: het gevraagde jaar, anders het jaar ervoor */
async function pdokJaar(jaar) {
  for (const j of [jaar, jaar - 1]) {
    try { await pdokVelden(j, 'buurten'); return j; } catch (e) { if (e.status !== 404) throw e; }
  }
  throw new Error('geen PDOK-buurtkaart voor ' + jaar + ' of ' + (jaar - 1));
}

function omvatting(features) {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const f of features) for (const r of ringen(f.geometry)) for (const [x, y] of r) { minX = Math.min(minX, x); maxX = Math.max(maxX, x); minY = Math.min(minY, y); maxY = Math.max(maxY, y); }
  return [minX, minY, maxX, maxY].map(Math.round);
}

/* Kan de collectie niet op gemeente filteren, dan op het kader (bbox) van de gemeente, en daarna op de code. */
async function pdok(jaar, collectie, gm, kader) {
  const velden = await pdokVelden(jaar, collectie);
  const sleutel = ['gemeentecode', 'gm_code'].find((k) => velden.includes(k));
  if (!sleutel && !kader) throw new Error('PDOK ' + jaar + ' ' + collectie + ': geen filter op gemeente');
  let url = PDOK + jaar + '/ogc/v1/collections/' + collectie + '/items?f=json&limit=1000&crs=' + RD +
    (sleutel ? '&' + sleutel + '=' + gm : '&bbox=' + kader.join(',') + '&bbox-crs=' + RD);
  const features = [];
  for (let pagina = 0; url && pagina < 10; pagina++) {
    const j = await haal(url, 'pdok-' + jaar + '-' + collectie + '-' + gm + (pagina ? '-' + pagina : ''));
    features.push(...j.features);
    const volgende = (j.links || []).find((l) => l.rel === 'next');
    url = volgende ? volgende.href : null;
  }
  return features.filter((f) => gemeentecodeVan(f.properties) === gm);
}

/* ---------------- rekenen ---------------- */
/* het eerste jaar met een waarde: tabellen staan op volgorde, het gevraagde jaar eerst */
function kies(code, naam, tabellen) {
  for (const t of tabellen) {
    const r = t.perCode.get(code);
    if (r && r[naam] !== undefined && r[naam] !== null) return { v: r[naam], jaar: t.jaar };
  }
  return { v: null, jaar: null };
}

function percentielen(waarden) {
  const geldig = waarden.map((v, i) => [v, i]).filter(([v]) => v !== null && Number.isFinite(v)).sort((a, b) => a[0] - b[0]);
  const uit = waarden.map(() => null);
  const n = geldig.length;
  for (let i = 0; i < n;) {
    let j = i;
    while (j + 1 < n && geldig[j + 1][0] === geldig[i][0]) j++;
    const rang = (i + j) / 2;
    for (let k = i; k <= j; k++) uit[geldig[k][1]] = n > 1 ? (rang / (n - 1)) * 100 : 50;
    i = j + 1;
  }
  return uit;
}

function slug(s) {
  return String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
}

/* ---------------- kaart: RD naar SVG, vereenvoudigd ---------------- */
function vereenvoudig(punten, tol) {
  if (punten.length < 5) return punten;
  const houd = new Uint8Array(punten.length);
  houd[0] = houd[punten.length - 1] = 1;
  const stapel = [[0, punten.length - 1]];
  while (stapel.length) {
    const [a, b] = stapel.pop();
    let max = 0, idx = -1;
    const [x1, y1] = punten[a], [x2, y2] = punten[b];
    const dx = x2 - x1, dy = y2 - y1, l2 = dx * dx + dy * dy;
    for (let i = a + 1; i < b; i++) {
      const [x, y] = punten[i];
      let d;
      if (!l2) d = Math.hypot(x - x1, y - y1);
      else {
        const t = Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / l2));
        d = Math.hypot(x - (x1 + t * dx), y - (y1 + t * dy));
      }
      if (d > max) { max = d; idx = i; }
    }
    if (max > tol && idx > 0) { houd[idx] = 1; stapel.push([a, idx], [idx, b]); }
  }
  const r = punten.filter((_, i) => houd[i]);
  return r.length >= 4 ? r : punten;
}

function ringen(geometry) {
  if (!geometry) return [];
  if (geometry.type === 'Polygon') return geometry.coordinates;
  if (geometry.type === 'MultiPolygon') return geometry.coordinates.flat();
  return [];
}

function oppervlakEnMidden(ring) {
  let a = 0, cx = 0, cy = 0;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const f = ring[j][0] * ring[i][1] - ring[i][0] * ring[j][1];
    a += f; cx += (ring[j][0] + ring[i][0]) * f; cy += (ring[j][1] + ring[i][1]) * f;
  }
  return a ? { a: Math.abs(a / 2), x: cx / (3 * a), y: cy / (3 * a) } : { a: 0, x: ring[0][0], y: ring[0][1] };
}

/* ---------------- uitvoer ---------------- */
const KLASSEN = ['#86b6ef', '#5598e7', '#2a78d6', '#1c5cab', '#104281']; /* dataviz-ramp 250..650, gevalideerd als ordinale schaal op wit */
const GEEN = '#e4e2dc';
const getal = (n) => (n === null || n === undefined ? '' : Number(n).toLocaleString('nl-NL', { maximumFractionDigits: 1 }));
const esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const klasse = (s) => (s === null ? null : Math.min(4, Math.floor(s / 20)));
const qrUrl = (dg, b) => SITE + dg.landing + '?utm_source=flyer&utm_medium=print&utm_campaign=' + b.slug + '&utm_content=' + dg.code;

async function main() {
  console.log('Buurtscore ' + JAAR + ' voor ' + Object.values(GEMEENTEN).join(', ') + (VERNIEUW ? ' (alles opnieuw ophalen)' : ''));
  const hoofd = await cbsTabel(JAAR);
  if (!hoofd) throw new Error('geen CBS-tabel "Kerncijfers wijken en buurten ' + JAAR + '" gevonden');
  const eerder = [];
  for (const j of [JAAR - 1, JAAR - 2]) { const t = await cbsTabel(j); if (t) eerder.push(t); }
  console.log('  CBS ' + hoofd.tabel + ' (' + JAAR + ')' + (eerder.length ? ', aanvulling uit ' + eerder.map((t) => t.tabel + ' (' + t.jaar + ')').join(' en ') : ''));

  /* buurten, met per cijfer het jaar van herkomst */
  const tabellen = [hoofd].concat(eerder).map((t) => ({ jaar: t.jaar, perCode: new Map(t.rijen.map((r) => [r.code, r])) }));
  const herkomst = {};
  const buurten = hoofd.rijen.filter((r) => r.code.startsWith('BU')).map((r) => {
    const b = { code: r.code, naam: hoofd.namen[r.code] || r.code, gemeentecode: 'GM' + r.code.slice(2, 6), wijkcode: 'WK' + r.code.slice(2, 8), bronjaar: {} };
    b.gemeente = GEMEENTEN[b.gemeentecode];
    b.wijk = hoofd.namen[b.wijkcode] || b.wijkcode;
    for (const naam of Object.keys(KOLOMMEN)) {
      const { v, jaar } = kies(r.code, naam, tabellen);
      b[naam] = v;
      if (v !== null) { b.bronjaar[naam] = jaar; herkomst[naam] = herkomst[naam] || {}; herkomst[naam][jaar] = (herkomst[naam][jaar] || 0) + 1; }
    }
    for (const [naam, fn] of Object.entries(AFGELEID)) b[naam] = fn(b);
    return b;
  });

  /* geometrie */
  const geoJaar = await pdokJaar(JAAR);
  const geo = new Map();
  const gemeenteGrenzen = [];
  for (const gm of Object.keys(GEMEENTEN)) {
    const gemeente = await pdok(geoJaar, 'gemeenten', gm);
    if (!gemeente.length) throw new Error('PDOK ' + geoJaar + ': gemeente ' + gm + ' niet gevonden');
    gemeenteGrenzen.push(...gemeente);
    for (const f of await pdok(geoJaar, 'buurten', gm, omvatting(gemeente))) geo.set(buurtcodeVan(f.properties), f);
  }
  for (const b of buurten) {
    const f = geo.get(b.code);
    b.water = f ? f.properties.water === 'JA' : false;
    b.geometrie = f ? f.geometry : null;
  }
  const doen = buurten.filter((b) => !b.water && (b.huishoudens || 0) >= MIN_HH);
  console.log('  ' + buurten.length + ' buurten, ' + doen.length + ' met minstens ' + MIN_HH + ' huishoudens; ' + geo.size + ' grenzen van PDOK (' + geoJaar + ')' +
    (buurten.some((b) => !b.geometrie) ? '; zonder grens: ' + buurten.filter((b) => !b.geometrie).map((b) => b.code).join(', ') : ''));

  /* unieke slugs voor de campagnecodes */
  const telSlug = {};
  for (const b of buurten) telSlug[slug(b.naam)] = (telSlug[slug(b.naam)] || 0) + 1;
  for (const b of buurten) b.slug = telSlug[slug(b.naam)] > 1 ? slug(b.naam + ' ' + b.gemeente) : slug(b.naam);

  /* scores */
  for (const dg of DOELGROEPEN) {
    const pct = {};
    for (const ind of Object.keys(dg.gewichten)) pct[ind] = percentielen(doen.map((b) => (b[ind] === undefined ? null : b[ind])));
    const totaal = Object.values(dg.gewichten).reduce((a, w) => a + w, 0);
    doen.forEach((b, i) => {
      let som = 0, gewicht = 0;
      for (const [ind, w] of Object.entries(dg.gewichten)) if (pct[ind][i] !== null) { som += w * pct[ind][i]; gewicht += w; }
      b['score_' + dg.code] = gewicht >= totaal / 2 ? Math.round(som / gewicht) : null;
    });
    const volgorde = doen.filter((b) => b['score_' + dg.code] !== null).sort((a, c) => c['score_' + dg.code] - a['score_' + dg.code] || (c.huishoudens - a.huishoudens));
    volgorde.forEach((b, i) => { b['rang_' + dg.code] = i + 1; });
    dg.volgorde = volgorde;
  }

  fs.mkdirSync(UIT, { recursive: true });
  const bronTekst = 'CBS ' + hoofd.tabel + ' (Kerncijfers wijken en buurten ' + JAAR + ')' +
    (eerder.length ? '; lege cijfers aangevuld uit ' + eerder.map((t) => t.tabel + ' (' + t.jaar + ')').join(' en ') : '') + '; grenzen PDOK CBS Wijken en Buurten ' + geoJaar;

  /* ---------- tabellen ---------- */
  const basis = [['Buurtcode', 14], ['Buurt', 26], ['Wijk', 22], ['Gemeente', 12], ['Postcode (meest)', 10], ['Huishoudens', 12, 'getal'], ['Inwoners', 10, 'getal']];
  const indicatoren = ['p65', 'n65', 'aow', 'koop', 'huur', 'corp', 'p2545', 'recent', 'nieuwbouw', 'woz', 'laag40', 'armoede', 'hoog20', 'vermogen'];
  const kolNaam = { p65: '% 65+', n65: '65+ (aantal)', aow: 'AOW (personen)', koop: '% koop', huur: '% huur', corp: '% corporatie', p2545: '% 25-45', recent: '% bouwjaar < 10 jr',
    nieuwbouw: 'Nieuwbouw (aantal)', woz: 'WOZ gem. (x1000)', laag40: '% laagste 40% ink.', armoede: '% armoede', hoog20: '% hoogste 20% ink.', vermogen: 'Vermogen mediaan (x1000)',
    inwoners: 'Inwoners', n2545: '25-45 (aantal)', huishoudens: 'Huishoudens', woningen: 'Woningen', postcode: 'Postcode' };
  /* "% koop: 89 buurten uit 2025" voor elk cijfer dat (deels) uit een eerder jaar komt */
  const aanvulling = Object.entries(herkomst).flatMap(([k, jaren]) => Object.entries(jaren).filter(([j]) => Number(j) !== JAAR)
    .map(([j, n]) => (kolNaam[k] || k) + ': ' + n + ' buurten uit ' + j));
  const rij = (b) => [b.code, b.naam, b.wijk, b.gemeente, b.postcode, b.huishoudens, b.inwoners];
  const ind = (b) => indicatoren.map((k) => (b[k] === null || b[k] === undefined ? null : Math.round(b[k] * 10) / 10));
  /* komt een cijfer helemaal uit eerdere jaren, dan staat het jaar in de kolomkop */
  const uitJaren = (k) => (herkomst[k] && !herkomst[k][JAAR] ? ' (' + Object.keys(herkomst[k]).sort().join('/') + ')' : '');
  const kolommen = basis.map(([kop, breedte, soort]) => ({ kop, breedte, soort }))
    .concat(indicatoren.map((k) => ({ kop: kolNaam[k] + uitJaren(k), breedte: 12, soort: 'getal' })));

  const bladen = DOELGROEPEN.map((dg) => ({
    naam: dg.code === 'box3' ? 'Box 3' : dg.code.charAt(0).toUpperCase() + dg.code.slice(1),
    kolommen: [{ kop: 'Rang', breedte: 6, soort: 'getal' }, { kop: 'Score', breedte: 7, soort: 'getal' }].concat(kolommen,
      [{ kop: 'Doelgroep (schatting: ' + dg.schattingUitleg + ')', breedte: 18, soort: 'getal' }],
      PRIJS ? [{ kop: 'Flyerkosten (€ ' + String(PRIJS).replace('.', ',') + ' per huishouden)', breedte: 14, soort: 'euro' }] : [],
      [{ kop: 'QR-adres', breedte: 60 }]),
    rijen: dg.volgorde.map((b) => [b['rang_' + dg.code], b['score_' + dg.code]].concat(rij(b), ind(b), [dg.schatting(b)],
      PRIJS ? [Math.round(b.huishoudens * PRIJS * 100) / 100] : [], [qrUrl(dg, b)]))
  }));
  const alle = {
    naam: 'Alle buurten',
    kolommen: kolommen.concat(DOELGROEPEN.map((dg) => ({ kop: 'Score ' + dg.code, breedte: 10, soort: 'getal' })), [{ kop: 'Water', breedte: 7 }]),
    rijen: buurten.map((b) => rij(b).concat(ind(b), DOELGROEPEN.map((dg) => (b['score_' + dg.code] === undefined ? null : b['score_' + dg.code])), [b.water ? 'ja' : '']))
  };
  const uitleg = {
    naam: 'Uitleg',
    kolommen: [{ kop: 'Onderwerp', breedte: 26 }, { kop: 'Toelichting', breedte: 120 }],
    rijen: [['Bron', bronTekst], ['Aangevuld uit eerdere jaren', aanvulling.join('; ') || 'niets'],
      ['Score', 'Per indicator de percentielrang tussen de buurten (0-100), gewogen opgeteld. Een indicatie, geen voorspelling.'],
      ['Buurten zonder score', 'Minder dan ' + MIN_HH + ' huishoudens, alleen water, of te weinig cijfers (CBS laat kleine aantallen weg).']]
      .concat(DOELGROEPEN.map((dg) => ['Gewichten ' + dg.code, Object.entries(dg.gewichten).map(([k, w]) => UITLEG[k] + ' ' + Math.round(w * 100) + '%').join(', ')]))
      .concat([['QR-adres', 'Pagina van de doelgroep met utm_source=flyer, utm_medium=print, utm_campaign=<buurt>, utm_content=<doelgroep>. Scan er altijd één met een telefoon voordat u laat drukken.']])
  };
  fs.writeFileSync(path.join(UIT, 'buurtscore.xlsx'), xlsx(bladen.concat([alle, uitleg])));
  const csvKop = alle.kolommen.map((k) => k.kop).concat(DOELGROEPEN.flatMap((dg) => ['Rang ' + dg.code, 'QR ' + dg.code]));
  const csvRij = (b) => alle.rijen[buurten.indexOf(b)].concat(DOELGROEPEN.flatMap((dg) => [b['rang_' + dg.code] || null, b['score_' + dg.code] !== undefined && b['score_' + dg.code] !== null ? qrUrl(dg, b) : null]));
  const cel = (v) => (v === null || v === undefined ? '' : /[;"\n]/.test(String(v)) ? '"' + String(v).replace(/"/g, '""') + '"' : typeof v === 'number' ? String(v).replace('.', ',') : String(v));
  fs.writeFileSync(path.join(UIT, 'buurtscore.csv'), '﻿' + [csvKop.map(cel).join(';')].concat(buurten.map((b) => csvRij(b).map(cel).join(';'))).join('\r\n') + '\r\n');

  /* ---------- QR-codes ---------- */
  let qrTel = 0;
  for (const dg of DOELGROEPEN) {
    const map = path.join(UIT, 'qr', dg.code);
    fs.mkdirSync(map, { recursive: true });
    for (const b of dg.volgorde) {
      fs.writeFileSync(path.join(map, b.slug + '.svg'), qr.svg(qr.maak(qrUrl(dg, b), 'M'), { rand: 4, schaal: 6, titel: 'QR-code ' + b.naam }));
      qrTel++;
    }
  }

  /* ---------- kaart ---------- */
  const alleRingen = buurten.filter((b) => b.geometrie).flatMap((b) => ringen(b.geometrie));
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const r of alleRingen) for (const [x, y] of r) { minX = Math.min(minX, x); maxX = Math.max(maxX, x); minY = Math.min(minY, y); maxY = Math.max(maxY, y); }
  const marge = 300;
  minX -= marge; minY -= marge; maxX += marge; maxY += marge;
  const sx = (x) => Math.round(x - minX), sy = (y) => Math.round(maxY - y);
  const pad = (geometrie) => ringen(geometrie).map((r) => {
    const v = vereenvoudig(r, 6);
    return 'M' + v.map(([x, y]) => sx(x) + ' ' + sy(y)).join('L') + 'Z';
  }).join('');
  const defs = buurten.filter((b) => b.geometrie).map((b) => '<path id="b' + b.code + '" d="' + pad(b.geometrie) + '"/>').join('');
  const grenzen = gemeenteGrenzen.map((f) => '<path d="' + pad(f.geometry) + '" fill="none" stroke="#6b6560" stroke-width="2" vector-effect="non-scaling-stroke"/>').join('');
  const midden = (b) => {
    const r = ringen(b.geometrie).map((x) => Object.assign(oppervlakEnMidden(x), { r: x })).sort((a, c) => c.a - a.a)[0];
    return r ? [sx(r.x), sy(r.y)] : null;
  };
  const kaartVoor = (dg) => {
    const vlakken = buurten.filter((b) => b.geometrie).map((b) => {
      const s = b['score_' + dg.code];
      const k = s === undefined || s === null ? null : klasse(s);
      const tip = b.naam + ' (' + b.wijk + ', ' + b.gemeente + ')' + (k === null ? ': geen score' : ': score ' + s + ', rang ' + b['rang_' + dg.code] + ', ' + getal(b.huishoudens) + ' huishoudens');
      return '<use href="#b' + b.code + '" fill="' + (k === null ? GEEN : KLASSEN[k]) + '" stroke="#ffffff" stroke-width="1" vector-effect="non-scaling-stroke"><title>' + esc(tip) + '</title></use>';
    }).join('');
    const nummers = dg.volgorde.slice(0, 10).map((b) => {
      const m = midden(b);
      return m ? '<g class="nr"><circle cx="' + m[0] + '" cy="' + m[1] + '" r="230" fill="#ffffff" stroke="#0b0b0b" stroke-width="1.5" vector-effect="non-scaling-stroke"/>' +
        '<text x="' + m[0] + '" y="' + (m[1] + 100) + '" text-anchor="middle" font-size="290" font-weight="700" fill="#0b0b0b">' + b['rang_' + dg.code] + '</text></g>' : '';
    }).join('');
    return '<svg class="kaart" viewBox="0 0 ' + Math.round(maxX - minX) + ' ' + Math.round(maxY - minY) + '" role="img" aria-label="' + esc('Kaart ' + dg.naam) + '">' +
      vlakken + grenzen + nummers + '</svg>';
  };
  const legenda = '<p class="legenda">' + ['0-19', '20-39', '40-59', '60-79', '80-100'].map((t, i) => '<span class="vak" data-kleur="' + i + '"></span>' + t).join(' ') +
    ' <span class="vak geen"></span>geen score</p>';
  const tabelTop = (dg, metQr) => '<table><thead><tr><th>#</th><th>Buurt</th><th>Gemeente</th><th class="g">Huishoudens</th><th class="g">Doelgroep*</th>' +
    (PRIJS ? '<th class="g">Flyers</th>' : '') + '<th class="g">Score</th>' + (metQr ? '<th>QR-code</th>' : '') + '</tr></thead><tbody>' +
    dg.volgorde.slice(0, 10).map((b) => '<tr><td>' + b['rang_' + dg.code] + '</td><td>' + esc(b.naam) + '<br><span class="klein">' + esc(b.wijk) + (b.postcode ? ', ' + esc(b.postcode) : '') + '</span></td><td>' + esc(b.gemeente) +
      '</td><td class="g">' + getal(b.huishoudens) + '</td><td class="g">' + getal(dg.schatting(b)) + '</td>' +
      (PRIJS ? '<td class="g">€ ' + (b.huishoudens * PRIJS).toLocaleString('nl-NL', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + '</td>' : '') +
      '<td class="g">' + b['score_' + dg.code] + '</td>' +
      (metQr ? '<td class="qr">' + qr.svg(qr.maak(qrUrl(dg, b), 'M'), { rand: 2, schaal: 2, titel: 'QR-code ' + b.naam }) + '<span class="url">' + esc(qrUrl(dg, b)) + '</span></td>' : '') + '</tr>').join('') +
    '</tbody></table><p class="klein">* Doelgroep, een schatting: ' + esc(dg.schattingUitleg) + '. Flyers gaan naar alle huishoudens.' +
    (PRIJS ? ' Top 10 samen: ' + getal(dg.volgorde.slice(0, 10).reduce((a, b) => a + b.huishoudens, 0)) + ' huishoudens, € ' +
      (dg.volgorde.slice(0, 10).reduce((a, b) => a + b.huishoudens, 0) * PRIJS).toLocaleString('nl-NL', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + '.' : '') + '</p>';
  const stijl = '<style>:root{color-scheme:light}body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#2c2520;background:#f9f9f7}' +
    'main{max-width:1000px;margin:0 auto;padding:20px 16px 60px}h1{font-size:1.5rem}h2{font-size:1.2rem;margin:34px 0 6px}' +
    '.kaart{width:100%;height:auto;background:#fff;border:1px solid rgba(11,11,11,.1);border-radius:12px}' +
    'table{border-collapse:collapse;width:100%;background:#fff;font-size:.92rem;margin:10px 0}th,td{padding:6px 8px;border-bottom:1px solid #e1e0d9;text-align:left;vertical-align:top}' +
    '.g{text-align:right;font-variant-numeric:tabular-nums}.klein{font-size:.85rem;color:#52514e}.legenda{font-size:.9rem;color:#52514e}' +
    '.vak{display:inline-block;width:14px;height:14px;border-radius:3px;vertical-align:-2px;margin:0 4px 0 10px}' +
    KLASSEN.map((k, i) => '.vak[data-kleur="' + i + '"]{background:' + k + '}').join('') + '.vak.geen{background:' + GEEN + '}' +
    '.qr svg{display:block;width:30mm;height:30mm}.url{display:block;font-size:.7rem;color:#52514e;word-break:break-all;max-width:60mm}' +
    '@media print{body{background:#fff}main{padding:0}.blad{page-break-after:always}.blad:last-child{page-break-after:auto}}</style>';
  const kop = (titel) => '<!doctype html><html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + esc(titel) + '</title>' + stijl + '</head><body><main>';
  const bronNoot = '<p class="klein">Bron: ' + esc(bronTekst) + '.' + (aanvulling.length ? ' Aangevuld uit eerdere jaren: ' + esc(aanvulling.join('; ')) + '.' : '') +
    ' De score is een indicatie (percentielrang van gewogen buurtcijfers), geen voorspelling. Gemaakt op ' + new Date().toLocaleDateString('nl-NL') + '.</p>';
  fs.writeFileSync(path.join(UIT, 'kaart.html'), kop('Buurtscore ' + JAAR) + '<h1>Buurtscore ' + JAAR + ': Zaanstad, Oostzaan en Wormerland</h1>' + bronNoot +
    '<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>' + defs + '</defs></svg>' +
    DOELGROEPEN.map((dg) => '<section><h2>' + esc(dg.naam) + '</h2><p class="klein">Gewichten: ' + esc(Object.entries(dg.gewichten).map(([k, w]) => UITLEG[k] + ' ' + Math.round(w * 100) + '%').join(', ')) +
      '. De nummers zijn de top 10.</p>' + legenda + kaartVoor(dg) + tabelTop(dg, false) + '</section>').join('') + '</main></body></html>');
  fs.writeFileSync(path.join(UIT, 'top10.html'), kop('Top 10 per doelgroep ' + JAAR) +
    DOELGROEPEN.map((dg) => '<section class="blad"><h1>Top 10: ' + esc(dg.naam) + '</h1><p class="klein">Landingspagina: ' + esc(SITE + dg.landing) +
      '. Elke QR-code heeft de buurt in het adres, zodat /beheer/overzicht per buurt laat zien wat de flyer oplevert. Scan er één met een telefoon voordat u laat drukken.</p>' +
      tabelTop(dg, true) + bronNoot + '</section>').join('') + '</main></body></html>');

  /* ---------- in de terminal ---------- */
  for (const dg of DOELGROEPEN) {
    console.log('\n' + dg.naam + ' — top 10');
    for (const b of dg.volgorde.slice(0, 10)) {
      console.log('  ' + String(b['rang_' + dg.code]).padStart(2) + '. ' + (b.naam + ' (' + b.gemeente + ')').padEnd(42) + ' score ' + String(b['score_' + dg.code]).padStart(3) +
        '  ' + String(b.huishoudens).padStart(5) + ' huishoudens');
    }
  }
  if (aanvulling.length) console.log('\nAangevuld uit eerdere jaren: ' + aanvulling.join('; '));
  console.log('\nGeschreven in ' + path.relative(ROOT, UIT) + ': buurtscore.csv, buurtscore.xlsx, kaart.html, top10.html en ' + qrTel + ' QR-codes.');
}

/* los te testen (app/test/buurtscore.test.js); als script: draaien */
if (require.main === module) main().catch((e) => { console.error('FOUT: ' + e.message); process.exit(1); });
module.exports = { percentielen, slug, vereenvoudig, oppervlakEnMidden, kolomSleutels, kies, buurtcodeVan, gemeentecodeVan, DOELGROEPEN };
