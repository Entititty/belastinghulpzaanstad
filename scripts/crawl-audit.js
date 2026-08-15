#!/usr/bin/env node
/*
 * crawl-audit.js
 * Crawlt de statische site vanaf schijf (geen server nodig) en schrijft:
 *   - data/crawl.csv        : één regel per pagina met alle SEO-velden
 *   - reports/crawl-audit.md: de problemen, gesorteerd op impact
 *
 * Gebruik:  node scripts/crawl-audit.js
 * Zie SEO-GEO-plan paragraaf 4.1.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ORIGIN = 'https://belastinghulpzaanstad.nl';
const DUN_WOORDEN = 500;        // drempel dunne pagina
const TITLE_MIN = 30, TITLE_MAX = 60;
const DESC_MIN = 120, DESC_MAX = 160;
const IN_LINK_MIN = 5;          // minder interne in-links = te weinig autoriteit

/* ---------- bestanden verzamelen ---------- */
function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      walk(path.join(dir, e.name), acc);
    } else if (e.name.endsWith('.html')) {
      acc.push(path.join(dir, e.name));
    }
  }
  return acc;
}

/* ---------- pad <-> url ---------- */
function fileToUrl(file) {
  let rel = path.relative(ROOT, file).split(path.sep).join('/');
  if (rel.endsWith('index.html')) rel = rel.slice(0, -'index.html'.length);
  return '/' + rel;
}

/* ---------- html helpers ---------- */
function stripComments(html) { return html.replace(/<!--[\s\S]*?-->/g, ''); }

function decode(s) {
  return s
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&euro;/g, '€').replace(/&[a-z]+;/gi, ' ');
}

function firstMatch(re, html) { const m = html.match(re); return m ? m[1].trim() : ''; }

function metaContent(html, attr, value) {
  const re = new RegExp('<meta[^>]+' + attr + '=["\']' + value + '["\'][^>]*>', 'i');
  const tag = html.match(re);
  if (!tag) return '';
  // Het aanhalingsteken aan het eind moet hetzelfde zijn als aan het begin.
  // Anders kapt een apostrof in de tekst de waarde af.
  const m = tag[0].match(/content=(["'])([\s\S]*?)\1/i);
  return m ? decode(m[2]) : '';
}

function wordCount(html) {
  const body = (html.match(/<body[^>]*>([\s\S]*)<\/body>/i) || [null, html])[1];
  const text = body
    .replace(/<(script|style|svg|noscript)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ');
  return decode(text).split(/\s+/).filter(function (w) { return /[a-zA-Z0-9€]/.test(w); }).length;
}

// Let op: @type mag ook een array zijn, bv. ["LocalBusiness","AccountingService"].
// Daarom lezen we de geparseerde knopen en niet de ruwe tekst.
function schemaTypes(html) {
  const types = new Set();
  jsonLdNodes(html).forEach(function (n) {
    [].concat(n['@type'] || []).forEach(function (t) {
      if (typeof t === 'string') types.add(t);
    });
  });
  return Array.from(types).sort();
}

function jsonLdParses(html) {
  const blocks = html.match(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi) || [];
  for (const b of blocks) {
    const json = b.replace(/^<script[^>]*>/i, '').replace(/<\/script>$/i, '');
    try { JSON.parse(json); } catch (err) { return false; }
  }
  return true;
}

// Alle JSON-LD-knopen plat, ook de geneste. Nodig om velden te controleren, niet alleen @type.
function jsonLdNodes(html) {
  const nodes = [];
  function collect(v) {
    if (Array.isArray(v)) { v.forEach(collect); return; }
    if (v && typeof v === 'object') {
      nodes.push(v);
      Object.keys(v).forEach(function (k) { collect(v[k]); });
    }
  }
  const blocks = html.match(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi) || [];
  for (const b of blocks) {
    const json = b.replace(/^<script[^>]*>/i, '').replace(/<\/script>$/i, '');
    try { collect(JSON.parse(json)); } catch (err) { /* al gemeld door jsonLdParses */ }
  }
  return nodes;
}

// Schema dat alleen in JavaScript staat (document.createElement('script') + JSON.stringify).
// Googlebot rendert JS, maar GPTBot, PerplexityBot en ClaudeBot doen dat niet.
// Dit schema bestaat dus niet voor AI-antwoorden. Zie plan paragraaf 4.3 en 7.
function jsOnlyTypes(html, staticTypes) {
  const alle = new Set((html.match(/"@type"\s*:\s*"([^"]+)"/g) || [])
    .map(function (m) { return m.replace(/.*"([^"]+)"$/, '$1'); }));
  staticTypes.forEach(function (t) { alle.delete(t); });
  return Array.from(alle).sort();
}

// Eisen uit SEO-GEO-plan paragraaf 4.2, per paginatype.
function schemaEisen(url) {
  if (url === '/' || url === '/en/') return ['Organization', 'WebSite', 'LocalBusiness'];
  if (/\/(diensten|services)\//.test(url)) return ['Service', 'Offer'];
  if (/\/blog\/.+/.test(url)) return ['Article', 'author:Person', 'dateModified'];
  if (/^\/(en\/)?(zaandam|koog-aan-de-zaan|wormerveer|krommenie|assendelft|westzaan|zaandijk|oostzaan|wormerland)\//.test(url)) {
    return ['LocalBusiness', 'areaServed'];
  }
  return [];
}

// LocalBusiness en Offer hebben subtypes; die tellen mee.
const LOCAL_BUSINESS = ['LocalBusiness', 'ProfessionalService', 'AccountingService', 'FinancialService'];
const OFFER = ['Offer', 'AggregateOffer'];

function schemaOntbreekt(url, types, nodes) {
  const heeft = new Set(types);
  const mist = [];
  for (const eis of schemaEisen(url)) {
    let ok;
    if (eis === 'LocalBusiness') ok = LOCAL_BUSINESS.some(function (t) { return heeft.has(t); });
    else if (eis === 'Offer') ok = OFFER.some(function (t) { return heeft.has(t); });
    else if (eis === 'author:Person') {
      ok = nodes.some(function (n) {
        const a = n.author;
        if (!a) return false;
        return [].concat(a).some(function (x) { return x && x['@type'] === 'Person'; });
      });
    } else if (eis === 'dateModified' || eis === 'areaServed') {
      ok = nodes.some(function (n) { return n[eis] !== undefined; });
    } else ok = heeft.has(eis);
    if (!ok) mist.push(eis);
  }
  return mist;
}

/* ---------- links ---------- */
function normalize(href, pageUrl) {
  let h = href.trim();
  if (!h) return null;
  if (/^(mailto:|tel:|javascript:|data:|#)/i.test(h)) return null;
  h = h.split('#')[0].split('?')[0];
  if (!h) return null;
  if (/^https?:\/\//i.test(h)) {
    if (h.indexOf(ORIGIN) !== 0) return null;         // extern
    h = h.slice(ORIGIN.length) || '/';
  } else if (h[0] !== '/') {
    // path.posix.resolve gooit de slash aan het eind weg; die moeten we bewaren.
    const slot = h.slice(-1) === '/';
    h = path.posix.resolve(path.posix.dirname(pageUrl + 'x'), h);
    if (slot && h.slice(-1) !== '/') h += '/';
  }
  if (/\/index\.html$/i.test(h)) h = h.replace(/index\.html$/i, '');
  return h;
}

// 'file' = het bestand zelf bestaat, 'dir' = map met index.html, 'none' = 404
function resolveTarget(url) {
  const clean = url.replace(/^\//, '');
  const asFile = path.join(ROOT, clean);
  if (clean && fs.existsSync(asFile) && fs.statSync(asFile).isFile()) return 'file';
  const asDir = path.join(ROOT, clean, 'index.html');
  if (fs.existsSync(asDir) && fs.statSync(asDir).isFile()) return 'dir';
  return 'none';
}

function isAsset(url) { return /\.[a-z0-9]{2,5}$/i.test(url) && !/\.html$/i.test(url); }

/* ---------- crawl ---------- */
const files = walk(ROOT, []).sort();
const pages = [];
const inLinks = new Map();       // url -> aantal interne links erheen
const brokenLinks = [];          // {van, naar}
const slashProblems = [];        // links naar map zonder trailing slash -> 301 op de server

for (const file of files) {
  const url = fileToUrl(file);
  const raw = fs.readFileSync(file, 'utf8');
  const html = stripComments(raw);

  const robots = metaContent(html, 'name', 'robots');
  const h1s = (html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/gi) || [])
    .map(function (h) { return decode(h.replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim(); });

  const hrefs = (html.match(/<a\s[^>]*href=["']([^"']+)["']/gi) || [])
    .map(function (a) { return firstMatch(/href=["']([^"']+)["']/i, a); });

  const outSet = new Set();
  for (const href of hrefs) {
    let t = normalize(href, url);
    if (!t || isAsset(t)) continue;
    const kind = resolveTarget(t);
    if (kind === 'none') {
      brokenLinks.push({ van: url, naar: t });
      continue;
    }
    // Een map-URL zonder slash werkt wel, maar kost een 301. Tel hem op de echte URL.
    if (kind === 'dir' && t.slice(-1) !== '/') {
      slashProblems.push({ van: url, naar: t });
      t += '/';
    }
    outSet.add(t);
  }
  outSet.forEach(function (t) { inLinks.set(t, (inLinks.get(t) || 0) + 1); });

  pages.push({
    url: url,
    status: 200,
    taal: url.indexOf('/en/') === 0 ? 'en' : 'nl',
    title: firstMatch(/<title[^>]*>([\s\S]*?)<\/title>/i, html).replace(/\s+/g, ' '),
    description: metaContent(html, 'name', 'description').replace(/\s+/g, ' '),
    h1: h1s[0] || '',
    h1_aantal: h1s.length,
    wordcount: wordCount(html),
    canonical: firstMatch(/<link[^>]+rel=["']canonical["'][^>]*href=["']([^"']+)["']/i, html),
    robots_meta: robots,
    indexeerbaar: /noindex/i.test(robots) ? 'nee' : 'ja',
    hreflang_aantal: (html.match(/rel=["']alternate["'][^>]*hreflang=/gi) || []).length,
    schema: schemaTypes(html),
    schema_valide: jsonLdParses(html) ? 'ja' : 'nee',
    schema_mist: schemaOntbreekt(url, schemaTypes(html), jsonLdNodes(html)),
    schema_js_only: jsOnlyTypes(html, schemaTypes(html)),
    links_uit: outSet.size,
    bytes: Buffer.byteLength(raw, 'utf8'),
    file: path.relative(ROOT, file).split(path.sep).join('/'),
  });
}

for (const p of pages) p.links_in = inLinks.get(p.url) || 0;

/* ---------- csv ---------- */
const COLS = ['url', 'status', 'taal', 'title', 'title_len', 'description', 'description_len',
  'h1', 'h1_aantal', 'wordcount', 'canonical', 'canonical_ok', 'robots_meta', 'indexeerbaar',
  'hreflang_aantal', 'schema_types', 'schema_valide', 'schema_mist', 'schema_js_only',
  'links_in', 'links_uit', 'bytes', 'file'];

function csvCell(v) {
  const s = String(v === undefined || v === null ? '' : v);
  return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

const rows = pages.map(function (p) {
  p.canonical_ok = p.canonical === ORIGIN + p.url ? 'ja' : 'nee';
  return [p.url, p.status, p.taal, p.title, p.title.length, p.description, p.description.length,
    p.h1, p.h1_aantal, p.wordcount, p.canonical, p.canonical_ok, p.robots_meta, p.indexeerbaar,
    p.hreflang_aantal, p.schema.join('|'), p.schema_valide, p.schema_mist.join('|'),
    p.schema_js_only.join('|'), p.links_in, p.links_uit, p.bytes, p.file]
    .map(csvCell).join(',');
});

fs.mkdirSync(path.join(ROOT, 'data'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'data', 'crawl.csv'), COLS.join(',') + '\n' + rows.join('\n') + '\n', 'utf8');

/* ---------- bevindingen ---------- */
const dun = pages.filter(function (p) { return p.wordcount < DUN_WOORDEN; }).sort(function (a, b) { return a.wordcount - b.wordcount; });
const wees = pages.filter(function (p) { return p.links_in === 0 && p.url !== '/'; });
const geenTitle = pages.filter(function (p) { return !p.title; });
const geenDesc = pages.filter(function (p) { return !p.description; });
const titleLang = pages.filter(function (p) { return p.title && (p.title.length > TITLE_MAX || p.title.length < TITLE_MIN); });
const descLang = pages.filter(function (p) { return p.description && (p.description.length > DESC_MAX || p.description.length < DESC_MIN); });
const h1Fout = pages.filter(function (p) { return p.h1_aantal !== 1; });
const canonFout = pages.filter(function (p) { return p.canonical_ok === 'nee'; });
const schemaKapot = pages.filter(function (p) { return p.schema_valide === 'nee'; });
const geenSchema = pages.filter(function (p) { return p.schema.length === 0; });
const schemaGat = pages.filter(function (p) { return p.schema_mist.length > 0; });
const schemaJs = pages.filter(function (p) { return p.schema_js_only.length > 0; });
const geenHreflang = pages.filter(function (p) { return p.hreflang_aantal === 0; });
const weinigUit = pages.filter(function (p) { return p.links_uit < 5; });
// Nav en footer staan op elke pagina; alles daarbuiten leunt op redactionele links.
const weinigIn = pages.filter(function (p) { return p.links_in > 0 && p.links_in < IN_LINK_MIN; })
  .sort(function (a, b) { return a.links_in - b.links_in || b.wordcount - a.wordcount; });

function dupes(key) {
  const m = new Map();
  pages.forEach(function (p) {
    const v = (p[key] || '').toLowerCase();
    if (!v) return;
    if (!m.has(v)) m.set(v, []);
    m.get(v).push(p.url);
  });
  return Array.from(m.entries()).filter(function (e) { return e[1].length > 1; });
}
const dupTitles = dupes('title');
const dupDescs = dupes('description');
const dupH1 = dupes('h1');

/* ---------- rapport ---------- */
function tbl(head, rows2) {
  if (!rows2.length) return '_Geen._\n';
  return '| ' + head.join(' | ') + ' |\n| ' + head.map(function () { return '---'; }).join(' | ') + ' |\n' +
    rows2.map(function (r) { return '| ' + r.map(function (c) { return String(c).replace(/\|/g, '\\|'); }).join(' | ') + ' |'; }).join('\n') + '\n';
}

const nu = new Date().toISOString().slice(0, 10);
const totWoorden = pages.reduce(function (s, p) { return s + p.wordcount; }, 0);

let md = '';
md += '# Crawl-audit — belastinghulpzaanstad.nl\n\n';
md += 'Gegenereerd: ' + nu + ' · `node scripts/crawl-audit.js` · bron: lokale bestanden, geen live server.\n\n';
md += '## Samenvatting\n\n';
md += tbl(['Metric', 'Waarde'], [
  ['Pagina\'s gecrawld', pages.length],
  ['Waarvan NL / EN', pages.filter(function (p) { return p.taal === 'nl'; }).length + ' / ' + pages.filter(function (p) { return p.taal === 'en'; }).length],
  ['Indexeerbaar', pages.filter(function (p) { return p.indexeerbaar === 'ja'; }).length],
  ['Totaal woorden', totWoorden.toLocaleString('nl-NL')],
  ['Gemiddeld woorden/pagina', Math.round(totWoorden / pages.length)],
  ['Dunne pagina\'s (<' + DUN_WOORDEN + ' w)', dun.length],
  ['Weespagina\'s (0 interne links in)', wees.length],
  ['Pagina\'s met <' + IN_LINK_MIN + ' interne in-links', weinigIn.length],
  ['Gebroken interne links', brokenLinks.length],
  ['Links zonder trailing slash (301)', slashProblems.length],
  ['Dubbele titles', dupTitles.length],
  ['Ongeldige JSON-LD', schemaKapot.length],
  ['Pagina\'s met schema-gat (§4.2)', schemaGat.length],
  ['Schema alleen in JavaScript', schemaJs.length],
]);

md += '\n## Problemen, gesorteerd op impact\n';

let secNr = 0;
function sec(titel, aantal, uitleg, head, rows2) {
  secNr += 1;
  md += '\n### ' + secNr + '. ' + titel + ' (' + aantal + ')\n';
  if (uitleg) md += uitleg + '\n';
  md += '\n' + tbl(head, rows2);
}

sec('Schema staat alleen in JavaScript', schemaJs.length,
  'Deze pagina\'s bouwen hun JSON-LD pas in de browser met `document.createElement`. ' +
  'Googlebot rendert JavaScript, maar GPTBot, OAI-SearchBot, PerplexityBot en ClaudeBot niet. ' +
  'Voor AI-antwoorden bestaat dit schema dus niet. Zet het als vaste `<script type="application/ld+json">` in de HTML.',
  ['URL', 'Types die alleen in JS staan'], schemaJs.map(function (p) { return [p.url, p.schema_js_only.join(', ')]; }));

sec('Gebroken interne links', brokenLinks.length,
  'Deze links geven een 404. Ze verspillen crawlbudget en breken de gebruikersreis.',
  ['Op pagina', 'Link naar'], brokenLinks.map(function (b) { return [b.van, b.naar]; }));

sec('Weespagina\'s', wees.length,
  'Geen enkele interne link wijst hierheen. Zonder interne links krijgt de pagina bijna geen autoriteit.',
  ['URL', 'Woorden', 'Links uit'], wees.map(function (p) { return [p.url, p.wordcount, p.links_uit]; }));

sec('Pagina\'s met minder dan ' + IN_LINK_MIN + ' interne in-links', weinigIn.length,
  'Nav en footer staan op elke pagina. Wat daar niet in staat, moet het van redactionele links hebben. ' +
  'Deze pagina\'s krijgen die nu bijna niet, dus blijven ze laag ranken.',
  ['URL', 'Links in', 'Woorden'], weinigIn.map(function (p) { return [p.url, p.links_in, p.wordcount]; }));

sec('Dunne pagina\'s, minder dan ' + DUN_WOORDEN + ' woorden', dun.length,
  'Te weinig inhoud om op een concurrerend keyword te ranken. Uitbreiden of samenvoegen.',
  ['URL', 'Woorden', 'Links in'], dun.map(function (p) { return [p.url, p.wordcount, p.links_in]; }));

sec('Dubbele titles', dupTitles.length,
  'Google kiest dan zelf welke pagina hij toont. Dat kost posities.',
  ['Title', 'URL\'s'], dupTitles.map(function (e) { return [e[0].slice(0, 70), e[1].join('<br>')]; }));

sec('Dubbele meta descriptions', dupDescs.length, '',
  ['Description', 'URL\'s'], dupDescs.map(function (e) { return [e[0].slice(0, 70) + '…', e[1].join('<br>')]; }));

sec('Dubbele H1\'s', dupH1.length, '',
  ['H1', 'URL\'s'], dupH1.map(function (e) { return [e[0].slice(0, 70), e[1].join('<br>')]; }));

sec('H1-problemen', h1Fout.length,
  'Elke pagina heeft precies één H1 nodig.',
  ['URL', 'Aantal H1'], h1Fout.map(function (p) { return [p.url, p.h1_aantal]; }));

sec('Titles buiten ' + TITLE_MIN + '-' + TITLE_MAX + ' tekens', titleLang.length,
  'Te lang = afgekapt in de SERP. Te kort = ongebruikte ruimte.',
  ['URL', 'Len', 'Title'], titleLang.map(function (p) { return [p.url, p.title.length, p.title.slice(0, 75)]; }));

sec('Meta descriptions buiten ' + DESC_MIN + '-' + DESC_MAX + ' tekens', descLang.length + geenDesc.length, '',
  ['URL', 'Len'], geenDesc.map(function (p) { return [p.url, 'ONTBREEKT']; })
    .concat(descLang.map(function (p) { return [p.url, p.description.length]; })));

sec('Canonical wijst niet naar de eigen URL', canonFout.length, '',
  ['URL', 'Canonical'], canonFout.map(function (p) { return [p.url, p.canonical || 'ONTBREEKT']; }));

sec('Ongeldige of ontbrekende JSON-LD', schemaKapot.length + geenSchema.length, '',
  ['URL', 'Probleem'], schemaKapot.map(function (p) { return [p.url, 'JSON-LD parst niet']; })
    .concat(geenSchema.map(function (p) { return [p.url, 'geen schema']; })));

sec('Schema-gaten t.o.v. plan §4.2', schemaGat.length,
  'Verplichte schema-velden per paginatype die nog ontbreken. Dit telt dubbel: rich results én GEO.',
  ['URL', 'Ontbreekt'], schemaGat.map(function (p) { return [p.url, p.schema_mist.join(', ')]; }));

sec('Interne links zonder trailing slash', slashProblems.length,
  'De server stuurt hier een 301. Dat is een redirect-hop die je gratis kunt weghalen.',
  ['Op pagina', 'Link naar'], slashProblems.slice(0, 50).map(function (b) { return [b.van, b.naar]; }));

sec('Pagina\'s met weinig uitgaande interne links', weinigUit.length,
  'Minder dan 5 interne links. Dat remt de doorstroom van autoriteit naar de pillars.',
  ['URL', 'Links uit'], weinigUit.map(function (p) { return [p.url, p.links_uit]; }));

sec('Pagina\'s zonder hreflang', geenHreflang.length,
  'De site heeft een NL- en een EN-versie. Zonder hreflang concurreren die met elkaar.',
  ['URL'], geenHreflang.map(function (p) { return [p.url]; }));

md += '\n## Zwaarste pagina\'s (bytes HTML)\n';
md += 'Laadtijd meet je niet vanaf schijf. Paginagewicht is de beste lokale indicatie.\n\n';
md += tbl(['URL', 'KB'], pages.slice().sort(function (a, b) { return b.bytes - a.bytes; }).slice(0, 10)
  .map(function (p) { return [p.url, Math.round(p.bytes / 1024)]; }));

md += '\n## Best gelinkte pagina\'s\n\n';
md += tbl(['URL', 'Links in'], pages.slice().sort(function (a, b) { return b.links_in - a.links_in; }).slice(0, 15)
  .map(function (p) { return [p.url, p.links_in]; }));

md += '\n---\n\nRuwe data: `data/crawl.csv`\n';

fs.mkdirSync(path.join(ROOT, 'reports'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'reports', 'crawl-audit.md'), md, 'utf8');

console.log('OK  ' + pages.length + ' pagina\'s -> data/crawl.csv + reports/crawl-audit.md');
console.log('    dun:' + dun.length + ' wees:' + wees.length + ' 404:' + brokenLinks.length +
  ' dupTitle:' + dupTitles.length + ' slash301:' + slashProblems.length);
