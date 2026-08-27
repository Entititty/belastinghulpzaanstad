#!/usr/bin/env node
/*
 * check-contrast.js
 * Toetst kleurcontrast op ALLE plekken waar deze site kleur zet, niet
 * alleen in de stylesheet. Dat onderscheid is de hele reden dat dit
 * script bestaat: eerdere controles keken naar belasting.css en misten
 * daardoor drie andere oppervlakken.
 *
 * De vier oppervlakken:
 *   1. belasting.css                 de bron
 *   2. belasting.<hash>.min.css      wat de bezoeker krijgt
 *   3. <style> in index.html         de NL-homepage draagt zijn CSS inline
 *   4. <style> in en/index.html      de EN-homepage ook
 * En daarnaast:
 *   5. style="..." attributen        op alle 94 pagina's
 *   6. #hex in js/*.js               banners die JS zelf opbouwt
 *
 * Norm: WCAG 2.1 AA, 1.4.3. Normale tekst 4,5:1. Grote tekst 3:1, en
 * groot betekent >= 24 px, of >= 18,66 px als de tekst vet is.
 *
 * HOE DE ACHTERGROND WORDT BEPAALD
 * Voor elk style-attribuut met een tekstkleur zoekt het script de
 * dichtstbijzijnde voorouder die zelf een achtergrond zet, door de
 * openstaande tags bij te houden. Staat er een gradient, dan wordt tegen
 * elke kleurstop getoetst en telt de slechtste. Vindt het script geen
 * voorouder met een achtergrond, dan geldt de paginakleur.
 *
 * WAT DIT SCRIPT NIET KAN
 * Achtergronden die uit een class in de stylesheet komen, ziet het niet.
 * Een tekstkleur die lichter is dan alle kandidaat-achtergronden wordt
 * daarom geteld en niet afgekeurd: die staat vrijwel zeker op een donker
 * vlak dat via een class is gezet.
 * Schaduwen, tinten en randen worden niet afgekeurd: 1.4.3 geldt voor
 * tekst. Een rand van een knop valt onder 1.4.11 (3:1) en dat toetst dit
 * script niet.
 *
 * DODE CSS
 * De .testimonial-regels halen de eis niet, maar geen enkele pagina
 * gebruikt die classes. Dat is een uitzondering die zichzelf opheft: komt
 * .testimonial ooit weer in de markup, dan vervalt de uitzondering en
 * slaat het script alsnog af.
 *
 * Gebruik:
 *   node scripts/check-contrast.js
 *   node scripts/check-contrast.js --alles     ook de geslaagde kleuren
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ALLES = process.argv.indexOf('--alles') !== -1;
const PAGINA = '#faf8f4';          // --clr-cream

/* ---------- contrast ---------- */
function lum(hex) {
  const h = hex.replace('#', '');
  const paren = h.length === 3 ? h.split('').map(c => c + c) : h.slice(0, 6).match(/../g);
  const c = paren.map(x => parseInt(x, 16) / 255)
    .map(v => v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
function ratio(a, b) {
  const x = lum(a), y = lum(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}
function naarHex(w) {
  if (/^#/.test(w)) return w.slice(0, 7);
  const namen = { white: '#ffffff', black: '#000000' };
  return namen[w.toLowerCase()] || null;
}

/* ---------- bestanden ---------- */
function walk(dir, filter, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      walk(path.join(dir, e.name), filter, acc);
    } else if (filter(e.name)) acc.push(path.join(dir, e.name));
  }
  return acc;
}
const rel = f => path.relative(ROOT, f).split(path.sep).join('/');
const paginas = walk(ROOT, n => n === 'index.html', []);

function inlineCss(file) {
  const s = fs.readFileSync(file, 'utf8');
  let c = '';
  for (const m of s.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) c += m[1];
  return c;
}
function zonderCssEnJs(s) {
  // vervang door spaties, zodat posities blijven kloppen
  return s.replace(/<style[^>]*>[\s\S]*?<\/style>/g, m => ' '.repeat(m.length))
    .replace(/<script[\s\S]*?<\/script>/g, m => ' '.repeat(m.length))
    .replace(/<!--[\s\S]*?-->/g, m => ' '.repeat(m.length));
}

/* ---------- maat en gewicht ---------- */
function pixels(st) {
  const m = st.match(/font-size\s*:\s*([0-9.]+)\s*(rem|px|em)/i);
  if (!m) return null;
  return m[2].toLowerCase() === 'px' ? parseFloat(m[1]) : parseFloat(m[1]) * 16;
}
function isVet(st) {
  const m = st.match(/font-weight\s*:\s*([0-9]+|bold)/i);
  return !!m && (m[1] === 'bold' || parseInt(m[1], 10) >= 700);
}
function eis(st) {
  const p = pixels(st);
  if (p !== null && (p >= 24 || (isVet(st) && p >= 18.66))) return 3;
  return 4.5;
}

/* ---------- achtergrond uit de voorouders ----------
 * Simpele tag-stack. De pagina's zijn gegenereerd en de tags zijn in
 * balans (crawl-audit.js controleert dat), dus dit is betrouwbaar genoeg
 * om de dichtstbijzijnde achtergrond te vinden. */
const LEEG = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr']);

function stops(st) {
  const m = st.match(/background(?:-color|-image)?\s*:\s*([^;]+)/i);
  if (!m) return null;
  const hexen = m[1].match(/#[0-9a-f]{3,8}/gi);
  return hexen && hexen.length ? hexen.map(h => h.slice(0, 7)) : null;
}

/* levert per style-attribuut de lijst kandidaat-achtergronden */
function metAchtergrond(html) {
  const uit = [];
  const stapel = [];
  const re = /<(\/?)([a-z0-9]+)([^>]*)>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const sluit = m[1] === '/';
    const tag = m[2].toLowerCase();
    const attr = m[3];

    if (sluit) {
      for (let i = stapel.length - 1; i >= 0; i--) {
        if (stapel[i].tag === tag) { stapel.length = i; break; }
      }
      continue;
    }

    const style = (attr.match(/style="([^"]*)"/i) || [])[1] || '';
    const eigen = style ? stops(style) : null;

    if (style && /(?:^|;|\s)color\s*:/i.test(style)) {
      // dichtstbijzijnde achtergrond: eerst het element zelf, dan omhoog
      let bg = eigen;
      if (!bg) for (let i = stapel.length - 1; i >= 0 && !bg; i--) bg = stapel[i].bg;
      uit.push({ style, bg: bg });
    }

    const zelfsluitend = /\/\s*$/.test(attr) || LEEG.has(tag);
    if (!zelfsluitend) stapel.push({ tag, bg: eigen });
  }
  return uit;
}

const fouten = [];
const geslaagd = [];
let getoetst = 0;

/* ============ 1-4. de stylesheets en de inline CSS ============ */
const min = fs.readdirSync(ROOT).filter(f => /^belasting\.[0-9a-f]{8}\.min\.css$/.test(f))[0];
const vlakken = [
  ['belasting.css', fs.readFileSync(path.join(ROOT, 'belasting.css'), 'utf8')],
  [min || '(geen gehashte stylesheet)', min ? fs.readFileSync(path.join(ROOT, min), 'utf8') : ''],
  ['index.html <style>', inlineCss(path.join(ROOT, 'index.html'))],
  ['en/index.html <style>', inlineCss(path.join(ROOT, 'en', 'index.html'))]
];

/* dode selectors: de uitzondering geldt alleen zolang de markup ze niet
 * gebruikt. Zodra dat verandert, valt de uitzondering weg. */
const DOOD = ['.testimonial'];
const dodeSelectors = DOOD.filter(function (sel) {
  const klasse = sel.replace('.', '');
  for (const f of paginas) {
    const markup = zonderCssEnJs(fs.readFileSync(f, 'utf8'));
    if (markup.indexOf(klasse) !== -1) return false;   // toch in gebruik
  }
  return true;
});
let overgeslagenDood = 0;

for (const [naam, css] of vlakken) {
  if (!css) continue;
  const vars = {};
  for (const m of css.matchAll(/(--[a-z0-9-]+)\s*:\s*(#[0-9a-f]{3,8})\s*[;}]/gi)) vars[m[1]] = m[2];

  // alleen echte color:, dus niet border-color of background-color
  for (const m of css.matchAll(/(?:^|[;{}\s])color\s*:\s*(#[0-9a-f]{3,8}|var\((--[a-z0-9-]+)\))/gi)) {
    let hex = m[1].startsWith('var(') ? vars[m[2]] : m[1];
    if (!hex) continue;
    hex = hex.slice(0, 7);
    if (lum(hex) > lum(PAGINA)) continue;          // staat op een donker vlak
    const regel = css.slice(css.lastIndexOf('}', m.index) + 1, css.indexOf('}', m.index) + 1).replace(/\s+/g, ' ').trim();
    if (dodeSelectors.some(sel => regel.indexOf(sel) !== -1)) { overgeslagenDood++; continue; }
    getoetst++;
    const r = ratio(hex, PAGINA);
    const rij = { waar: naam, wat: hex + ' op de paginakleur', r, eis: 4.5, detail: regel.slice(0, 100) };
    (r < 4.5 ? fouten : geslaagd).push(rij);
  }
}

/* ============ 5. inline style-attributen ============ */
let opDonkerViaClass = 0;

for (const f of paginas) {
  const s = zonderCssEnJs(fs.readFileSync(f, 'utf8'));

  for (const item of metAchtergrond(s)) {
    const st = item.style;
    const fg = naarHex(((st.match(/(?:^|;|\s)color\s*:\s*(#[0-9a-f]{3,8}|white|black)/i) || [])[1]) || '');
    if (!fg) continue;

    const nodig = eis(st);
    const gevonden = !!(item.bg && item.bg.length);
    const kandidaten = gevonden ? item.bg : [PAGINA];

    /* Alleen overslaan als er GEEN achtergrond te vinden was en de tekst
     * lichter is dan de pagina: dan staat hij op een donker vlak dat via
     * een class is gezet en valt er niets te meten. Is de achtergrond wel
     * gevonden, dan wordt er altijd getoetst, ook lichte tekst op donker. */
    if (!gevonden && lum(fg) > lum(PAGINA)) { opDonkerViaClass++; continue; }

    // slechtste kleurstop telt
    let slechtste = Infinity, tegen = kandidaten[0];
    for (const b of kandidaten) {
      const r = ratio(fg, b);
      if (r < slechtste) { slechtste = r; tegen = b; }
    }
    getoetst++;
    const waarop = tegen === PAGINA ? 'de paginakleur' : tegen +
      (kandidaten.length > 1 ? ' (slechtste stop van ' + kandidaten.length + ')' : '');
    (slechtste < nodig ? fouten : geslaagd).push({
      waar: rel(f), wat: fg + ' op ' + waarop, r: slechtste, eis: nodig, detail: st.slice(0, 90)
    });
  }
}

/* ============ 6. kleuren in JS ============ */
for (const f of walk(path.join(ROOT, 'js'), n => /\.js$/.test(n), [])) {
  const s = fs.readFileSync(f, 'utf8');
  for (const m of s.matchAll(/(?:^|[;{'"\s])color\s*:\s*(#[0-9a-f]{3,8})/gi)) {
    const hex = m[1].slice(0, 7);
    if (lum(hex) > lum(PAGINA)) continue;
    getoetst++;
    const r = ratio(hex, PAGINA);
    (r < 4.5 ? fouten : geslaagd).push({ waar: rel(f), wat: hex + ' op de paginakleur', r, eis: 4.5, detail: 'kleur in een JS-string' });
  }
}

/* ---------- uitvoer ---------- */
function samenvatten(lijst) {
  const groep = {};
  for (const x of lijst) {
    const k = x.wat + ' | ' + (isNaN(x.r) ? 'n.v.t.' : x.r.toFixed(2) + ':1 tegen eis ' + x.eis);
    groep[k] = groep[k] || { n: 0, plekken: new Set(), detail: x.detail };
    groep[k].n++; groep[k].plekken.add(x.waar);
  }
  return Object.keys(groep).sort((a, b) => groep[b].n - groep[a].n)
    .map(k => ({ k, n: groep[k].n, plekken: groep[k].plekken, detail: groep[k].detail }));
}

console.log('contrastcontrole, WCAG 2.1 AA (1.4.3)');
console.log('  paginakleur      : ' + PAGINA);
console.log('  oppervlakken     : 2 stylesheets, 2x inline CSS, ' + paginas.length + ' pagina\'s met style-attributen, js/');
console.log('  toetsingen       : ' + getoetst);
console.log('  niet te toetsen  : ' + opDonkerViaClass + ' lichte tekst op een achtergrond uit een class');
console.log('  overgeslagen     : ' + overgeslagenDood + ' regel(s) van dode selectors ' +
  (dodeSelectors.length ? '(' + dodeSelectors.join(', ') + ', nergens in de markup)' : '(geen)'));
console.log('');

if (ALLES) {
  console.log('=== haalt de eis ===');
  samenvatten(geslaagd).forEach(g => console.log('  ' + String(g.n).padStart(4) + 'x  ' + g.k));
  console.log('');
}

if (!fouten.length) {
  console.log('OK: geen enkele tekstkleur zakt door de eis.');
  process.exit(0);
}

console.log('=== ZAKT DOOR DE EIS ===');
for (const g of samenvatten(fouten)) {
  console.log('  ' + String(g.n).padStart(4) + 'x op ' + String(g.plekken.size).padStart(3) + ' plek(ken)  ' + g.k);
  console.log('        ' + g.detail);
  const eerste = [...g.plekken].slice(0, 3);
  console.log('        bv. ' + eerste.join(', ') + (g.plekken.size > 3 ? ', ...' : ''));
}
console.log('\nFOUT: ' + fouten.length + ' toetsing(en) onder de eis.');
process.exit(1);
