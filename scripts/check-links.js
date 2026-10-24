#!/usr/bin/env node
/*
 * check-links.js
 * Interne links inclusief ankers, geldigheid van de JSON-LD, en de lengte van
 * titles en meta descriptions. Faalt met exitcode 1 bij een probleem.
 *
 * WAAROM
 * crawl-audit.js telt 404's en dubbele titels, maar kijkt niet of een #anker
 * bestaat op de pagina waarnaar het wijst. Dat is geen theoretisch risico: de
 * homepage linkte een tijd naar /contact/#terugbellen terwijl dat formulier op
 * de homepage zelf staat, en bij het schrappen van een sectie verdwijnt een id
 * zonder dat iets erover valt. Dit script loopt elke <a href> na, ook de
 * relatieve, en meldt zowel een ontbrekend bestand als een dood anker.
 *
 * De JSON-LD- en lengtecontrole zitten erbij omdat ze uit dezelfde bestanden
 * komen en anders drie keer worden ingelezen.
 *
 * GEBRUIK
 *   node scripts/check-links.js .
 *
 * GRENZEN
 * 60 tekens voor een title, 155 voor een description. Pagina's met noindex
 * doen niet mee: de vangnetstubs hebben met opzet een korte tekst.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const BASIS = 'https://belastinghulpzaanstad.nl';
const MAX_TITLE = 60;
const MAX_DESC = 155;

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'intern') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}

const files = walk(ROOT, []);
const rel = (f) => path.relative(ROOT, f).split(path.sep).join('/');

/* ---------- alle id's per pagina verzamelen ---------- */
const ids = new Map();
for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  const set = new Set();
  const re = /\sid="([^"]+)"/g;
  let m;
  while ((m = re.exec(s)) !== null) set.add(m[1]);
  /* een naam-anker telt ook */
  const re2 = /<a\s[^>]*name="([^"]+)"/g;
  while ((m = re2.exec(s)) !== null) set.add(m[1]);
  ids.set('/' + rel(f).replace(/index\.html$/, ''), set);
}

/* ---------- links nalopen ---------- */
let kapot = 0, ankerFout = 0, gecontroleerd = 0;
for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  const mapVanBestand = '/' + path.dirname(rel(f)) + '/';
  const eigenUrl = '/' + rel(f).replace(/index\.html$/, '');

  const re = /<a\s[^>]*href="([^"]+)"/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    let href = m[1];
    if (/^(mailto:|tel:|javascript:|data:)/i.test(href)) continue;
    if (href.startsWith('http') && !href.startsWith(BASIS)) continue;
    if (href.startsWith(BASIS)) href = href.slice(BASIS.length) || '/';
    if (href.startsWith('//')) continue;

    let [pad, anker] = href.split('#');
    if (pad === '') pad = eigenUrl;              /* alleen een anker */
    else if (!pad.startsWith('/')) {             /* relatief pad */
      pad = path.posix.normalize(mapVanBestand + pad);
    }
    if (!pad.endsWith('/') && !pad.match(/\.[a-z0-9]+$/i)) pad += '/';
    gecontroleerd++;

    /* bestaat het doel? */
    const isBestand = pad.match(/\.[a-z0-9]+$/i);
    const doel = isBestand
      ? path.join(ROOT, pad.replace(/^\//, ''))
      : path.join(ROOT, pad.replace(/^\//, ''), 'index.html');
    if (!fs.existsSync(doel)) {
      console.log('KAPOT   ' + rel(f) + '  -> ' + href);
      kapot++;
      continue;
    }
    /* bestaat het anker? */
    if (anker && !isBestand) {
      const set = ids.get(pad);
      if (set && !set.has(anker)) {
        console.log('ANKER   ' + rel(f) + '  -> ' + href + '  (#' + anker + ' bestaat niet op die pagina)');
        ankerFout++;
      }
    }
  }
}

/* ---------- JSON-LD ---------- */
let ldFout = 0, ldTotaal = 0;
for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  const blokken = s.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g) || [];
  for (const b of blokken) {
    ldTotaal++;
    const body = b.replace(/^<script[^>]*>/, '').replace(/<\/script>$/, '');
    try { JSON.parse(body); } catch (e) {
      console.log('JSON-LD ' + rel(f) + ': ' + e.message.slice(0, 70));
      ldFout++;
    }
  }
}

/* ---------- titles en descriptions ---------- */
let teLang = 0, ontbreekt = 0;
for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  if (s.indexOf('name="robots" content="noindex') !== -1) continue;
  const t = (s.match(/<title>([^<]*)<\/title>/) || [])[1];
  const d = (s.match(/<meta name="description" content="([^"]*)"/) || [])[1];
  if (!t) { console.log('GEEN TITLE  ' + rel(f)); ontbreekt++; }
  if (!d) { console.log('GEEN DESCR  ' + rel(f)); ontbreekt++; }
  if (t && t.length > MAX_TITLE) { console.log('TITLE ' + t.length + '  ' + rel(f) + '  ' + t); teLang++; }
  if (d && d.length > MAX_DESC) { console.log('DESCR ' + d.length + '  ' + rel(f)); teLang++; }
}

console.log('\n--- check-links ---');
console.log('bestanden            : ' + files.length);
console.log('interne links        : ' + gecontroleerd + ', kapot: ' + kapot + ', dood anker: ' + ankerFout);
console.log('JSON-LD-blokken      : ' + ldTotaal + ', ongeldig: ' + ldFout);
console.log('title/descr te lang  : ' + teLang + ', ontbrekend: ' + ontbreekt);
process.exit(kapot + ankerFout + ldFout + teLang + ontbreekt ? 1 : 0);
