#!/usr/bin/env node
/*
 * minify-css.js
 * Maakt belasting.<hash>.min.css uit belasting.css. Daarna zet hash-css.js de
 * nieuwe hash in de naam en in de HTML; bouw.js draait ze in die volgorde.
 *
 * WAAROM
 * Tot oktober 2026 werd elke CSS-wijziging met de hand in twee bestanden gezet:
 * de leesbare bron en het geminificeerde bestand dat de bezoeker krijgt. Die
 * twee konden ongemerkt uit elkaar lopen. Nu is de bron leidend en controleert
 * --check dat het .min.css-bestand er precies uit volgt.
 *
 * WAT HET DOET (en bewust niet meer)
 * Alleen commentaar en overbodige witruimte eruit. Strings, url() en de
 * spaties rond + en - in calc() blijven staan; een spatie voor een : in een
 * selector ook (".a :hover" is iets anders dan ".a:hover"). Geen kleuren of
 * getallen inkorten: dat scheelt na gzip bijna niets en kan alleen fout gaan.
 * Elke regel op een eigen regel, zodat een diff leesbaar blijft.
 *
 * GEBRUIK
 *   node scripts/minify-css.js           schrijft het .min.css-bestand
 *   node scripts/minify-css.js --check   schrijft niets; faalt als het afwijkt
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BRON = path.join(ROOT, 'belasting.css');
const CHECK = process.argv.includes('--check');

/* ---------- in stukken hakken ----------
 * str: een string, letterlijk; ws: witruimte of commentaar; p: een teken met
 * betekenis; t: de rest (namen, getallen, url( zonder aanhalingstekens). */
function stukken(css) {
  const uit = [];
  let i = 0;
  while (i < css.length) {
    const c = css[i];
    if (c === '/' && css[i + 1] === '*') {
      const eind = css.indexOf('*/', i + 2);
      if (eind < 0) throw new Error('commentaar zonder einde bij teken ' + i);
      uit.push({ s: 'ws' });
      i = eind + 2;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < css.length && css[j] !== c) j += css[j] === '\\' ? 2 : 1;
      if (j >= css.length) throw new Error('string zonder einde bij teken ' + i);
      uit.push({ s: 'str', v: css.slice(i, j + 1) });
      i = j + 1;
    } else if (/\s/.test(c)) {
      while (i < css.length && /\s/.test(css[i])) i++;
      uit.push({ s: 'ws' });
    } else if ('{};:,>+~()!'.includes(c)) {
      uit.push({ s: 'p', v: c });
      i++;
    } else {
      let j = i;
      while (j < css.length && !/[\s{};:,>+~()!"']/.test(css[j]) && !(css[j] === '/' && css[j + 1] === '*')) j += css[j] === '\\' ? 2 : 1;
      let v = css.slice(i, j);
      // url( zonder aanhalingstekens: alles tot de ) letterlijk
      if (/^url$/i.test(v) && css[j] === '(' && !/["']/.test(css[j + 1])) {
        const eind = css.indexOf(')', j);
        v = css.slice(i, eind + 1);
        j = eind + 1;
      }
      uit.push({ s: 't', v });
      i = j;
    }
  }
  return uit;
}

/* ---------- opnieuw opbouwen ----------
 * Een blok is "regels" (bovenaan, in @media, @supports, @keyframes) of
 * "declaraties" (na een selector, in @font-face). In een kop (selector of
 * @media-voorwaarde) gelden andere spatieregels dan in een declaratie. */
const BLOK_MET_REGELS = /^@(media|supports|keyframes|-webkit-keyframes|layer|container|document)\b/i;

function minify(css) {
  const s = stukken(css);
  let uit = '';
  const stapel = ['regels'];
  let kop = '';            // de kop die nu wordt gelezen (in een regels-blok)
  let kopStrings = [];     // strings in de kop, zodat de spatieregels er niet aan komen
  let decl = '';           // de declaraties van het huidige blok
  let haakjes = 0;

  const ruimteWeg = (v) => v.replace(/\s+/g, ' ').trim();

  function kopKlaar(k) {
    // spaties rond , > + ~ weg; na ( en voor ) weg. Strings staan er als
    // \u0000n\u0000 in en komen pas aan het eind terug.
    const klaar = ruimteWeg(k)
      .replace(/ ?([,>+~]) ?/g, '$1')
      .replace(/\( /g, '(').replace(/ \)/g, ')')
      .replace(/\u0000(\d+)\u0000/g, (h, n) => kopStrings[n]);
    kopStrings = [];
    return klaar;
  }

  for (let i = 0; i < s.length; i++) {
    const x = s[i];
    const soort = stapel[stapel.length - 1];
    if (soort === 'regels') {
      if (x.s === 'p' && x.v === '{') {
        const k = kopKlaar(kop);
        uit += k + '{';
        stapel.push(BLOK_MET_REGELS.test(k) ? 'regels' : 'declaraties');
        kop = '';
        continue;
      }
      if (x.s === 'p' && x.v === '}') {
        if (ruimteWeg(kop)) throw new Error('kop zonder blok: ' + ruimteWeg(kop));
        stapel.pop();
        uit += '}' + (stapel.length === 1 ? '\n' : '');
        continue;
      }
      if (x.s === 'p' && x.v === ';') {        // @charset, @import
        uit += kopKlaar(kop) + ';' + (stapel.length === 1 ? '\n' : '');
        kop = '';
        continue;
      }
      if (x.s === 'ws') { kop += ' '; continue; }
      if (x.s === 'str') { kop += '\u0000' + kopStrings.length + '\u0000'; kopStrings.push(x.v); continue; }
      if (x.s === 'p' && x.v === '(') haakjes++;
      if (x.s === 'p' && x.v === ')') haakjes--;
      if (x.s === 'p' && x.v === ':' && haakjes > 0 && /^\s*@/.test(kop)) {
        // alleen in een @media-voorwaarde: "(max-width: 600px)" -> "(max-width:600px)".
        // In een selector blijft het staan: ":is(.a :hover)" is iets anders.
        kop = kop.replace(/ $/, '') + ':';
        while (s[i + 1] && s[i + 1].s === 'ws') i++;
        continue;
      }
      kop += x.v;
    } else {
      // declaraties: tot de } van dit blok
      if (x.s === 'p' && x.v === '}') {
        uit += declaratiesKlaar(decl) + '}';
        decl = '';
        stapel.pop();
        if (stapel.length === 1) uit += '\n';
        continue;
      }
      if (x.s === 'p' && x.v === '{') throw new Error('geneste blokken in declaraties worden niet ondersteund');
      decl += x.s === 'ws' ? ' ' : x.v;
    }
  }
  if (stapel.length !== 1) throw new Error('blok zonder }');
  if (ruimteWeg(kop)) throw new Error('tekst na de laatste regel: ' + ruimteWeg(kop));
  return uit;
}

/* Declaraties: "prop : waarde ; ..." -> "prop:waarde;..." zonder de laatste ;
 * Strings zijn hier al weer letterlijke tekst; daarom eerst opknippen op ; en :
 * buiten strings en haakjes. */
function splits(tekst, teken) {
  const delen = [];
  let diep = 0, q = null, start = 0;
  for (let i = 0; i < tekst.length; i++) {
    const c = tekst[i];
    if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '(') diep++;
    else if (c === ')') diep--;
    else if (c === teken && diep === 0) { delen.push(tekst.slice(start, i)); start = i + 1; if (teken === ':') break; }
  }
  delen.push(tekst.slice(start));
  return delen;
}

function waardeKlaar(w) {
  // buiten strings: witruimte samenvoegen, spaties rond , weg, na ( en voor ) weg, voor ! weg
  let uit = '', q = null, buf = '';
  const spoel = () => {
    uit += buf.replace(/\s+/g, ' ').replace(/ ?, ?/g, ',').replace(/\( /g, '(').replace(/ \)/g, ')').replace(/ !/g, '!').replace(/! /g, '!');
    buf = '';
  };
  for (let i = 0; i < w.length; i++) {
    const c = w[i];
    if (q) { uit += c; if (c === '\\') { uit += w[i + 1]; i++; } else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { spoel(); q = c; uit += c; continue; }
    buf += c;
  }
  spoel();
  return uit.trim();
}

function declaratiesKlaar(blok) {
  return splits(blok, ';')
    .map((d) => d.trim())
    .filter(Boolean)
    .map((d) => {
      const [prop, ...rest] = splits(d, ':');
      if (!rest.length) throw new Error('declaratie zonder ":": ' + d.slice(0, 60));
      return prop.trim() + ':' + waardeKlaar(rest.join(':'));
    })
    .join(';');
}

/* ---------- het bestand ---------- */
function minBestand() {
  const kandidaten = fs.readdirSync(ROOT).filter((f) => /^belasting(\.[0-9a-f]{8})?\.min\.css$/.test(f));
  if (kandidaten.length !== 1) {
    console.error('Verwacht precies één belasting[.<hash>].min.css, gevonden: ' + (kandidaten.join(', ') || 'geen'));
    process.exit(1);
  }
  return kandidaten[0];
}

if (require.main === module) {
  const bron = fs.readFileSync(BRON, 'utf8').replace(/\r\n/g, '\n');
  const nieuw = minify(bron);
  const naam = minBestand();
  const huidig = fs.readFileSync(path.join(ROOT, naam), 'utf8').replace(/\r\n/g, '\n');
  const kb = (n) => (Buffer.byteLength(n) / 1024).toFixed(1) + ' KB';
  console.log('bron   : belasting.css (' + kb(bron) + ')');
  console.log('uit    : ' + naam + ' (' + kb(nieuw) + ')');
  if (huidig === nieuw) {
    console.log('ok  het .min.css-bestand volgt precies uit belasting.css');
  } else if (CHECK) {
    console.error('FOUT: ' + naam + ' wijkt af van belasting.css. Draai node scripts/bouw.js (zonder --check).');
    process.exit(1);
  } else {
    fs.writeFileSync(path.join(ROOT, naam), nieuw);
    console.log('geschreven; hash-css.js geeft het daarna een nieuwe naam');
  }
}

module.exports = { minify };
