#!/usr/bin/env node
/*
 * check-html.js
 * Controleert de tag-balans en de nesting van alle HTML-bestanden.
 * Faalt (exit 1) bij een niet-gesloten tag, een sluittag zonder opening, of
 * een sluittag die de verkeerde tag sluit.
 *
 * WAAROM
 * Bij een bewerking in augustus 2026 verdween op negen plaatspagina's een
 * sluitende </div>. Dat is met de hand gevonden, en dat is geen vangnet.
 * Een browser herstelt zoiets stil; de opmaak schuift dan een niveau op
 * zonder dat er ergens een foutmelding komt.
 *
 * GEBRUIK
 *   node scripts/check-html.js            alle bestanden
 *   node scripts/check-html.js <pad>      één bestand of map
 *
 * Dit is bewust geen volledige HTML-parser: het controleert de containers waar
 * een fout de pagina echt scheeftrekt, en laat de tags met rij dat HTML5 zelf
 * mag sluiten (li, p, td) met rust.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const doel = process.argv[2] ? path.resolve(process.argv[2]) : ROOT;

/* Tags zonder sluittag. */
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr']);

/* Tags die HTML5 zelf mag sluiten; die controleren we niet op balans. */
const OPTIONEEL = new Set(['p', 'li', 'dt', 'dd', 'option', 'optgroup', 'thead',
  'tbody', 'tfoot', 'tr', 'td', 'th', 'rt', 'rp', 'colgroup', 'caption']);

/* Wat we wél bewaken: containers waar een gemiste sluittag de opmaak breekt. */
const BEWAAKT = new Set(['html', 'head', 'body', 'main', 'section', 'article',
  'aside', 'nav', 'header', 'footer', 'div', 'ul', 'ol', 'dl', 'table', 'form',
  'fieldset', 'label', 'button', 'a', 'span', 'figure', 'picture', 'select',
  'textarea', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'details', 'summary']);

function walk(dir, acc) {
  const st = fs.statSync(dir);
  if (st.isFile()) { if (dir.endsWith('.html')) acc.push(dir); return acc; }
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}

function regelVan(html, index) {
  let regel = 1;
  for (let i = 0; i < index && i < html.length; i++) if (html[i] === '\n') regel++;
  return regel;
}

function controleer(file) {
  const html = fs.readFileSync(file, 'utf8');
  const fouten = [];
  const stack = [];

  const tagRe = /<(\/?)([a-zA-Z][a-zA-Z0-9-]*)([^>]*?)(\/?)>/g;
  let m;
  while ((m = tagRe.exec(html)) !== null) {
    const sluit = m[1] === '/';
    const naam = m[2].toLowerCase();
    const zelfsluitend = m[4] === '/';

    /* De inhoud van script, style en textarea is geen HTML: overslaan. */
    if (!sluit && (naam === 'script' || naam === 'style' || naam === 'textarea')) {
      const eind = html.toLowerCase().indexOf('</' + naam, tagRe.lastIndex);
      if (eind === -1) {
        fouten.push({ regel: regelVan(html, m.index), tekst: '<' + naam + '> wordt nergens gesloten' });
        break;
      }
      tagRe.lastIndex = eind + naam.length + 3;
      continue;
    }

    if (VOID.has(naam) || zelfsluitend) continue;
    if (OPTIONEEL.has(naam)) continue;
    if (!BEWAAKT.has(naam)) continue;

    if (!sluit) {
      stack.push({ naam: naam, regel: regelVan(html, m.index) });
    } else {
      if (!stack.length) {
        fouten.push({ regel: regelVan(html, m.index), tekst: '</' + naam + '> zonder openende tag' });
        continue;
      }
      const top = stack[stack.length - 1];
      if (top.naam === naam) { stack.pop(); continue; }

      /* Sluit deze tag iets dat dieper in de stapel zit? Dan zijn de tags
         ertussen niet gesloten. */
      let diepte = -1;
      for (let i = stack.length - 2; i >= 0; i--) if (stack[i].naam === naam) { diepte = i; break; }
      if (diepte === -1) {
        fouten.push({ regel: regelVan(html, m.index), tekst: '</' + naam + '> sluit niets; open staat <' + top.naam + '> van regel ' + top.regel });
      } else {
        for (let i = stack.length - 1; i > diepte; i--) {
          fouten.push({ regel: stack[i].regel, tekst: '<' + stack[i].naam + '> is niet gesloten (</' + naam + '> op regel ' + regelVan(html, m.index) + ' sluit eroverheen)' });
        }
        stack.length = diepte;
      }
    }
  }

  for (const open of stack) {
    fouten.push({ regel: open.regel, tekst: '<' + open.naam + '> is nergens gesloten' });
  }
  return fouten;
}

const files = walk(doel, []);
let totaal = 0;
let stuk = 0;
for (const f of files.sort()) {
  const fouten = controleer(f);
  if (!fouten.length) continue;
  stuk++;
  totaal += fouten.length;
  console.log('\n' + path.relative(ROOT, f).split(path.sep).join('/'));
  fouten.slice(0, 12).forEach(function (e) { console.log('  regel ' + e.regel + ': ' + e.tekst); });
  if (fouten.length > 12) console.log('  (nog ' + (fouten.length - 12) + ' meldingen)');
}

console.log('\nGecontroleerd: ' + files.length + ' HTML-bestanden.');
if (totaal) {
  console.error('FAIL: ' + totaal + ' tag-fout(en) in ' + stuk + ' bestand(en).');
  process.exit(1);
}
console.log('OK: tag-balans en nesting kloppen overal.');
