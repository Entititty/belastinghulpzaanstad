#!/usr/bin/env node
/*
 * check-rekenvoorbeelden.js
 * Rekent de rekenvoorbeelden eigen woning na: rente min eigenwoningforfait,
 * maal het tarief, gedeeld door twaalf. Faalt (exit 1) bij een verschil van
 * meer dan €1.
 *
 * WAAROM
 * docs/jaarlijkse-update.md zei het al: "geen script bewaakt die". In oktober
 * 2026 bleek wat dat kost. Op de plaatspagina's stond in het rekenvoorbeeld
 * €404 per maand en verderop, in de FAQ, €326 voor dezelfde woning. De
 * voetnoot zei "eerste schijf" terwijl er met 37,56% werd gerekend. En op een
 * Engelse pagina stond "€3,908 ÷ 12" onder een jaarbedrag van €3,970.
 * set-fiscale-cijfers.js vervangt percentages, maar de uitkomsten die daaruit
 * volgen ziet het niet.
 *
 * WAT HET CONTROLEERT
 * Per blok (hero-card, teruggave-example, of een tabel met een aftrekbaar
 * saldo of bedrag):
 *   rente - forfait = saldo
 *   saldo x eerste-schijftarief   = de uitkomst achter "(35,75%)"
 *   saldo x maximaal aftrektarief = de uitkomst achter "(37,56%)"
 *   een maandbedrag of -bereik    = jaarbedrag / 12
 * De tarieven komen uit data/fiscale-cijfers.json, zodat dit script na de
 * jaarovergang vanzelf op de nieuwe percentages controleert.
 *
 * WAT HET NIET CONTROLEERT
 * Of het gekozen tarief past bij het inkomen in het voorbeeld. Een drempel-
 * inkomen van €45.000 valt in de tweede schijf; een voorbeeld dat daar met
 * 35,75% rekent, is rekenkundig juist en toch fout. Dat blijft mensenwerk.
 *
 * GEBRUIK
 *   node scripts/check-rekenvoorbeelden.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const cijfers = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'fiscale-cijfers.json'), 'utf8')).cijfers;
const pct = (w) => parseFloat(w.replace('%', '').replace(',', '.'));
const T1 = pct(cijfers.box1_schijf1_tarief.waarde);
const T2 = pct(cijfers.max_aftrektarief_eigen_woning.waarde);
const labelVan = (t) => new RegExp('\\(' + String(t).replace('.', '[.,]') + '%\\)');

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

/* "€12.897", "€ 12,897", "€ 12.580" -> 12897 */
function getal(s) { return parseInt(s.replace(/[.,](?=\d{3}\b)/g, ''), 10); }

function tekst(html) {
  return html.replace(/<[^>]+>/g, ' ')
    .replace(/&euro;/g, '€').replace(/&nbsp;/g, ' ').replace(/&ndash;/g, '–')
    .replace(/&rarr;/g, '→').replace(/&minus;/g, '−').replace(/&times;/g, '×')
    .replace(/\s+/g, ' ');
}

function blokken(html) {
  const uit = [];
  const re = /<div class="hero-card">([\s\S]*?)<\/p>|<div class="teruggave-example">([\s\S]*?)<\/p>|<table class="income-table">([\s\S]*?)<\/table>/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    const t = tekst(m[1] || m[2] || m[3]);
    if (/Aftrekbaar saldo|Deductible balance|Aftrekbaar bedrag/i.test(t)) uit.push(t);
  }
  return uit;
}

/* Alle bedragen in een blok, met hun positie. Een bedrag dat een operand is
   van een som ("€280.000 × 4,2%", "€900 − €450", "€3.970 ÷ 12") is geen
   uitkomst; dat slaan we over bij het zoeken naar de uitkomst achter een label. */
function bedragen(t) {
  const uit = [];
  const re = /€\s?([\d.,]*\d)/g;
  let m;
  while ((m = re.exec(t)) !== null) {
    const na = t.slice(re.lastIndex, re.lastIndex + 8);
    const voor = t.slice(Math.max(0, m.index - 4), m.index);
    const vorige = uit[uit.length - 1];
    /* "− €1.190 − €99" zijn twee negatieve cellen, geen som: een bedrag met
       zelf een minteken ervoor is nooit de linkerkant van een aftreksom. */
    const linkerOperand = /^\s*[×÷]/.test(na) || (/^\s*[−-]\s*€/.test(na) && !/[−-]\s*$/.test(voor));
    const rechterOperand = /[−-]\s*$/.test(voor) && vorige && vorige.linker && (m.index - vorige.eind) < 6;
    uit.push({ waarde: getal(m[1]), tekst: m[1], begin: m.index, eind: re.lastIndex, linker: linkerOperand, operand: linkerOperand || rechterOperand });
  }
  return uit;
}
function uitkomstNa(t, lijst, labelRe, nummer) {
  const m = t.match(labelRe);
  if (!m) return null;
  const vanaf = m.index + m[0].length;
  const kandidaten = lijst.filter(function (b) { return b.begin >= vanaf && !b.operand; });
  return kandidaten[nummer || 0] || null;
}

const fouten = [];
let gecontroleerd = 0;

for (const f of walk(ROOT, [])) {
  const html = fs.readFileSync(f, 'utf8');
  for (const t of blokken(html)) {
    const lijst = bedragen(t);
    const pak = (re) => { const b = uitkomstNa(t, lijst, re, 0); return b ? b.waarde : null; };
    const rente = pak(/(?:Betaalde )?[Hh]ypotheekrente(?! \(100)|Mortgage interest|Paid mortgage interest/);
    const forfait = pak(/eigenwoningforfait|imputed rental value/i);
    const saldo = pak(/Aftrekbaar saldo|Deductible balance|Aftrekbaar bedrag/i);
    if (saldo === null) continue;
    gecontroleerd++;
    const waar = rel(f) + ' (saldo €' + saldo + ')';

    if (rente !== null && forfait !== null && Math.abs(rente - forfait - saldo) > 1) {
      fouten.push(waar + ': ' + rente + ' - ' + forfait + ' is geen ' + saldo);
    }

    const scenario = function (tarief) {
      const re = labelVan(tarief);
      const jaarB = uitkomstNa(t, lijst, re, 0);
      if (!jaarB) return null;
      const jaar = jaarB.waarde;
      const verwacht = saldo * tarief / 100;
      if (Math.abs(jaar - verwacht) > 1) {
        fouten.push(waar + ': ' + String(tarief).replace('.', ',') + '% van €' + saldo + ' is €' + Math.round(verwacht) + ', er staat €' + jaar);
      }
      /* in een tabel staat het maandbedrag direct ernaast */
      const volgende = uitkomstNa(t, lijst, re, 1);
      if (volgende && volgende.waarde < jaar / 6 && (volgende.begin - jaarB.eind) < 12 && Math.abs(volgende.waarde - jaar / 12) > 1) {
        fouten.push(waar + ': maandbedrag €' + volgende.waarde + ' hoort €' + Math.round(jaar / 12) + ' te zijn');
      }
      return jaar;
    };
    const j1 = scenario(T1);
    const j2 = scenario(T2);

    /* een maandbereik "€339–€357" of "€339–357" */
    const bereik = t.match(/€\s?(\d{2,4})\s*–\s*€?\s?(\d{2,4})\b/);
    if (bereik && j1 && j2) {
      const a = getal(bereik[1]), b = getal(bereik[2]);
      if (Math.abs(a - j1 / 12) > 1 || Math.abs(b - j2 / 12) > 1) {
        fouten.push(waar + ': maandbereik €' + a + '–€' + b + ' hoort €' + Math.round(j1 / 12) + '–€' + Math.round(j2 / 12) + ' te zijn');
      }
    }
    /* "€3.970 ÷ 12" moet een van de jaarbedragen zijn, en de uitkomst een twaalfde */
    const deling = t.match(/€\s?([\d.,]*\d)\s*÷\s*12[^€]*?€\s?([\d.,]*\d)/);
    if (deling) {
      const deeltal = getal(deling[1]), uitkomst = getal(deling[2]);
      if ((j2 === null || Math.abs(deeltal - j2) > 1) && (j1 === null || Math.abs(deeltal - j1) > 1)) {
        fouten.push(waar + ': "€' + deling[1] + ' ÷ 12" hoort bij geen van de jaarbedragen');
      }
      if (Math.abs(uitkomst - deeltal / 12) > 1) fouten.push(waar + ': €' + deeltal + ' ÷ 12 is geen €' + uitkomst);
    }
  }
}

console.log('Rekenvoorbeelden nagerekend: ' + gecontroleerd + ' blokken (tarieven ' + T1 + '% en ' + T2 + '%).');
if (fouten.length) {
  console.error('FAIL: ' + fouten.length + ' rekenfout(en):');
  fouten.forEach(function (e) { console.error('  - ' + e); });
  process.exit(1);
}
console.log('OK: alle rekenvoorbeelden kloppen.');
