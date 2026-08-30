#!/usr/bin/env node
/*
 * set-fiscale-cijfers.js
 * Werkt een fiscaal bedrag bij in data/fiscale-cijfers.json én overal in de HTML.
 *
 * WAAROM
 * De bedragen staan 610 keer hardcoded in de pagina's, waarvan 90 keer in
 * JSON-LD. Bij een herziening was dat handwerk, en handwerk laat plekken staan.
 * De site heeft geen build: de HTML die in git staat is de HTML die de server
 * serveert. Daarom vervangen we de tekst, in plaats van er een sjabloon van te
 * maken. Zelfde aanpak als set-btw.js en set-kvk.js.
 *
 * GEBRUIK
 *   node scripts/set-fiscale-cijfers.js --herstel
 *       vervangt elke VEROUDERDE waarde uit fiscale-cijfers.json door de actuele
 *
 *   node scripts/set-fiscale-cijfers.js --zet <sleutel> "<nieuwe waarde>" \
 *        --bron-url https://... [--bron "korte omschrijving"]
 *       zet een nieuwe waarde, schuift de oude naar "verouderd", en vervangt
 *       hem overal in de HTML
 *
 *   Zonder --schrijf doet het script niets; het toont alleen wat het zou doen.
 *
 * VEILIGHEID
 * Korte bedragen als "36%" of "€20" komen ook in een andere betekenis voor.
 * Zulke waarden krijgen in fiscale-cijfers.json een "context": een lijst met
 * woorden waarvan er één op dezelfde regel moet staan. Ontbreekt die lijst bij
 * een korte waarde, dan weigert het script te vervangen.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const BESTAND = path.join(ROOT, 'data', 'fiscale-cijfers.json');
const args = process.argv.slice(2);
const SCHRIJF = args.includes('--schrijf');
const HERSTEL = args.includes('--herstel');
const iZet = args.indexOf('--zet');

function argWaarde(vlag) {
  const i = args.indexOf(vlag);
  return i === -1 ? null : args[i + 1];
}

if (!HERSTEL && iZet === -1) {
  console.error('Geef --herstel of --zet <sleutel> "<waarde>". Zie de kop van dit bestand.');
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(BESTAND, 'utf8'));
const VANDAAG = new Date().toISOString().slice(0, 10);

/* ---------- schrijfwijzen van een bedrag ---------- */
function varianten(waarde) {
  const uit = new Set();
  if (waarde.indexOf('€') === 0) {
    const kaal = waarde.slice(1).trim();
    uit.add('€' + kaal);
    uit.add('€ ' + kaal);
    uit.add('&euro;' + kaal);
    uit.add('&euro; ' + kaal);
    uit.add('&euro;&nbsp;' + kaal);
    if (kaal.indexOf('.') !== -1) {
      const en = kaal.split('.').join(',');
      uit.add('€' + en);
      uit.add('€ ' + en);
      uit.add('&euro;' + en);
      uit.add('&euro; ' + en);
    }
  } else {
    uit.add(waarde);
    if (waarde.indexOf(',') !== -1) uit.add(waarde.split(',').join('.'));
  }
  return [...uit];
}

/* Bij een korte waarde is een context verplicht: "36%" staat ook in zinnen die
   niets met box 3 te maken hebben. */
function kortEnRisicovol(waarde) {
  const kaal = waarde.replace('€', '').replace('%', '').trim();
  return kaal.length <= 3;
}

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}
const files = walk(ROOT, []);

/* ---------- vervangen ---------- */
function vervang(oudeWaarde, nieuweWaarde, context, sleutel) {
  const oudeVarianten = varianten(oudeWaarde);
  let treffers = 0, overgeslagen = 0, geraakt = 0;

  for (const f of files) {
    const src = fs.readFileSync(f, 'utf8');
    const eol = src.includes('\r\n') ? '\r\n' : '\n';
    const L = src.split(/\r?\n/);
    let veranderd = false;

    for (let i = 0; i < L.length; i++) {
      let regel = L[i];
      if (!oudeVarianten.some((v) => regel.indexOf(v) !== -1)) continue;

      if (context && context.length && !context.some((c) => regel.toLowerCase().indexOf(c.toLowerCase()) !== -1)) {
        overgeslagen++;
        console.log('  overgeslagen (geen context)  ' +
          path.relative(ROOT, f).split(path.sep).join('/') + ':' + (i + 1) + '  ' + regel.trim().slice(0, 90));
        continue;
      }

      let nieuw = regel;
      for (const v of oudeVarianten) {
        if (nieuw.indexOf(v) === -1) continue;
        /* de nieuwe waarde in dezelfde schrijfwijze terugzetten */
        let vervanging = nieuweWaarde;
        if (v.indexOf('&euro;') === 0) vervanging = nieuweWaarde.replace('€', v.indexOf('&euro; ') === 0 ? '&euro; ' : '&euro;');
        else if (v.indexOf('€ ') === 0) vervanging = nieuweWaarde.replace('€', '€ ');
        if (v.indexOf(',') !== -1 && oudeWaarde.indexOf('.') !== -1) vervanging = vervanging.split('.').join(',');
        nieuw = nieuw.split(v).join(vervanging);
      }
      if (nieuw !== regel) {
        treffers++;
        veranderd = true;
        console.log('  ' + path.relative(ROOT, f).split(path.sep).join('/') + ':' + (i + 1));
        console.log('    -  ' + regel.trim().slice(0, 110));
        console.log('    +  ' + nieuw.trim().slice(0, 110));
        L[i] = nieuw;
      }
    }
    if (veranderd) {
      geraakt++;
      if (SCHRIJF) fs.writeFileSync(f, L.join(eol));
    }
  }
  console.log('\n' + sleutel + ': ' + treffers + ' regel(s) in ' + geraakt + ' bestand(en)' +
    (overgeslagen ? ', ' + overgeslagen + ' overgeslagen zonder context' : '') + '.');
  return treffers;
}

let totaal = 0;

if (HERSTEL) {
  console.log('Verouderde waarden vervangen door de actuele.\n');
  for (const [sleutel, c] of Object.entries(data.cijfers)) {
    for (const oud of c.verouderd || []) {
      if (kortEnRisicovol(oud) && !(c.context && c.context.length)) {
        console.log('OVERGESLAGEN  ' + sleutel + ': "' + oud + '" is te kort zonder "context" in fiscale-cijfers.json');
        continue;
      }
      totaal += vervang(oud, c.waarde, c.context, sleutel);
    }
  }
}

if (iZet !== -1) {
  const sleutel = args[iZet + 1];
  const nieuweWaarde = args[iZet + 2];
  const bronUrl = argWaarde('--bron-url');
  const bron = argWaarde('--bron');
  const c = data.cijfers[sleutel];
  if (!c) { console.error('onbekende sleutel: ' + sleutel); process.exit(1); }
  if (!nieuweWaarde) { console.error('geef een nieuwe waarde'); process.exit(1); }
  if (!bronUrl || bronUrl.indexOf('https://') !== 0) {
    console.error('geef --bron-url met een https-adres van de primaire bron');
    process.exit(1);
  }
  if (kortEnRisicovol(c.waarde) && !(c.context && c.context.length)) {
    console.error(sleutel + ': deze waarde is kort. Zet eerst een "context" in fiscale-cijfers.json.');
    process.exit(1);
  }

  console.log(sleutel + ': ' + c.waarde + '  ->  ' + nieuweWaarde + '\n');
  totaal += vervang(c.waarde, nieuweWaarde, c.context, sleutel);

  c.verouderd = (c.verouderd || []).concat([c.waarde]).filter((v, i, a) => a.indexOf(v) === i);
  c.waarde = nieuweWaarde;
  c.bron_url = bronUrl;
  if (bron) c.bron = bron;
  c.gecontroleerd_op = VANDAAG;
  delete c.bron_url_todo;
  data.laatst_gecontroleerd = VANDAAG;
  if (SCHRIJF) fs.writeFileSync(BESTAND, JSON.stringify(data, null, 2) + '\n');
}

console.log('\n' + (SCHRIJF ? 'Geschreven: ' : 'Proefdraai, niets geschreven: ') + totaal + ' regel(s).');
if (!SCHRIJF && totaal) console.log('Zet --schrijf erbij om het door te voeren.');
if (SCHRIJF) console.log('Draai daarna: node scripts/check-fiscale-cijfers.js && node scripts/check-html.js');
