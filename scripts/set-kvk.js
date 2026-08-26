#!/usr/bin/env node
/*
 * set-kvk.js
 * Zet de wettelijk verplichte KvK- en BTW-vermelding in de footer van alle
 * pagina's, of haalt hem er weer uit.
 *
 * Art. 3:15d BW verplicht een online dienstverlener om identiteit,
 * KvK-nummer en BTW-identificatienummer eenvoudig, direct en permanent
 * toegankelijk te maken. Zolang de onderneming niet is ingeschreven bestaan
 * die nummers niet. Dan is geen vermelding beter dan een invulmarkering:
 * een wettelijk verplichte regel met een zichtbaar leeg veld laat juist zien
 * dat er iets ontbreekt.
 *
 * Gebruik:
 *   node scripts/set-kvk.js --kvk 12345678 --btw NL123456789B01
 *   node scripts/set-kvk.js --verwijder
 *   voeg --dry toe om alleen te tonen wat er zou gebeuren
 *
 * Het BTW-identificatienummer (NL + 9 cijfers + B + 2 cijfers) is het nummer
 * dat je publiceert. Het omzetbelastingnummer NIET: dat bevat bij een
 * eenmanszaak je BSN.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DRY = process.argv.indexOf('--dry') !== -1;

function arg(naam) {
  const i = process.argv.indexOf('--' + naam);
  return i !== -1 ? process.argv[i + 1] : null;
}
const VERWIJDER = process.argv.indexOf('--verwijder') !== -1;
const KVK = arg('kvk');
const BTW = arg('btw');

/* ------------------------------------------------------------------
 * De twee markupvormen, exact zoals ze in de footer staan.
 *
 * "zonder" is de regel zoals hij op de site staat als er geen nummers
 * zijn. "met" is dezelfde regel met de nummers erin, op precies dezelfde
 * plek. Zo is het invoegen en verwijderen een omkeerbare tekstoperatie en
 * hoeft er niets geraden te worden.
 *
 * Geteld op 26-08-2026: vorm nl op 55 pagina's, vorm en op 38 pagina's,
 * samen 93 van de 94. blog/einddatum-belastingaangifte-2025/ heeft geen
 * footer (noindex meta-refresh-stub) en hoort er dus niet bij.
 * ------------------------------------------------------------------ */
const VORMEN = [
  {
    taal: 'nl',
    verwacht: 55,
    zonder: 'Bezoek uitsluitend op afspraak &mdash; wij komen bij u thuis</span>',
    met: function (kvk, btw) {
      return 'Bezoek uitsluitend op afspraak &mdash; wij komen bij u thuis &middot; KvK ' + kvk +
        ' &middot; BTW-id ' + btw +
        '<!-- Verplicht o.g.v. art. 3:15d BW. Bijwerken met scripts/set-kvk.js. --></span>';
    }
  },
  {
    taal: 'en',
    verwacht: 38,
    zonder: 'By appointment only &mdash; we come to your home</span>',
    met: function (kvk, btw) {
      return 'By appointment only &mdash; we come to your home &middot; KvK ' + kvk +
        ' &middot; VAT ' + btw +
        '<!-- Required under art. 3:15d Dutch Civil Code. Update with scripts/set-kvk.js. --></span>';
    }
  }
];

/* Vormen die eerder in de repo hebben gestaan. Alleen nodig om ze te kunnen
 * herkennen en opruimen; nieuwe uitvoer gebruikt altijd VORMEN hierboven. */
const OUDE_VORMEN = [
  'Bezoek uitsluitend op afspraak &mdash; wij komen bij u thuis<!-- TODO eigenaar: KvK-nummer + BTW-id hier tonen zodra ingeschreven bij de KvK (verplicht o.g.v. art. 3:15d BW) --></span>',
  'By appointment only &mdash; we come to your home<!-- TODO owner: show KvK + VAT number once registered (required under art. 3:15d Dutch Civil Code) --></span>'
];

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      walk(path.join(dir, e.name), acc);
    } else if (e.name === 'index.html') acc.push(path.join(dir, e.name));
  }
  return acc;
}

/* ---------- argumenten controleren ---------- */
if (!VERWIJDER) {
  if (!KVK || !BTW) {
    console.error('Gebruik: node scripts/set-kvk.js --kvk <nummer> --btw <NL...B01>');
    console.error('     of: node scripts/set-kvk.js --verwijder');
    process.exit(1);
  }
  if (!/^\d{8}$/.test(KVK)) {
    console.error('KvK-nummer moet 8 cijfers zijn, kreeg: ' + KVK);
    process.exit(1);
  }
  if (!/^NL\d{9}B\d{2}$/.test(BTW)) {
    console.error('BTW-id moet de vorm NL123456789B01 hebben, kreeg: ' + BTW);
    console.error('Let op: gebruik het BTW-identificatienummer, niet het omzetbelastingnummer.');
    process.exit(1);
  }
}

/* ---------- uitvoeren ---------- */
const bestanden = walk(ROOT, []);
const telling = {};
let geraakt = 0, onbekend = [];

for (const f of bestanden) {
  let s = fs.readFileSync(f, 'utf8');
  const voor = s;

  // eerst altijd terug naar de kale vorm, ongeacht welke variant erin staat
  for (const oud of OUDE_VORMEN) {
    while (s.indexOf(oud) !== -1) {
      const vorm = oud.indexOf('Bezoek uitsluitend') === 0 ? VORMEN[0] : VORMEN[1];
      s = s.replace(oud, vorm.zonder);
    }
  }
  // en de "met nummers"-vorm eruit halen, mochten die er staan
  for (const v of VORMEN) {
    // eenvoudiger en veiliger: op vaste tekst zoeken
    const kop = v.zonder.slice(0, v.zonder.length - '</span>'.length);
    let i;
    while ((i = s.indexOf(kop + ' &middot; KvK ')) !== -1) {
      const eind = s.indexOf('</span>', i);
      if (eind === -1) break;
      s = s.slice(0, i) + v.zonder + s.slice(eind + '</span>'.length);
    }
  }

  // nu eventueel de nummers erin zetten
  if (!VERWIJDER) {
    for (const v of VORMEN) {
      if (s.indexOf(v.zonder) === -1) continue;
      const n = s.split(v.zonder).length - 1;
      if (n !== 1) { onbekend.push(path.relative(ROOT, f) + ': ' + n + 'x vorm ' + v.taal); continue; }
      s = s.replace(v.zonder, v.met(KVK, BTW));
      telling[v.taal] = (telling[v.taal] || 0) + 1;
    }
  } else {
    for (const v of VORMEN) {
      if (s.indexOf(v.zonder) !== -1) telling[v.taal] = (telling[v.taal] || 0) + 1;
    }
  }

  if (s !== voor) { if (!DRY) fs.writeFileSync(f, s, 'utf8'); geraakt++; }
}

console.log((DRY ? '[dry] ' : '') + (VERWIJDER ? 'KvK/BTW-regel verwijderd' : 'KvK ' + KVK + ' / BTW ' + BTW + ' gezet'));
for (const v of VORMEN) {
  const n = telling[v.taal] || 0;
  const ok = n === v.verwacht;
  console.log('  vorm ' + v.taal + ': ' + n + ' pagina\'s' + (ok ? '  ok' : '  LET OP: verwacht ' + v.verwacht));
}
console.log('  bestanden gewijzigd: ' + geraakt);
if (onbekend.length) {
  console.error('\nAfwijkende vorm gevonden, NIET aangepast:');
  onbekend.forEach(function (o) { console.error('  ' + o); });
  process.exit(1);
}

/* ---------- controle ---------- */
if (!DRY) {
  let fout = 0;
  for (const f of bestanden) {
    const s = fs.readFileSync(f, 'utf8');
    const r = path.relative(ROOT, f).split(path.sep).join('/');
    const m = s.match(/<div class="footer-bottom">[\s\S]*?<\/div>/);
    const foot = m ? m[0] : '';
    if (!foot) continue;                 // de redirect-stub heeft geen footer
    if (VERWIJDER) {
      if (foot.indexOf('KvK') !== -1) { console.error('KvK-fragment in de footer van ' + r); fout++; }
    } else if (!/KvK \d{8} &middot; (BTW-id|VAT) NL\d{9}B\d{2}/.test(foot)) {
      console.error('nummers niet correct gezet in ' + r); fout++;
    }
    if (/TODO (eigenaar|owner): (KvK|show KvK)/.test(s)) { console.error('oude TODO in ' + r); fout++; }
  }
  console.log(fout === 0 ? '\nok  geen placeholders of losse fragmenten' : '\nFOUT: ' + fout + ' probleem(en)');
  if (fout) process.exit(1);
}
