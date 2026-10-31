#!/usr/bin/env node
/*
 * rekentabellen.js
 * Zet de vaste tabellen en bedragen bij de rekentools in de HTML, uitgerekend
 * met js/rekenregels.js en de cijfers uit data/fiscale-cijfers.json.
 *
 * WAAROM
 * Een rekentool werkt met JavaScript. Google voert dat meestal uit, maar
 * ChatGPT, Perplexity en de andere AI-diensten lezen alleen de HTML. Een
 * tabel als "huurtoeslag per huur en inkomen" lezen ze wel, en mensen die
 * "zorgtoeslag 2026 tabel" zoeken ook. Met de hand bijhouden kan niet: bij
 * elke jaarwisseling veranderen alle bedragen. Dit script rekent ze uit met
 * dezelfde code als de rekentool, dus de tabel en de rekentool zeggen altijd
 * hetzelfde.
 *
 * IN DE HTML
 *   <!-- tabel:naam -->...<!-- /tabel:naam -->   een hele tabel
 *   <!-- r:naam -->€129<!-- /r:naam -->           een los bedrag in de tekst
 * De namen staan hieronder in TABELLEN en WAARDEN. Een onbekende naam is een
 * fout. Let op: in JSON-LD kan geen markering; een bedrag dat daar ook staat
 * (in een FAQ-antwoord) past check-fiscale-cijfers.js tegen de zichtbare tekst.
 *
 * GEBRUIK
 *   node scripts/rekentabellen.js           schrijft
 *   node scripts/rekentabellen.js --check   schrijft niets; faalt als de HTML afwijkt
 * Draait in bouw.js.
 */
const fs = require('fs');
const path = require('path');
const R = require('../js/rekenregels.js');

const ROOT = path.resolve(__dirname, '..');
const CHECK = process.argv.includes('--check');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'fiscale-cijfers.json'), 'utf8'));
const C = R.cijfers(data.cijfers);
const JAAR = data.belastingjaar;

/* ---------- opmaak ---------- */
function duizend(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, '.'); }
function euro(n) { return '€' + duizend(Math.round(n)); }
function euroCent(n) {
  const [heel, cent] = (Math.round(n * 100) / 100).toFixed(2).split('.');
  return '€' + duizend(heel) + ',' + cent;
}
const GEEN = '<span aria-hidden="true">&ndash;</span><span class="sr-only">geen</span>';

/* De titel staat boven het schuifkader en niet als <caption>: een caption is
   zo breed als de tabel en wordt op een telefoon afgekapt. aria-labelledby
   koppelt hem voor schermlezers alsnog aan de tabel. */
function tabel(id, kop, kolommen, rijen) {
  return '<p class="rekentabel-kop" id="tabel-' + id + '">' + kop + '</p>\n' +
    '<div class="tabel-scroll"><table class="income-table rekentabel" aria-labelledby="tabel-' + id + '">\n' +
    '<thead><tr>' + kolommen.map((k) => '<th scope="col">' + k + '</th>').join('') + '</tr></thead>\n<tbody>\n' +
    rijen.map((r) => '<tr><th scope="row">' + r[0] + '</th>' + r.slice(1).map((c) => '<td>' + c + '</td>').join('') + '</tr>').join('\n') +
    '\n</tbody>\n</table></div>';
}

/* ---------- zorgtoeslag ---------- */
function zorgtoeslagTabel(id, partner) {
  const drempel = C.zorgtoeslag_drempelinkomen;
  const grens = partner ? C.zorgtoeslag_inkomensgrens_partners : C.zorgtoeslag_inkomensgrens_alleenstaand;
  const stap = partner ? 2000 : 1000;
  const inkomens = [drempel];
  for (let i = Math.ceil((drempel + 1) / stap) * stap; i < grens; i += stap) inkomens.push(i);
  inkomens.push(grens);
  const rijen = inkomens.map((ink, i) => {
    const z = R.zorgtoeslag(C, { partner, inkomen: ink });
    const label = i === 0 ? euro(ink) + ' of minder' : euro(ink);
    return [label, z.maand ? euro(z.maand) : GEEN, z.jaar ? euro(z.jaar) : GEEN];
  });
  rijen.push(['meer dan ' + euro(grens), GEEN, GEEN]);
  return tabel(id, 'Zorgtoeslag ' + JAAR + ' ' + (partner ? 'met toeslagpartner (inkomen samen)' : 'zonder toeslagpartner'),
    ['Toetsingsinkomen', 'Per maand', 'Per jaar'], rijen);
}

/* ---------- huurtoeslag ---------- */
const HUREN = [350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900];

function huurtoeslagTabel(id, personen, kop, inkomens) {
  const ijkpunt = personen > 1 ? C.huurtoeslag_inkomensijkpunt_meerpersoons : C.huurtoeslag_inkomensijkpunt_eenpersoons;
  const kolommen = ['Kale huur'].concat(inkomens.map((ink, i) => i === 0 ? 'Inkomen tot ' + euro(ijkpunt) : 'Inkomen ' + euro(ink)));
  const max = C.huurtoeslag_rekenhuur_max;
  const huren = HUREN.filter((h) => h < max).concat([max]);
  const rijen = huren.map((huur) => {
    const label = huur === max ? euroCent(max) + ' of meer' : euro(huur);
    return [label].concat(inkomens.map((ink, i) => {
      const h = R.huurtoeslag(C, { kaleHuur: huur, personen, iemand21: true, inkomen: i === 0 ? ijkpunt : ink });
      return h.maand ? euro(h.maand) : GEEN;
    }));
  });
  return tabel(id, kop, kolommen, rijen);
}

function huurtoeslagJongeren(id) {
  const grens = C.huurtoeslag_jongerengrens;
  const ijkpunt = C.huurtoeslag_inkomensijkpunt_eenpersoons;
  const inkomens = [ijkpunt, 25000, 27500, 30000, 35000];
  const huren = [300, 350, 400, 450].filter((h) => h < grens).concat([grens]);
  const kolommen = ['Kale huur'].concat(inkomens.map((ink, i) => i === 0 ? 'Inkomen tot ' + euro(ijkpunt) : 'Inkomen ' + euro(ink)));
  const rijen = huren.map((huur) => [huur === grens ? euroCent(grens) + ' of meer' : euro(huur)].concat(inkomens.map((ink) => {
    const h = R.huurtoeslag(C, { kaleHuur: huur, personen: 1, iemand21: false, inkomen: ink });
    return h.maand ? euro(h.maand) : GEEN;
  })));
  return tabel(id, 'Huurtoeslag ' + JAAR + ' per maand voor 1 persoon jonger dan 21 (zonder kind of handicap)', kolommen, rijen);
}

/* Tot welk inkomen is er nog minstens €1 per maand? Afgerond op €100 omlaag. */
function nulpunt(huur, personen) {
  const h = R.huurtoeslag(C, { kaleHuur: huur, personen, iemand21: true, inkomen: 0 });
  const bruto = h.a + h.b + h.c;
  if (bruto < 1) return 0;
  return Math.floor((h.ijkpunt + (bruto - 1) * 12 / h.afbouw) / 100) * 100;
}

function huurtoeslagNulpunt(id) {
  const max = C.huurtoeslag_rekenhuur_max;
  const huren = [400, 500, 600, 700, 800].concat([max]);
  const rijen = huren.map((huur) => [huur === max ? euroCent(max) + ' of meer' : euro(huur)]
    .concat([1, 2, 3].map((p) => { const n = nulpunt(huur, p); return n ? 'tot ' + euro(n) : GEEN; })));
  return tabel(id, 'Tot welk inkomen krijgt u huurtoeslag in ' + JAAR + '? (21 jaar of ouder)',
    ['Kale huur', '1 persoon', '2 personen', '3 of meer'], rijen);
}

/* ---------- inkomstenbelasting bij loon ---------- */
function belastingBijLoon(id) {
  const lonen = [5000, 10000, 15000, 20000, 25000, 30000, 35000, 40000, 45000, 50000, 60000, 75000];
  const rijen = lonen.map((loon) => {
    const r = R.belastingteruggave(C, { loon });
    // eerst afronden, dan aftrekken: dan klopt de som in elke rij op de euro
    const heffing = Math.round(r.heffing), kortingen = Math.round(r.kortingen);
    const betaalt = Math.max(0, heffing - kortingen);
    return [euro(loon), euro(heffing), euro(kortingen), euro(betaalt), euro(betaalt / 12)];
  });
  return tabel(id, 'Inkomstenbelasting ' + JAAR + ' bij alleen loon (jonger dan de AOW-leeftijd)',
    ['Loon per jaar', 'Belasting', 'Heffingskortingen', 'U betaalt', 'Per maand'], rijen);
}

/* Tot welk loon betaalt u niets? Afgerond op €100 omlaag. */
function belastingvrijLoon() {
  let laag = 0, hoog = 40000;
  while (hoog - laag > 1) {
    const m = Math.floor((laag + hoog) / 2);
    if (R.belastingteruggave(C, { loon: m }).verschuldigd < 0.5) laag = m; else hoog = m;
  }
  return Math.floor(laag / 100) * 100;
}

/* ---------- erfbelasting en schenkbelasting ---------- */
function erfschenkTabel(id, soort, kop, kolommen, bedragen) {
  const rijen = bedragen.map((b) => [euro(b)].concat(kolommen.map(([, relatie]) => {
    const r = R.erfschenkbelasting(C, { soort, relatie, bedrag: b });
    return r.belasting >= 0.5 ? euro(r.belasting) : '€0';
  })));
  return tabel(id, kop, [soort === 'erf' ? 'Wat u erft' : 'Schenking'].concat(kolommen.map(([naam]) => naam)), rijen);
}

/* ---------- zorgkosten ---------- */
function zorgkostenDrempelTabel(id) {
  const g = C.zorgkosten_drempel_grens_alleen;
  const inkomens = [g, 15000, 20000, 25000, 30000, 35000, 40000, 45000, C.zorgkosten_drempel_grens_hoog, 60000, 75000];
  const rijen = inkomens.map((ink, i) => [i === 0 ? euro(ink) + ' of minder' : euro(ink),
    euro(R.zorgkostenDrempel(C, false, ink)), euro(R.zorgkostenDrempel(C, true, ink))]);
  return tabel(id, 'Drempel zorgkosten ' + JAAR + ' per drempelinkomen', ['Drempelinkomen', 'Zonder fiscale partner', 'Met fiscale partner'], rijen);
}
function zorgkostenDrempelTabelEn(id) {
  const g = C.zorgkosten_drempel_grens_alleen;
  const inkomens = [g, 15000, 20000, 25000, 30000, 35000, 40000, 45000, C.zorgkosten_drempel_grens_hoog, 60000, 75000];
  const rijen = inkomens.map((ink, i) => [i === 0 ? euroEn(ink) + ' or less' : euroEn(ink),
    euroEn(R.zorgkostenDrempel(C, false, ink)), euroEn(R.zorgkostenDrempel(C, true, ink))]);
  return tabel(id, 'Healthcare costs threshold ' + JAAR + ' by threshold income', ['Threshold income', 'No tax partner', 'With tax partner'], rijen);
}
// Engelse notatie: €1,308 en 35.75%
function euroEn(n) { return euro(n).replace(/\./g, ','); }
function pctEn(n) { return pct(n).replace(',', '.'); }

/* Het rekenvoorbeeld op /rekentools/zorgkosten/ en /blog/zorgkosten-aftrekken/:
   drempelinkomen €35.000, geen partner, geen AOW. Eerst afronden, dan rekenen. */
const ZORG_VB = { tandarts: 450, fysio: 320, medicijnen: 185, vervoer: 120, inkomen: 35000 };
const ZORG_AOW = { drempelinkomen: 24000, aow: true, verhoogbaar: 800 };
function zorgVoorbeeld() {
  const v = ZORG_VB;
  const r = R.zorgkosten(C, { drempelinkomen: v.inkomen, behandeling: v.tandarts + v.fysio, verhoogbaar: v.medicijnen + v.vervoer });
  const verhoging = Math.round(r.verhoging), drempel = Math.round(r.drempel);
  const totaal = v.tandarts + v.fysio + v.medicijnen + v.vervoer + verhoging;
  const aftrek = Math.max(0, totaal - drempel);
  return { v, r, verhoging, drempel, totaal, aftrek, voordeel: aftrek * C.box1_schijf1_tarief };
}
function zorgkostenVoorbeeld(id) {
  const z = zorgVoorbeeld(), v = z.v;
  const rijen = [
    ['Tandarts, niet vergoed', euro(v.tandarts)],
    ['Fysiotherapie op verwijzing, niet vergoed', euro(v.fysio)],
    ['Medicijnen op recept', euro(v.medicijnen)],
    ['Vervoer naar het ziekenhuis', euro(v.vervoer)],
    ['Verhoging: ' + pct(z.r.verhogingPct) + ' over medicijnen en vervoer', euro(z.verhoging)],
    ['Totaal', euro(z.totaal)],
    ['Drempel: ' + pct(C.zorgkosten_drempel_pct) + ' van ' + euro(v.inkomen), '− ' + euro(z.drempel)],
    ['Aftrek', euro(z.aftrek)],
    ['Belastingvoordeel bij ' + pct(C.box1_schijf1_tarief), '± ' + euro(z.voordeel)]
  ];
  return tabel(id, 'Rekenvoorbeeld zorgkosten ' + JAAR + ': drempelinkomen ' + euro(v.inkomen) + ', zonder partner, jonger dan de AOW-leeftijd',
    ['Post', 'Bedrag'], rijen);
}
// hetzelfde voorbeeld voor /en/blog/healthcare-costs-deduction/, met Engelse notatie
function zorgkostenVoorbeeldEn(id) {
  const z = zorgVoorbeeld(), v = z.v, en = euroEn;
  const rijen = [
    ['Dentist, not reimbursed', en(v.tandarts)],
    ['Physiotherapy on referral, not reimbursed', en(v.fysio)],
    ['Prescribed medicines', en(v.medicijnen)],
    ['Transport to the hospital', en(v.vervoer)],
    ['Increase: ' + pctEn(z.r.verhogingPct) + ' of medicines and transport', en(z.verhoging)],
    ['Total', en(z.totaal)],
    ['Threshold: ' + pctEn(C.zorgkosten_drempel_pct) + ' of ' + en(v.inkomen), '− ' + en(z.drempel)],
    ['Deduction', en(z.aftrek)],
    ['Tax saving at ' + pctEn(C.box1_schijf1_tarief), '± ' + en(z.voordeel)]
  ];
  return tabel(id, 'Healthcare costs example ' + JAAR + ': threshold income ' + en(v.inkomen) + ', no partner, below the state pension age',
    ['Item', 'Amount'], rijen);
}
function pct(n) { return String(Math.round(n * 10000) / 100).replace('.', ',') + '%'; }

/* ---------- giftenaftrek ---------- */
function giftenTabel(id) {
  const rijen = [5000, 15000, 25000, 35000, 45000, 60000, 80000, 100000].map((ink) => {
    const r = R.giftenaftrek(C, { inkomen: ink });
    return [euro(ink), euro(r.drempel), euro(r.maximum)];
  });
  return tabel(id, 'Drempel en maximum giftenaftrek ' + JAAR + ' (gewone giften)', ['Drempelinkomen', 'Drempel', 'Maximum aftrek'], rijen);
}
const giften = (i) => euro(R.giftenaftrek(C, i).aftrek);

/* ---------- belasting met AOW en pensioen ---------- */
// eerst afronden, dan aftrekken, zoals de rekentool
function aowVerschuldigd(inkomen, alleenstaand) {
  const r = R.aowBelasting(C, { pensioen: inkomen, alleenstaand });
  let rest = Math.round(r.heffing);
  for (const k of [r.ahk, r.ouderenkorting, r.alleenstaand]) rest -= Math.min(Math.round(k), rest);
  return rest;
}
function aowTabel(id) {
  const rijen = [20000, 25000, 30000, 35000, 40000, 45000, 50000, 60000, 75000].map((ink) => {
    const a = aowVerschuldigd(ink, true), s = aowVerschuldigd(ink, false);
    return [euro(ink), a ? euro(a) : GEEN, s ? euro(s) : GEEN];
  });
  return tabel(id, 'Inkomstenbelasting ' + JAAR + ' per jaar, het hele jaar de AOW-leeftijd',
    ['AOW en pensioen samen', 'AOW voor alleenstaanden', 'AOW met partner'], rijen);
}
// tot welk inkomen u geen belasting betaalt, naar beneden afgerond op honderden
function aowBelastingvrij(alleenstaand) {
  let ink = 0;
  while (aowVerschuldigd(ink + 100, alleenstaand) === 0) ink += 100;
  return euro(ink);
}

/* ---------- kindgebonden budget ---------- */
function kgbTabel(id, partner, inkomens) {
  const grens = partner ? C.kindgebonden_budget_inkomensgrens_partners : C.kindgebonden_budget_inkomensgrens_alleen;
  const rijen = [grens].concat(inkomens).map((ink, i) => [i === 0 ? euro(ink) + ' of minder' : euro(ink)].concat([1, 2, 3].map((n) => {
    const m = R.kindgebondenBudget(C, { partner, inkomen: ink, jong: n }).maand;
    return m ? euro(m) : GEEN;
  })));
  return tabel(id, 'Kindgebonden budget ' + JAAR + ' per maand' + (partner ? ', met toeslagpartner' : ', alleenstaande ouder') + ' (kinderen jonger dan 12)',
    [partner ? 'Inkomen samen' : 'Inkomen', '1 kind', '2 kinderen', '3 kinderen'], rijen);
}
const kgbMaand = (i) => euro(R.kindgebondenBudget(C, i).maand);

/* ---------- box 3 ---------- */
const BOX3_VERMOGENS = [75000, 100000, 150000, 200000, 250000, 300000, 400000, 500000, 750000, 1000000];
function box3Tabel(id, partner) {
  const rijen = BOX3_VERMOGENS.map((v) => {
    const s = R.box3(C, { partner, bank: v }).belasting, b = R.box3(C, { partner, overig: v }).belasting;
    return [euro(v), s ? euro(s) : GEEN, b ? euro(b) : GEEN];
  });
  return tabel(id, 'Box 3-belasting ' + JAAR + (partner ? ' met een fiscale partner (samen)' : ' zonder fiscale partner'),
    ['Vermogen op 1 januari', 'Alleen spaargeld', 'Alleen beleggingen'], rijen);
}

const TABELLEN = {
  'giften-drempel': giftenTabel,
  'aow-belasting': aowTabel,
  'kindgebonden-budget-alleen': (id) => kgbTabel(id, false, [35000, 40000, 45000, 50000, 60000, 70000, 80000, 100000]),
  'kindgebonden-budget-partners': (id) => kgbTabel(id, true, [45000, 50000, 55000, 60000, 70000, 80000, 90000, 110000]),
  'box3-alleen': (id) => box3Tabel(id, false),
  'box3-partners': (id) => box3Tabel(id, true),
  'zorgkosten-drempel': zorgkostenDrempelTabel,
  'zorgkosten-voorbeeld': zorgkostenVoorbeeld,
  'zorgkosten-voorbeeld-en': zorgkostenVoorbeeldEn,
  'zorgkosten-drempel-en': zorgkostenDrempelTabelEn,
  'erfbelasting-tabel': (id) => erfschenkTabel(id, 'erf', 'Erfbelasting ' + JAAR + ' per erfgenaam',
    [['Partner', 'partner'], ['Kind', 'kind'], ['Kleinkind', 'kleinkind'], ['Broer, zus, ander', 'overig']],
    [25000, 50000, 100000, 150000, 200000, 300000, 500000, 1000000]),
  'schenkbelasting-tabel': (id) => erfschenkTabel(id, 'schenk', 'Schenkbelasting ' + JAAR + ' per ontvanger',
    [['Kind', 'kind'], ['Kind 18-40, eenmalig', 'kind-eenmalig'], ['Kleinkind', 'kleinkind'], ['Iemand anders', 'overig']],
    [5000, 10000, 25000, 50000, 100000, 250000]),
  'inkomstenbelasting-loon': belastingBijLoon,
  'zorgtoeslag-alleenstaand': (id) => zorgtoeslagTabel(id, false),
  'zorgtoeslag-partners': (id) => zorgtoeslagTabel(id, true),
  'huurtoeslag-1': (id) => huurtoeslagTabel(id, 1, 'Huurtoeslag ' + JAAR + ' per maand: 1 persoon, 21 jaar of ouder',
    [0, 25000, 27500, 30000, 32500, 35000, 40000, 45000]),
  'huurtoeslag-2': (id) => huurtoeslagTabel(id, 2, 'Huurtoeslag ' + JAAR + ' per maand: 2 personen',
    [0, 35000, 40000, 45000, 50000, 55000, 60000]),
  'huurtoeslag-3': (id) => huurtoeslagTabel(id, 3, 'Huurtoeslag ' + JAAR + ' per maand: 3 personen of meer',
    [0, 35000, 40000, 45000, 50000, 55000, 60000]),
  'huurtoeslag-jongeren': huurtoeslagJongeren,
  'huurtoeslag-nulpunt': huurtoeslagNulpunt
};

const erfschenk = (soort, relatie, bedrag) => euro(R.erfschenkbelasting(C, { soort, relatie, bedrag }).belasting);

const WAARDEN = {
  // de voorbeelden 1 en 3 van belastingdienst.nl (culturele ANBI)
  'giften-vb1': () => giften({ inkomen: 35000, gewoon: 5000, gewoonCultureel: 200 }),
  'giften-vb3': () => giften({ inkomen: 40000, periodiek: 4000, periodiekCultureel: 4000, gewoon: 2400, gewoonCultureel: 2400 }),
  'giften-45k-900': () => giften({ inkomen: 45000, gewoon: 900 }),
  'aow-belastingvrij-alleen': () => aowBelastingvrij(true),
  'aow-belastingvrij-samen': () => aowBelastingvrij(false),
  'aow-30k-alleen': () => euro(aowVerschuldigd(30000, true)),
  'aow-belastingvrij-alleen-en': () => euroEn(Number(aowBelastingvrij(true).replace(/\D/g, ''))),
  'aow-belastingvrij-samen-en': () => euroEn(Number(aowBelastingvrij(false).replace(/\D/g, ''))),
  'kgb-max-maand-alleen-1': () => kgbMaand({ jong: 1 }),
  'kgb-max-maand-partners-1': () => kgbMaand({ partner: true, jong: 1 }),
  'kgb-max-maand-partners-2': () => kgbMaand({ partner: true, jong: 2 }),
  // de rekenvoorbeelden 1 en 3 van Dienst Toeslagen
  'kgb-vb1-maand': () => kgbMaand({ partner: true, inkomen: 45000, jong: 2 }),
  'kgb-vb3-maand': () => kgbMaand({ inkomen: 30000, jong: 1 }),
  // tot welk inkomen er nog iets is, afgerond op honderden
  'kgb-nulpunt-alleen-1': () => euro(Math.floor(R.kindgebondenBudget(C, { jong: 1 }).nulpunt / 100) * 100),
  'kgb-nulpunt-partners-1': () => euro(Math.floor(R.kindgebondenBudget(C, { partner: true, jong: 1 }).nulpunt / 100) * 100),
  'box3-100k-spaargeld': () => euro(R.box3(C, { bank: 100000 }).belasting),
  'box3-100k-beleggingen': () => euro(R.box3(C, { overig: 100000 }).belasting),
  'box3-150k-spaargeld': () => euro(R.box3(C, { bank: 150000 }).belasting),
  'box3-150k-spaargeld-partners': () => euro(R.box3(C, { partner: true, bank: 150000 }).belasting),
  'zorgkosten-drempel-35000': () => euro(R.zorgkostenDrempel(C, false, 35000)),
  'zorgkosten-voorbeeld-aftrek': () => euro(zorgVoorbeeld().aftrek),
  'zorgkosten-voorbeeld-voordeel': () => euro(zorgVoorbeeld().voordeel),
  // het voorbeeld met de AOW-leeftijd: €800 medicijnen, drempelinkomen €24.000
  'zorgkosten-aow-verhoging': () => euro(R.zorgkosten(C, ZORG_AOW).verhoging),
  'zorgkosten-aow-drempel': () => euro(R.zorgkosten(C, ZORG_AOW).drempel),
  'zorgkosten-aow-aftrek': () => euro(R.zorgkosten(C, ZORG_AOW).aftrek),
  'zorgkosten-aow-aftrek-en': () => euroEn(R.zorgkosten(C, ZORG_AOW).aftrek),
  'erf-100k-kind': () => erfschenk('erf', 'kind', 100000),
  'erf-100k-kleinkind': () => erfschenk('erf', 'kleinkind', 100000),
  'erf-100k-overig': () => erfschenk('erf', 'overig', 100000),
  'schenk-10k-kind': () => erfschenk('schenk', 'kind', 10000),
  'inkomstenbelasting-vrij-tot': () => euro(belastingvrijLoon()),
  'zorgtoeslag-max-maand': () => euro(R.zorgtoeslag(C, { inkomen: 0 }).maand),
  'zorgtoeslag-max-maand-partners': () => euro(R.zorgtoeslag(C, { partner: true, inkomen: 0 }).maand),
  'huurtoeslag-max-maand-1': () => euro(R.huurtoeslag(C, { kaleHuur: 9999, personen: 1, iemand21: true, inkomen: 0 }).maand),
  'huurtoeslag-max-maand-2': () => euro(R.huurtoeslag(C, { kaleHuur: 9999, personen: 2, iemand21: true, inkomen: 0 }).maand),
  'huurtoeslag-max-maand-3': () => euro(R.huurtoeslag(C, { kaleHuur: 9999, personen: 3, iemand21: true, inkomen: 0 }).maand),
  'huurtoeslag-max-maand-jongeren': () => euro(R.huurtoeslag(C, { kaleHuur: 9999, personen: 1, iemand21: false, inkomen: 0 }).maand),
  // het rekenvoorbeeld op en/blog/rent-benefit/: kale huur €680, alleen, inkomen €22.000
  'huurtoeslag-voorbeeld-680': () => euro(R.huurtoeslag(C, { kaleHuur: 680, personen: 1, iemand21: true, inkomen: 22000 }).maand),
  'huurtoeslag-nulpunt-max-1': () => euro(nulpunt(9999, 1)),
  'huurtoeslag-nulpunt-max-2': () => euro(nulpunt(9999, 2)),
  'huurtoeslag-nulpunt-max-3': () => euro(nulpunt(9999, 3))
};

/* ---------- de pagina's ---------- */
function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['.git', 'node_modules', 'intern', 'app', 'docs', 'reports'].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}

const MARKERING = /<!-- (tabel|r):([a-z0-9-]+) -->([\s\S]*?)<!-- \/\1:\2 -->/g;
const fouten = [];
const afwijkend = [];
let blokken = 0;

for (const f of walk(ROOT, [])) {
  const rel = path.relative(ROOT, f).split(path.sep).join('/');
  const oud = fs.readFileSync(f, 'utf8');
  const nieuw = oud.replace(MARKERING, (heel, soort, naam, inhoud) => {
    const maak = (soort === 'tabel' ? TABELLEN : WAARDEN)[naam];
    if (!maak) { fouten.push(rel + ': onbekende ' + soort + ' "' + naam + '"'); return heel; }
    blokken++;
    const binnen = soort === 'tabel' ? '\n' + maak(naam) +'\n' : maak();
    return '<!-- ' + soort + ':' + naam + ' -->' + binnen + '<!-- /' + soort + ':' + naam + ' -->';
  });
  // een openingsmarkering zonder sluiting is vrijwel zeker een tikfout
  const open = (oud.match(/<!-- (tabel|r):[a-z0-9-]+ -->/g) || []).length;
  const dicht = (oud.match(/<!-- \/(tabel|r):[a-z0-9-]+ -->/g) || []).length;
  if (open !== dicht) fouten.push(rel + ': ' + open + ' openings- en ' + dicht + ' sluitmarkeringen');
  if (nieuw !== oud) {
    afwijkend.push(rel);
    if (!CHECK) fs.writeFileSync(f, nieuw);
  }
}

if (fouten.length) {
  console.error('FAIL:\n  ' + fouten.join('\n  '));
  process.exit(1);
}
if (CHECK && afwijkend.length) {
  console.error('FAIL: tabellen of bedragen wijken af van de rekenregels in: ' + afwijkend.join(', ') +
    '\nDraai node scripts/rekentabellen.js (zonder --check).');
  process.exit(1);
}
console.log((CHECK ? 'OK: ' : '') + blokken + ' tabellen en bedragen' +
  (CHECK ? ' kloppen met de rekenregels (' + JAAR + ').' : ', ' + afwijkend.length + ' bestand(en) bijgewerkt.'));
