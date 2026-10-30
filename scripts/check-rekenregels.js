#!/usr/bin/env node
/*
 * check-rekenregels.js
 * Rekent de rekenvoorbeelden van Dienst Toeslagen na met js/rekenregels.js,
 * de code achter de rekentools en de tabellen. Faalt (exit 1) bij een
 * verschil.
 *
 * WAAROM
 * Een rekentool die een verkeerd bedrag noemt, kost meer vertrouwen dan hij
 * bezoekers oplevert. De brochures "Berekening zorgtoeslag" en "Berekening
 * huurtoeslag" rekenen elk jaar een paar voorbeelden helemaal uit. Komen wij
 * op hetzelfde bedrag, dan klopt de formule; met de cijfers uit
 * data/fiscale-cijfers.json, dus ook die worden zo gecontroleerd.
 *
 * NA DE JAARWISSELING
 * De voorbeelden horen bij één belastingjaar. Staat in fiscale-cijfers.json
 * een ander jaar dan VOORBEELDJAAR, dan faalt dit script tot de voorbeelden
 * uit de nieuwe brochures hieronder staan (docs/jaarlijkse-update.md).
 *
 * Daarnaast een paar eigenschappen die altijd moeten gelden: nooit een
 * negatief bedrag, meer inkomen geeft nooit meer toeslag, en boven de grens
 * is het nul.
 *
 * GEBRUIK
 *   node scripts/check-rekenregels.js
 */
const fs = require('fs');
const path = require('path');
const R = require('../js/rekenregels.js');

const ROOT = path.resolve(__dirname, '..');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'fiscale-cijfers.json'), 'utf8'));
const C = R.cijfers(data.cijfers);

const VOORBEELDJAAR = 2026;
const fouten = [];
let getoetst = 0;

function gelijk(wat, kreeg, verwacht, marge) {
  getoetst++;
  if (Math.abs(kreeg - verwacht) > (marge === undefined ? 0.005 : marge)) {
    fouten.push(wat + ': ' + kreeg.toFixed(2) + ', verwacht ' + verwacht.toFixed(2));
  }
}

if (data.belastingjaar !== VOORBEELDJAAR) {
  fouten.push('fiscale-cijfers.json is voor ' + data.belastingjaar + ', de rekenvoorbeelden hieronder voor ' + VOORBEELDJAAR +
    '. Zet de voorbeelden uit de nieuwe brochures erin (docs/jaarlijkse-update.md).');
}

/* ---------- zorgtoeslag: Berekening zorgtoeslag 2026, rekenvoorbeeld 1 en 2 ----------
   Voorbeeld 3 woont in België; de woonlandfactor zit niet in de rekentool. */
let z = R.zorgtoeslag(C, { partner: false, inkomen: 19000 });
gelijk('zorgtoeslag vb 1 (Wouter): normpremie', z.normpremie, 568.55);
gelijk('zorgtoeslag vb 1 (Wouter): per jaar', z.jaar, 1550.45);
gelijk('zorgtoeslag vb 1 (Wouter): per maand', z.maandExact, 129.20);
gelijk('zorgtoeslag vb 1 (Wouter): uitbetaald per maand', z.maand, 129, 0);

z = R.zorgtoeslag(C, { partner: true, inkomen: 7000 + 26200, partnerVerzekerd: false });
gelijk('zorgtoeslag vb 2 (Marit en Rik): normpremie', z.normpremie, 1750.98);
gelijk('zorgtoeslag vb 2 (Marit en Rik): per jaar', z.jaar, 1243.51);
gelijk('zorgtoeslag vb 2 (Marit en Rik): uitbetaald per maand', z.maand, 103, 0);

// het maximum uit de brochure (€ 1.550 en € 2.963, afgerond op hele euro's)
gelijk('zorgtoeslag maximum alleenstaand', Math.round(R.zorgtoeslag(C, { inkomen: 0 }).jaar), C.zorgtoeslag_max_alleenstaand, 0);
gelijk('zorgtoeslag maximum met partner', Math.round(R.zorgtoeslag(C, { partner: true, inkomen: 0 }).jaar), C.zorgtoeslag_max_partners, 0);

/* ---------- huurtoeslag: Berekening huurtoeslag 2026, rekenvoorbeeld 1 t/m 3 ---------- */
let h = R.huurtoeslag(C, { kaleHuur: 600, personen: 1, iemand21: false, inkomen: 22000 });
gelijk('huurtoeslag vb 1 (Sem, 20 jaar): rekenhuur', h.rekenhuur, 498.20);
gelijk('huurtoeslag vb 1 (Sem): deel A', h.a, 295.68);
gelijk('huurtoeslag vb 1 (Sem): per maand', h.maand, 295, 0);

h = R.huurtoeslag(C, { kaleHuur: 1200, personen: 3, iemand21: true, inkomen: 26000 + 8000 });
gelijk('huurtoeslag vb 2 (Demi en Sophie): deel A', h.a, 297.49);
gelijk('huurtoeslag vb 2 (Demi en Sophie): deel B', h.b, 172.86);
gelijk('huurtoeslag vb 2 (Demi en Sophie): deel C', h.c, 67.51, 0.01);
gelijk('huurtoeslag vb 2 (Demi en Sophie): correctie', h.d, 45.83);
gelijk('huurtoeslag vb 2 (Demi en Sophie): per maand', h.maand, 492, 0);

h = R.huurtoeslag(C, { kaleHuur: 710, personen: 1, iemand21: true, inkomen: 29000 });
gelijk('huurtoeslag vb 3 (Marina): deel B', h.b, 137.67);
gelijk('huurtoeslag vb 3 (Marina): deel C', h.c, 0);
gelijk('huurtoeslag vb 3 (Marina): correctie', h.d, 125.44, 0.01);
gelijk('huurtoeslag vb 3 (Marina): per maand', h.maand, 307, 0);

/* ---------- inkomstenbelasting: de randen van de tabellen 2026 ----------
   De tabellen algemene heffingskorting en arbeidskorting noemen per schijf een
   startbedrag (€ 996, € 5.300, € 5.685). Op elke grens moeten twee schijven op
   minder dan €1 na hetzelfde geven, anders staat er een cijfer verkeerd. */
gelijk('algemene heffingskorting tot de afbouwgrens', R.algemeneHeffingskorting(C, C.ahk_afbouwgrens), C.algemene_heffingskorting_max);
gelijk('algemene heffingskorting bij €50.000', R.algemeneHeffingskorting(C, 50000), C.algemene_heffingskorting_max - C.ahk_afbouwpercentage * (50000 - C.ahk_afbouwgrens));
gelijk('algemene heffingskorting vanaf €78.427 nul', R.algemeneHeffingskorting(C, 78427), 0, 0.5);
gelijk('arbeidskorting bij €11.965', R.arbeidskorting(C, C.arbeidskorting_grens1), C.arbeidskorting_bedrag2, 0.5);
gelijk('arbeidskorting bij €25.845', R.arbeidskorting(C, C.arbeidskorting_grens2), C.arbeidskorting_bedrag3, 0.5);
gelijk('arbeidskorting bij €45.592', R.arbeidskorting(C, C.arbeidskorting_grens3), C.arbeidskorting_max, 0.5);
gelijk('arbeidskorting vanaf €132.921 nul', R.arbeidskorting(C, 132921), 0, 0.5);
for (const g of [C.arbeidskorting_grens1, C.arbeidskorting_grens2, C.arbeidskorting_grens3]) {
  gelijk('arbeidskorting sluit aan bij ' + g, R.arbeidskorting(C, g + 1), R.arbeidskorting(C, g), 1);
}
gelijk('box 1 tot de eerste schijfgrens', R.box1(C, C.box1_schijf1_grens), C.box1_schijf1_grens * C.box1_schijf1_tarief);
gelijk('box 1 tot de tweede schijfgrens', R.box1(C, C.box1_schijf2_grens),
  C.box1_schijf1_grens * C.box1_schijf1_tarief + (C.box1_schijf2_grens - C.box1_schijf1_grens) * C.box1_schijf2_tarief);
gelijk('box 1 boven de tweede schijfgrens', R.box1(C, C.box1_schijf2_grens + 1000) - R.box1(C, C.box1_schijf2_grens), 1000 * C.box1_schijf3_tarief);

/* ---------- eigenschappen ---------- */
{
  let vorige = -1;
  for (let loon = 0; loon <= 150000; loon += 100) {
    const r = R.belastingteruggave(C, { loon, ingehouden: 0 });
    eigenschap('verschuldigde belasting negatief bij loon ' + loon, r.verschuldigd >= 0);
    eigenschap('meer loon geeft minder belasting bij ' + loon, r.verschuldigd >= vorige - 1e-9);
    vorige = r.verschuldigd;
  }
  eigenschap('teruggave = ingehouden - verschuldigd',
    Math.abs(R.belastingteruggave(C, { loon: 20000, ingehouden: 2000 }).verschil - (2000 - R.belastingteruggave(C, { loon: 20000, ingehouden: 0 }).verschuldigd)) < 1e-9);
}
function eigenschap(wat, ok) { getoetst++; if (!ok) fouten.push(wat); }

for (const partner of [false, true]) {
  let vorige = Infinity;
  const grens = partner ? C.zorgtoeslag_inkomensgrens_partners : C.zorgtoeslag_inkomensgrens_alleenstaand;
  for (let ink = 0; ink <= grens + 5000; ink += 250) {
    const r = R.zorgtoeslag(C, { partner, inkomen: ink });
    eigenschap('zorgtoeslag ' + (partner ? 'partner' : 'alleen') + ' negatief bij ' + ink, r.jaar >= 0);
    eigenschap('zorgtoeslag ' + (partner ? 'partner' : 'alleen') + ' stijgt bij inkomen ' + ink, r.jaar <= vorige + 1e-9);
    if (ink > grens) eigenschap('zorgtoeslag boven de inkomensgrens bij ' + ink, r.jaar === 0);
    vorige = r.jaar;
  }
}
eigenschap('zorgtoeslag zonder recht bij te veel vermogen', R.zorgtoeslag(C, { inkomen: 10000, vermogenTeHoog: true }).jaar === 0);

for (const personen of [1, 2, 3]) {
  for (const huur of [150, 300, 498.2, 600, 713.02, 800, 932.93, 1500]) {
    let vorige = Infinity;
    for (let ink = 0; ink <= 80000; ink += 500) {
      const r = R.huurtoeslag(C, { kaleHuur: huur, personen, iemand21: true, inkomen: ink });
      eigenschap('huurtoeslag negatief (' + personen + 'p, huur ' + huur + ', inkomen ' + ink + ')', r.maand >= 0);
      eigenschap('huurtoeslag stijgt met inkomen (' + personen + 'p, huur ' + huur + ', inkomen ' + ink + ')', r.maandExact <= vorige + 1e-9);
      vorige = r.maandExact;
    }
    const nul = R.huurtoeslag(C, { kaleHuur: huur, personen, iemand21: true, inkomen: 0 });
    if (nul.nulpunt) {
      const erboven = R.huurtoeslag(C, { kaleHuur: huur, personen, iemand21: true, inkomen: nul.nulpunt + 1 });
      eigenschap('huurtoeslag boven het nulpunt (' + personen + 'p, huur ' + huur + ')', erboven.maand === 0);
    }
  }
}
eigenschap('huurtoeslag: huur boven de huurgrens telt als de huurgrens',
  R.huurtoeslag(C, { kaleHuur: 2000, personen: 1, iemand21: true, inkomen: 0 }).maand ===
  R.huurtoeslag(C, { kaleHuur: C.huurtoeslag_rekenhuur_max, personen: 1, iemand21: true, inkomen: 0 }).maand);
eigenschap('huurtoeslag: jongere met kind krijgt de gewone huurgrens',
  R.huurtoeslag(C, { kaleHuur: 800, personen: 2, iemand21: false, kindOfHandicap: true, inkomen: 0 }).rekenhuur === 800);
eigenschap('huurtoeslag zonder recht bij te veel vermogen', R.huurtoeslag(C, { kaleHuur: 600, personen: 1, iemand21: true, inkomen: 10000, vermogenTeHoog: true }).maand === 0);

if (fouten.length) {
  console.error('FAIL: ' + fouten.length + ' van de ' + getoetst + ' controles:');
  fouten.forEach((f) => console.error('  - ' + f));
  process.exit(1);
}
console.log('OK: ' + getoetst + ' controles, de rekenvoorbeelden van Dienst Toeslagen en de tabellen van de Belastingdienst (' + VOORBEELDJAAR + ') kloppen.');
