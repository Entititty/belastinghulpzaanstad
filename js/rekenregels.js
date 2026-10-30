/*
 * rekenregels.js
 * De rekenregels achter de rekentools, los van de pagina.
 *
 * WAAROM APART
 * Dezelfde berekening wordt op drie plekken gebruikt: in de browser
 * (rekenhulp.js), voor de vaste tabellen in de HTML (scripts/rekentabellen.js)
 * en in de controle op de officiële rekenvoorbeelden
 * (scripts/check-rekenregels.js). Staat de formule op één plek, dan kunnen
 * de rekentool, de tabel en de controle niet uit elkaar lopen.
 *
 * DE CIJFERS
 * Komen uit data/fiscale-cijfers.json; cijfers() zet "€2.119" om in 2119 en
 * "13,73%" in 0.1373. Bij de jaarlijkse update volgen de rekentools en de
 * tabellen dus vanzelf.
 *
 * BRONNEN (2026)
 * - Zorgtoeslag: "Berekening zorgtoeslag 2026" van Dienst Toeslagen.
 * - Huurtoeslag: "Berekening huurtoeslag 2026" van Dienst Toeslagen, en de
 *   Wet op de huurtoeslag (art. 13, 20 en 21) waar de brochure kort is.
 * De rekenvoorbeelden uit beide brochures staan in check-rekenregels.js.
 *
 * Werkt in de browser (window.BHZRekenregels) en in Node (require).
 */
(function (root, maak) {
  var regels = maak();
  if (typeof module === 'object' && module.exports) module.exports = regels;
  else root.BHZRekenregels = regels;
})(this, function () {
  'use strict';

  // "€38.883" -> 38883, "35,75%" -> 0.3575, "€932,93" -> 932.93
  function getal(waarde) {
    var s = String(waarde).replace(/[€\s]/g, '');
    var pct = s.indexOf('%') !== -1;
    s = s.replace('%', '').replace(/\./g, '').replace(',', '.');
    var n = parseFloat(s);
    return pct ? n / 100 : n;
  }

  // de "cijfers" uit fiscale-cijfers.json als getallen
  function cijfers(lijst) {
    var C = {};
    Object.keys(lijst).forEach(function (k) {
      if (lijst[k] && lijst[k].waarde !== undefined) C[k] = getal(lijst[k].waarde);
    });
    return C;
  }

  // Dienst Toeslagen betaalt per maand in hele euro's, naar beneden afgerond.
  // De kleine marge vangt afrondingsruis op (307,9999999 is 308).
  function heleEuroOmlaag(n) {
    return n <= 0 ? 0 : Math.floor(n + 1e-9);
  }

  /*
   * ZORGTOESLAG
   * invoer: {
   *   partner: true/false          toeslagpartner?
   *   inkomen: getal                (gezamenlijk) toetsingsinkomen per jaar
   *   partnerVerzekerd: true/false  is de partner verzekerd voor de Wet op de
   *                                 zorgtoeslag (standaard ja; nee: 50%)
   *   vermogenTeHoog: true/false
   * }
   * Alleen voor wie in Nederland woont; de woonlandfactor voor het
   * buitenland zit er bewust niet in.
   */
  function zorgtoeslag(C, inv) {
    var partner = !!inv.partner;
    var inkomen = Math.max(0, Number(inv.inkomen) || 0);
    var standaardpremie = C.zorgtoeslag_standaardpremie * (partner ? 2 : 1);
    var normpct = partner ? C.zorgtoeslag_normpercentage_partners : C.zorgtoeslag_normpercentage_alleenstaand;
    var drempel = C.zorgtoeslag_drempelinkomen;
    var normpremie = normpct * drempel + C.zorgtoeslag_afbouwpercentage * Math.max(0, inkomen - drempel);
    var grens = partner ? C.zorgtoeslag_inkomensgrens_partners : C.zorgtoeslag_inkomensgrens_alleenstaand;
    var vermogensgrens = partner ? C.zorgtoeslag_vermogensgrens_partners : C.zorgtoeslag_vermogensgrens_alleenstaand;
    var half = partner && inv.partnerVerzekerd === false;

    var uit = {
      standaardpremie: standaardpremie, normpremie: normpremie, drempelinkomen: drempel,
      inkomensgrens: grens, vermogensgrens: vermogensgrens, half: half,
      jaar: 0, maandExact: 0, maand: 0, reden: ''
    };
    if (inv.vermogenTeHoog) { uit.reden = 'vermogen'; return uit; }
    if (inkomen > grens) { uit.reden = 'inkomen'; return uit; }
    var jaar = Math.max(0, standaardpremie - normpremie) * (half ? 0.5 : 1);
    if (jaar <= 0) { uit.reden = 'inkomen'; return uit; }
    uit.jaar = jaar;
    uit.maandExact = jaar / 12;
    uit.maand = heleEuroOmlaag(jaar / 12);
    if (!uit.maand) uit.reden = 'inkomen';
    return uit;
  }

  /*
   * HUURTOESLAG
   * invoer: {
   *   kaleHuur: getal          per maand, zonder servicekosten (die tellen
   *                            sinds 2026 niet meer mee)
   *   personen: 1, 2 of 3      3 = drie of meer
   *   iemand21: true/false     is iemand in het huishouden 21 of ouder?
   *   kindOfHandicap: true/false  alleen van belang als iedereen jonger is
   *                            dan 21: dan geldt toch de gewone huurgrens
   *   inkomen: getal           rekeninkomen: de toetsingsinkomens van het hele
   *                            huishouden samen (kinderen onder 23 alleen
   *                            boven de vrijstelling)
   *   vermogenTeHoog: true/false
   * }
   * Stap 1 t/m 7 uit de brochure. De brochure laat jongeren onder 21 alleen
   * deel A berekenen; dat volgt vanzelf uit de lage huurgrens (gelijk aan de
   * kwaliteitskortingsgrens). De inkomenscorrectie geldt volgens art. 21 lid 2
   * van de wet voor elk huishouden, dus ook hier.
   */
  function huurtoeslag(C, inv) {
    var personen = Number(inv.personen) >= 3 ? 3 : Number(inv.personen) === 2 ? 2 : 1;
    var meer = personen > 1;
    var kaleHuur = Math.max(0, Number(inv.kaleHuur) || 0);
    var inkomen = Math.max(0, Number(inv.inkomen) || 0);
    var jongeren = inv.iemand21 === false && !inv.kindOfHandicap;

    var huurgrens = jongeren ? C.huurtoeslag_jongerengrens : C.huurtoeslag_rekenhuur_max;
    var rekenhuur = Math.min(kaleHuur, huurgrens);
    var basishuur = meer ? C.huurtoeslag_basishuur_meerpersoons : C.huurtoeslag_minimum_basishuur_eenpersoons;
    var kkg = C.huurtoeslag_kwaliteitskortingsgrens;
    var atg = personen >= 3 ? C.huurtoeslag_aftoppingsgrens_hoog : C.huurtoeslag_aftoppingsgrens_laag;
    var ijkpunt = meer ? C.huurtoeslag_inkomensijkpunt_meerpersoons : C.huurtoeslag_inkomensijkpunt_eenpersoons;
    var afbouw = meer ? C.huurtoeslag_afbouwpercentage_meerpersoons : C.huurtoeslag_afbouwpercentage_eenpersoons;

    var a = Math.max(0, Math.min(rekenhuur, kkg) - basishuur);
    var b = rekenhuur > kkg ? C.huurtoeslag_vergoeding_tot_aftoppingsgrens * (Math.min(rekenhuur, atg) - kkg) : 0;
    var c = rekenhuur > atg ? C.huurtoeslag_vergoeding_boven_aftoppingsgrens * (rekenhuur - atg) : 0;
    var d = Math.max(0, inkomen - ijkpunt) * afbouw / 12;
    var bruto = a + b + c;

    var uit = {
      rekenhuur: rekenhuur, huurgrens: huurgrens, boven_huurgrens: kaleHuur > huurgrens,
      basishuur: basishuur, kwaliteitskortingsgrens: kkg, aftoppingsgrens: atg,
      ijkpunt: ijkpunt, afbouw: afbouw, jongeren: jongeren, personen: personen,
      a: a, b: b, c: c, d: d,
      // tot dit inkomen is er bij deze huur nog huurtoeslag
      nulpunt: bruto > 0 ? ijkpunt + bruto * 12 / afbouw : 0,
      maandExact: 0, maand: 0, jaar: 0, reden: ''
    };
    if (inv.vermogenTeHoog) { uit.reden = 'vermogen'; return uit; }
    if (rekenhuur <= basishuur) { uit.reden = 'huur'; return uit; }
    var totaal = bruto - d;
    if (totaal <= 0) { uit.reden = 'inkomen'; return uit; }
    uit.maandExact = totaal;
    uit.maand = heleEuroOmlaag(totaal);
    uit.jaar = uit.maand * 12;
    if (!uit.maand) uit.reden = 'inkomen';
    return uit;
  }

  return { getal: getal, cijfers: cijfers, heleEuroOmlaag: heleEuroOmlaag, zorgtoeslag: zorgtoeslag, huurtoeslag: huurtoeslag };
});
