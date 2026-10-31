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
 * - Inkomstenbelasting: de tarieven box 1 en de tabellen algemene
 *   heffingskorting en arbeidskorting 2026 van de Belastingdienst.
 * - Box 3: de berekening van het box 3-inkomen 2026 van de Belastingdienst.
 * - Kindgebonden budget: "Berekening kindgebonden budget 2026" van Dienst
 *   Toeslagen.
 * De rekenvoorbeelden uit de brochures en de randen van de tabellen staan in
 * check-rekenregels.js.
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

  /*
   * INKOMSTENBELASTING BOX 1, voor wie de AOW-leeftijd nog niet heeft
   * Tarieven en de tabellen algemene heffingskorting en arbeidskorting 2026
   * van de Belastingdienst. De schijfgrenzen in die tabellen ("vanaf € 11.966")
   * en de formules ("- € 11.965") staan hier zoals daar.
   */
  function box1(C, inkomen) {
    var g1 = C.box1_schijf1_grens, g2 = C.box1_schijf2_grens;
    return Math.min(inkomen, g1) * C.box1_schijf1_tarief +
      Math.max(0, Math.min(inkomen, g2) - g1) * C.box1_schijf2_tarief +
      Math.max(0, inkomen - g2) * C.box1_schijf3_tarief;
  }

  function algemeneHeffingskorting(C, verzamelinkomen) {
    if (verzamelinkomen <= C.ahk_afbouwgrens) return C.algemene_heffingskorting_max;
    return Math.max(0, C.algemene_heffingskorting_max - C.ahk_afbouwpercentage * (verzamelinkomen - C.ahk_afbouwgrens));
  }

  function arbeidskorting(C, arbeidsinkomen) {
    var ai = arbeidsinkomen;
    if (ai <= 0) return 0;
    if (ai <= C.arbeidskorting_grens1) return C.arbeidskorting_pct1 * ai;
    if (ai <= C.arbeidskorting_grens2) return C.arbeidskorting_bedrag2 + C.arbeidskorting_pct2 * (ai - C.arbeidskorting_grens1);
    if (ai <= C.arbeidskorting_grens3) return C.arbeidskorting_bedrag3 + C.arbeidskorting_pct3 * (ai - C.arbeidskorting_grens2);
    return Math.max(0, C.arbeidskorting_max - C.arbeidskorting_afbouwpercentage * (ai - C.arbeidskorting_grens3));
  }

  /*
   * BELASTINGTERUGGAVE voor wie alleen loon heeft
   * invoer: { loon: fiscaal loon (loon voor de loonheffing, alle werkgevers samen),
   *           ingehouden: ingehouden loonheffing, aow: true/false }
   * Verschuldigd = box 1 min de heffingskortingen, nooit minder dan nul: een
   * heffingskorting verlaagt alleen de belasting die er is. Zonder
   * aftrekposten, ander inkomen of box 3.
   */
  function belastingteruggave(C, inv) {
    var loon = Math.max(0, Number(inv.loon) || 0);
    var ingehouden = Math.max(0, Number(inv.ingehouden) || 0);
    var heffing = box1(C, loon);
    var ahk = algemeneHeffingskorting(C, loon);
    var ak = arbeidskorting(C, loon);
    var kortingen = Math.min(heffing, ahk + ak);
    var verschuldigd = heffing - kortingen;
    return {
      reden: inv.aow ? 'aow' : '',
      heffing: heffing, ahk: ahk, ak: ak, kortingen: kortingen,
      verschuldigd: verschuldigd, ingehouden: ingehouden,
      verschil: inv.aow ? 0 : ingehouden - verschuldigd
    };
  }

  /*
   * ERFBELASTING EN SCHENKBELASTING
   * invoer: { soort: 'erf' of 'schenk', relatie, bedrag }
   * Belastbaar is het bedrag min de vrijstelling. Daarover het lage tarief tot
   * de schijfgrens en het hoge daarboven (vrijstellingen en tarieven 2026 van
   * de Belastingdienst). Per relatie: [sleutel van de vrijstelling, tariefgroep].
   * Groep 1: partner en kinderen; 1a: kleinkinderen en verder; 2: de rest,
   * ook ouders, broers en zussen.
   */
  var ERFSCHENK = {
    erf: {
      partner: ['erf_vrijstelling_partner', '1'],
      kind: ['erf_vrijstelling_kind', '1'],
      'kind-beperking': ['erf_vrijstelling_kind_beperking', '1'],
      kleinkind: ['erf_vrijstelling_kind', '1a'],
      achterkleinkind: ['erf_vrijstelling_overig', '1a'],
      ouder: ['erf_vrijstelling_ouders', '2'],
      overig: ['erf_vrijstelling_overig', '2']
    },
    schenk: {
      kind: ['schenk_vrijstelling_kind', '1'],
      'kind-eenmalig': ['schenk_vrijstelling_kind_eenmalig', '1'],
      'kind-studie': ['schenk_vrijstelling_studie', '1'],
      kleinkind: ['erf_vrijstelling_overig', '1a'],
      overig: ['erf_vrijstelling_overig', '2']
    }
  };

  function erfschenkbelasting(C, inv) {
    var regel = (ERFSCHENK[inv.soort] || {})[inv.relatie];
    if (!regel) throw new Error('onbekende relatie: ' + inv.soort + '/' + inv.relatie);
    var bedrag = Math.max(0, Number(inv.bedrag) || 0);
    var vrijstelling = C[regel[0]];
    var groep = regel[1];
    var laagPct = C['erfschenk_tarief_groep' + groep + '_laag'];
    var hoogPct = C['erfschenk_tarief_groep' + groep + '_hoog'];
    var grens = C.erfschenk_schijfgrens;
    var belastbaar = Math.max(0, bedrag - vrijstelling);
    var laag = Math.min(belastbaar, grens) * laagPct;
    var hoog = Math.max(0, belastbaar - grens) * hoogPct;
    return {
      vrijstelling: vrijstelling, belastbaar: belastbaar, groep: groep, grens: grens,
      tariefLaag: laagPct, tariefHoog: hoogPct, laag: laag, hoog: hoog, belasting: laag + hoog
    };
  }

  /*
   * AFTREK SPECIFIEKE ZORGKOSTEN
   * invoer: { partner: hele jaar een fiscale partner, drempelinkomen (samen),
   *           aow: u of uw partner op 1 januari de AOW-leeftijd,
   *           behandeling: genees- en heelkundige hulp (huisarts, tandarts,
   *             fysiotherapie...), ziekenbezoek: reiskosten ziekenbezoek,
   *           verhoogbaar: medicijnen, hulpmiddelen, vervoer, dieet, extra
   *             gezinshulp, kleding en beddengoed }
   * Volgorde uit het Handboek (17.4): eerst de verhoging (40% of 113%) over
   * de verhoogbare kosten, als het drempelinkomen niet hoger is dan de grens;
   * dan behandeling en ziekenbezoek erbij; dan de drempel eraf.
   */
  function zorgkostenDrempel(C, partner, inkomen) {
    if (inkomen <= (partner ? C.zorgkosten_drempel_grens_partners : C.zorgkosten_drempel_grens_alleen)) {
      return partner ? C.zorgkosten_drempel_vast_partners : C.zorgkosten_drempel_vast_alleen;
    }
    if (inkomen <= C.zorgkosten_drempel_grens_hoog) return C.zorgkosten_drempel_pct * inkomen;
    return C.zorgkosten_drempel_bedrag_hoog + C.zorgkosten_drempel_pct_hoog * (inkomen - C.zorgkosten_drempel_grens_hoog);
  }

  function zorgkosten(C, inv) {
    var inkomen = Math.max(0, Number(inv.drempelinkomen) || 0);
    var verhoogbaar = Math.max(0, Number(inv.verhoogbaar) || 0);
    var behandeling = Math.max(0, Number(inv.behandeling) || 0);
    var ziekenbezoek = Math.max(0, Number(inv.ziekenbezoek) || 0);
    var verhogingPct = inkomen <= C.zorgkosten_verhoging_grens ? (inv.aow ? C.zorgkosten_verhoging_pct_aow : C.zorgkosten_verhoging_pct) : 0;
    var verhoging = verhoogbaar * verhogingPct;
    var totaal = verhoogbaar + verhoging + behandeling + ziekenbezoek;
    var drempel = zorgkostenDrempel(C, !!inv.partner, inkomen);
    return {
      verhoogbaar: verhoogbaar, verhogingPct: verhogingPct, verhoging: verhoging,
      behandeling: behandeling, ziekenbezoek: ziekenbezoek, totaal: totaal,
      drempel: drempel, aftrek: Math.max(0, totaal - drempel)
    };
  }

  /*
   * BOX 3 (forfaitair, vermogen op 1 januari)
   * invoer: { partner: het hele jaar een fiscale partner, bank: banktegoeden,
   *           overig: beleggingen en andere bezittingen, schulden: schulden in
   *           box 3 (niet de eigenwoningschuld), verdeling: deel van de
   *           grondslag bij de eerste partner (standaard de helft) }
   * Stappen van belastingdienst.nl, "Hoe is het box 3-inkomen op mijn
   * voorlopige aanslag 2026 berekend?". De tekst daar zegt "rond af op 3
   * decimalen", maar alle vijf rekenvoorbeelden kappen het percentage af op 2
   * decimalen en ronden de bedragen naar beneden af. Zo rekenen wij ook: dan
   * komen we op de euro uit op hun voorbeelden (check-rekenregels.js).
   */
  function omlaag(n) { return Math.floor(n + 1e-6); }

  function box3(C, inv) {
    var partner = !!inv.partner;
    var bank = Math.max(0, Number(inv.bank) || 0);
    var overig = Math.max(0, Number(inv.overig) || 0);
    var schulden = Math.max(0, Number(inv.schulden) || 0);
    var drempel = C.box3_schuldendrempel_alleenstaand * (partner ? 2 : 1);
    var aftrekbareSchulden = Math.max(0, schulden - drempel);
    // stap 1: het fictieve rendement
    var rendement = omlaag(bank * C.box3_forfait_spaargeld + overig * C.box3_forfait_beleggingen -
      aftrekbareSchulden * C.box3_forfait_schulden);
    // stap 2 en 3: de grondslag, en wat boven het heffingsvrij vermogen uitkomt
    var grondslag = bank + overig - aftrekbareSchulden;
    var heffingvrij = partner ? C.box3_heffingvrij_partners : C.box3_heffingvrij_alleenstaand;
    var boven = Math.max(0, grondslag - heffingvrij);
    // stap 4 tot 6, per persoon: aandeel in procenten, voordeel, belasting
    var delen = partner ? [Number(inv.verdeling === undefined ? 0.5 : inv.verdeling)] : [1];
    if (partner) delen.push(1 - delen[0]);
    var personen = delen.map(function (d) {
      if (rendement <= 0 || boven <= 0 || grondslag <= 0) return { grondslag: boven * d, pct: 0, voordeel: 0, belasting: 0 };
      var pct = Math.floor(boven * d / grondslag * 10000 + 1e-6) / 100;
      var voordeel = omlaag(rendement * pct / 100);
      return { grondslag: boven * d, pct: pct, voordeel: voordeel, belasting: omlaag(voordeel * C.box3_tarief) };
    });
    return {
      drempel: drempel, aftrekbareSchulden: aftrekbareSchulden, rendement: rendement,
      grondslag: grondslag, heffingvrij: heffingvrij, boven: boven, personen: personen,
      voordeel: personen.reduce(function (s, p) { return s + p.voordeel; }, 0),
      belasting: personen.reduce(function (s, p) { return s + p.belasting; }, 0)
    };
  }

  /*
   * KINDGEBONDEN BUDGET
   * invoer: { partner: toeslagpartner, inkomen: (gezamenlijk) toetsingsinkomen,
   *           jong: kinderen tot 12, k12: kinderen van 12 t/m 15,
   *           k16: kinderen van 16 en 17, vermogenTeHoog }
   * De vijf stappen uit "Berekening kindgebonden budget 2026" van Dienst
   * Toeslagen: het maximum uit de tabel (1 kind, 2 kinderen, plus een bedrag
   * vanaf het 3e kind), de verhoging voor kinderen van 12 en ouder, en 7,6% van
   * het inkomen boven de grens eraf. Per maand in hele euro's, naar beneden.
   */
  function kindgebondenBudget(C, inv) {
    var partner = !!inv.partner;
    var jong = Math.max(0, Math.floor(Number(inv.jong) || 0));
    var k12 = Math.max(0, Math.floor(Number(inv.k12) || 0));
    var k16 = Math.max(0, Math.floor(Number(inv.k16) || 0));
    var kinderen = jong + k12 + k16;
    var inkomen = Math.max(0, Number(inv.inkomen) || 0);
    var max = 0;
    if (kinderen === 1) max = partner ? C.kindgebonden_budget_1_kind_partner : C.kindgebonden_budget_1_kind_alleen;
    if (kinderen >= 2) {
      max = (partner ? C.kindgebonden_budget_2_kinderen_partner : C.kindgebonden_budget_2_kinderen_alleen) +
        (kinderen - 2) * C.kindgebonden_budget_vanaf_3e_kind;
    }
    var verhoging = k12 * C.kindgebonden_budget_verhoging_12_15 + k16 * C.kindgebonden_budget_verhoging_16_17;
    var grens = partner ? C.kindgebonden_budget_inkomensgrens_partners : C.kindgebonden_budget_inkomensgrens_alleen;
    var vermindering = Math.max(0, inkomen - grens) * C.kindgebonden_budget_afbouw;
    var jaar = Math.max(0, max + verhoging - vermindering);
    var reden = '';
    if (!kinderen) reden = 'kinderen';
    else if (inv.vermogenTeHoog) { reden = 'vermogen'; jaar = 0; }
    else if (!jaar) reden = 'inkomen';
    return {
      kinderen: kinderen, max: max, verhoging: verhoging, grens: grens, vermindering: vermindering,
      jaar: jaar, maand: heleEuroOmlaag(jaar / 12), reden: reden,
      // het inkomen waarboven er niets meer is
      nulpunt: kinderen ? grens + (max + verhoging) / C.kindgebonden_budget_afbouw : 0
    };
  }

  /*
   * BELASTING MET AOW EN PENSIOEN (het hele jaar de AOW-leeftijd)
   * invoer: { aow, pensioen, loon: bruto per jaar (loon voor de loonheffing),
   *           ingehouden: ingehouden loonheffing van alle jaaropgaven samen,
   *           alleenstaand: AOW voor alleenstaanden, voor1946: geboren vóór 1946 }
   * Tarief en kortingen uit de tabellen 2026 van de Belastingdienst voor wie
   * het hele jaar de AOW-leeftijd heeft. Alleen box 1; het verzamelinkomen is
   * hier dus het inkomen uit AOW, pensioen en loon.
   */
  function ouderenkorting(C, verzamelinkomen) {
    // zoals rekentool ouderenkorting: rechte lijn naar nul bij het nulpunt (2026: 15%)
    var max = C.ouderenkorting_max, grens = C.ouderenkorting_afbouwgrens, nul = C.ouderenkorting_nulpunt;
    if (verzamelinkomen <= grens) return max;
    return Math.max(0, max * (nul - verzamelinkomen) / (nul - grens));
  }

  function arbeidskortingAow(C, ai) {
    // de tabel zet hem vanaf €132.921 op nul; de formule komt daar op €1,81
    if (ai <= 0 || ai >= C.arbeidskorting_aow_nul_vanaf) return 0;
    if (ai <= C.arbeidskorting_grens1) return C.arbeidskorting_aow_pct1 * ai;
    if (ai <= C.arbeidskorting_grens2) return C.arbeidskorting_aow_bedrag2 + C.arbeidskorting_aow_pct2 * (ai - C.arbeidskorting_grens1);
    if (ai <= C.arbeidskorting_grens3) return C.arbeidskorting_aow_bedrag3 + C.arbeidskorting_aow_pct3 * (ai - C.arbeidskorting_grens2);
    return Math.max(0, C.arbeidskorting_aow_max - C.arbeidskorting_aow_afbouwpercentage * (ai - C.arbeidskorting_grens3));
  }

  function aowBelasting(C, inv) {
    var aow = Math.max(0, Number(inv.aow) || 0);
    var pensioen = Math.max(0, Number(inv.pensioen) || 0);
    var loon = Math.max(0, Number(inv.loon) || 0);
    var inkomen = aow + pensioen + loon;
    var g1 = inv.voor1946 ? C.box1_aow_schijf1_grens_voor_1946 : C.box1_schijf1_grens, g2 = C.box1_schijf2_grens;
    var heffing = Math.min(inkomen, g1) * C.box1_aow_schijf1_tarief +
      Math.max(0, Math.min(inkomen, g2) - g1) * C.box1_schijf2_tarief +
      Math.max(0, inkomen - g2) * C.box1_schijf3_tarief;
    var ahk = inkomen <= C.ahk_afbouwgrens ? C.ahk_aow_max
      : Math.max(0, C.ahk_aow_max - C.ahk_aow_afbouwpercentage * (inkomen - C.ahk_afbouwgrens));
    var ok = ouderenkorting(C, inkomen);
    var aok = inv.alleenstaand ? C.ouderenkorting_alleenstaande : 0;
    var ak = arbeidskortingAow(C, loon);
    var kortingen = Math.min(heffing, ahk + ok + aok + ak);
    var verschuldigd = heffing - kortingen;
    var ingehouden = Math.max(0, Number(inv.ingehouden) || 0);
    return {
      inkomen: inkomen, grens1: g1, heffing: heffing, ahk: ahk, ouderenkorting: ok, alleenstaand: aok, ak: ak,
      kortingen: kortingen, verschuldigd: verschuldigd, ingehouden: ingehouden, verschil: ingehouden - verschuldigd
    };
  }

  /*
   * GIFTENAFTREK
   * invoer: { inkomen: (gezamenlijk) drempelinkomen, gewoon: gewone giften,
   *           gewoonCultureel: daarvan aan een culturele ANBI, periodiek:
   *           periodieke giften, periodiekCultureel: daarvan cultureel }
   * Zoals de voorbeelden van belastingdienst.nl ("Voorbeelden berekening giften
   * aan een culturele ANBI"): de verhoging van 25% (samen hoogstens €1.250, eerst
   * over de periodieke giften) komt bij de giften én bij het maximum van 10%.
   * Periodieke giften: geen drempel en geen maximum van 10%.
   */
  function giftenaftrek(C, inv) {
    var inkomen = Math.max(0, Number(inv.inkomen) || 0);
    var gewoon = Math.max(0, Number(inv.gewoon) || 0);
    var periodiek = Math.max(0, Number(inv.periodiek) || 0);
    var gc = Math.min(gewoon, Math.max(0, Number(inv.gewoonCultureel) || 0));
    var pc = Math.min(periodiek, Math.max(0, Number(inv.periodiekCultureel) || 0));
    var vp = Math.min(C.giften_cultureel_max, pc * C.giften_cultureel_pct);
    var vg = Math.min(C.giften_cultureel_max - vp, gc * C.giften_cultureel_pct);
    var drempel = Math.max(C.giften_drempel_minimum, inkomen * C.giften_drempel_pct);
    var maximum = inkomen * C.giften_maximum_pct;
    var gewoonAftrek = gewoon ? Math.max(0, Math.min(gewoon + vg - drempel, maximum + vg)) : 0;
    var periodiekAftrek = Math.min(periodiek, C.giften_periodiek_max) + vp;
    return {
      drempel: drempel, maximum: maximum, verhogingGewoon: vg, verhogingPeriodiek: vp,
      gewoonAftrek: gewoonAftrek, periodiekAftrek: periodiekAftrek,
      boven: gewoon + vg - drempel > maximum + vg,
      aftrek: gewoonAftrek + periodiekAftrek
    };
  }

  return {
    giftenaftrek: giftenaftrek,
    aowBelasting: aowBelasting, ouderenkorting: ouderenkorting, arbeidskortingAow: arbeidskortingAow,
    kindgebondenBudget: kindgebondenBudget,
    box3: box3,
    zorgkosten: zorgkosten, zorgkostenDrempel: zorgkostenDrempel,
    erfschenkbelasting: erfschenkbelasting,
    getal: getal, cijfers: cijfers, heleEuroOmlaag: heleEuroOmlaag,
    zorgtoeslag: zorgtoeslag, huurtoeslag: huurtoeslag,
    box1: box1, algemeneHeffingskorting: algemeneHeffingskorting, arbeidskorting: arbeidskorting,
    belastingteruggave: belastingteruggave
  };
});
