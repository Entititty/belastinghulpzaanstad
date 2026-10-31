/*
 * rekenhulp.js
 * De rekentools op /rekentools/ (voorlopige teruggave, ouderenkorting,
 * zorgtoeslag) en op /blog/huurtoeslag-berekenen/, en het formulier "gratis
 * laten narekenen" onder elke rekentool, ook op de blogs die een eigen
 * rekentool hebben.
 *
 * De zorgtoeslag en de huurtoeslag rekenen met js/rekenregels.js (laad dat
 * vóór dit script). Daar staan de formules van Dienst Toeslagen; hier alleen
 * de invoer en de uitkomst op de pagina.
 *
 * VELDEN DIE ER SOMS NIET TOE DOEN
 * Een element met data-rh-als="partner=ja" (of "personen!=1") is alleen
 * zichtbaar als die keuze geldt. Verborgen velden gaan niet mee in de
 * berekening voor het formulier.
 *
 * WAAROM DE CIJFERS UIT /data/fiscale-cijfers.json KOMEN
 * De oudere rekentools op de blogs hebben hun percentages in de code staan
 * (var TARIEF_SCHIJF1 = 0.3575). set-fiscale-cijfers.js vervangt tekst als
 * "35,75%", niet dat getal, dus bij de jaarlijkse update rekenen die tools
 * met de oude cijfers door. Deze tools lezen het bestand dat bij de update
 * toch wordt bijgewerkt, en rekenen dus vanzelf mee.
 *
 * HET FORMULIER
 * Elk formulier met data-rh-lead krijgt in het verborgen veld "berekening" de
 * invoer en de uitkomst van de rekentool op dezelfde pagina ([data-rh-calc]),
 * als JSON: {"invoer": [[label, waarde], ...], "uitkomst": [[label, waarde], ...]}.
 * Zo ziet Stan bij het terugbellen meteen waar het over gaat. Er gaat niets
 * weg zolang de bezoeker het formulier niet verstuurt; versturen doet
 * formulier.js, net als bij de andere formulieren.
 *
 * GEBRUIK TELLEN
 * De eerste keer dat iemand iets invult, telt js/tellingen.js één
 * "rekentool"-gebeurtenis (zonder de ingevulde waarden). Zo is te zien hoe
 * vaak een rekentool gebruikt wordt tegenover hoe vaak het tot een aanvraag
 * leidt.
 */
(function () {
  'use strict';

  /* ---------- hulpjes ---------- */

  // "€38.883" -> 38883, "35,75%" -> 0.3575, "€932,93" -> 932.93
  function getal(waarde) {
    var s = String(waarde).replace(/[€\s]/g, '');
    var pct = s.indexOf('%') !== -1;
    s = s.replace('%', '').replace(/\./g, '').replace(',', '.');
    var n = parseFloat(s);
    return pct ? n / 100 : n;
  }
  function euro(n) {
    return '€ ' + Math.round(n).toLocaleString('nl-NL');
  }
  function euroCent(n) {
    return '€ ' + n.toLocaleString('nl-NL', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function pct(n) {
    return (n * 100).toLocaleString('nl-NL', { maximumFractionDigits: 2 }) + '%';
  }
  function veld(box, naam) {
    return box.querySelector('[data-rh-in="' + naam + '"]');
  }
  function bedrag(box, naam) {
    var el = veld(box, naam);
    var v = el ? parseFloat(String(el.value).replace(',', '.')) : NaN;
    return isNaN(v) || v < 0 ? 0 : v;
  }
  function keuze(box, naam) {
    var el = veld(box, naam);
    return el ? el.value : '';
  }
  function zet(box, naam, tekst, html) {
    var el = box.querySelector('[data-rh-out="' + naam + '"]');
    if (!el) return;
    if (html) el.innerHTML = tekst; else el.textContent = tekst;
  }
  function tekst(el) {
    return el ? el.textContent.replace(/\s+/g, ' ').trim() : '';
  }

  /* ---------- de rekentools ---------- */

  var REKENHULPEN = {
    /* Voordeel van de hypotheekrenteaftrek, dat u met een voorlopige teruggave
       elke maand krijgt: (rente - eigenwoningforfait) x tarief. Twee scenario's,
       omdat het tarief van het inkomen afhangt. */
    'voorlopige-teruggave': function (box, C) {
      var T1 = C.box1_schijf1_tarief, T2 = C.max_aftrektarief_eigen_woning;
      var EWF = C.eigenwoningforfait_pct, GRENS = C.box1_schijf1_grens;
      var rente = bedrag(box, 'hypotheek') * bedrag(box, 'rente') / 100;
      var forfait = bedrag(box, 'woz') * EWF;
      var saldo = Math.max(0, rente - forfait);
      var jaar1 = saldo * T1, jaar2 = saldo * T2;
      var schijf = keuze(box, 'schijf');
      if (schijf === '1' || schijf === '2') {
        var jaar = schijf === '1' ? jaar1 : jaar2;
        zet(box, 'maand', euro(jaar / 12));
        zet(box, 'jaar', euro(jaar));
      } else {
        zet(box, 'maand', euro(jaar1 / 12) + ' – ' + euro(jaar2 / 12).replace('€ ', ''));
        zet(box, 'jaar', euro(jaar1) + ' – ' + euro(jaar2).replace('€ ', ''));
      }
      zet(box, 'uitleg',
        'Betaalde hypotheekrente: ' + euro(rente) + ' per jaar<br>' +
        'Min eigenwoningforfait (' + pct(EWF) + ' van de WOZ-waarde): &minus; ' + euro(forfait) + '<br>' +
        'Aftrekbaar saldo: ' + euro(saldo) + '<br>' +
        (schijf !== '2' ? 'Bij een inkomen tot ' + euro(GRENS) + ' (' + pct(T1) + '): ' + euro(jaar1) + ' per jaar<br>' : '') +
        (schijf !== '1' ? 'Bij een hoger inkomen (' + pct(T2) + ', het maximum): ' + euro(jaar2) + ' per jaar' : ''), true);
      zet(box, 'melding', saldo === 0 && rente > 0
        ? 'Uw hypotheekrente is niet hoger dan het eigenwoningforfait. Dan levert een voorlopige teruggave niets op.'
        : '');
    },

    /* Ouderenkorting: het volle bedrag tot de afbouwgrens, daarboven lineair
       naar nul bij het nulpunt (2026: 15% van het meerdere). Plus de
       alleenstaande ouderenkorting bij AOW voor alleenstaanden. */
    'ouderenkorting': function (box, C) {
      var MAX = C.ouderenkorting_max, GRENS = C.ouderenkorting_afbouwgrens;
      var NUL = C.ouderenkorting_nulpunt, ALLEEN = C.ouderenkorting_alleenstaande;
      var aow = keuze(box, 'aow') !== 'nee';
      var inkomen = bedrag(box, 'inkomen');
      var korting = 0;
      if (aow) {
        korting = inkomen <= GRENS ? MAX : Math.max(0, MAX * (NUL - inkomen) / (NUL - GRENS));
      }
      var extra = aow && keuze(box, 'alleenstaand') === 'ja' ? ALLEEN : 0;
      zet(box, 'korting', euro(korting));
      zet(box, 'alleenstaand', euro(extra));
      zet(box, 'totaal', euro(korting + extra));
      zet(box, 'maand', euro((korting + extra) / 12));
      zet(box, 'uitleg',
        'Inkomen tot ' + euro(GRENS) + ': de volledige ouderenkorting van ' + euro(MAX) + '.<br>' +
        'Daarboven wordt de korting ' + pct(MAX / (NUL - GRENS)) + ' van het meerdere lager, tot nul bij ' + euro(NUL) + '.<br>' +
        'Alleenstaande ouderenkorting bij AOW voor alleenstaanden: ' + euro(ALLEEN) + '.', true);
      zet(box, 'melding', aow ? ''
        : 'De ouderenkorting is er voor wie uiterlijk eind 2026 de AOW-leeftijd bereikt. Krijgt u nog geen AOW, dan telt deze korting (nog) niet.');
    },

    /* Zorgtoeslag: standaardpremie min normpremie (rekenregels.js). */
    'zorgtoeslag': function (box, C) {
      var R = window.BHZRekenregels;
      var partner = keuze(box, 'partner') === 'ja';
      var inkomen = bedrag(box, 'inkomen') + (partner ? bedrag(box, 'inkomen_partner') : 0);
      var z = R.zorgtoeslag(C, {
        partner: partner,
        inkomen: inkomen,
        partnerVerzekerd: keuze(box, 'partner_verzekerd') !== 'nee',
        vermogenTeHoog: keuze(box, 'vermogen') === 'ja'
      });
      zet(box, 'maand', euro(z.maand));
      zet(box, 'jaar', euro(z.jaar));
      zet(box, 'standaardpremie', euro(z.standaardpremie));
      zet(box, 'normpremie', z.reden === 'vermogen' ? '–' : euroCent(z.normpremie));
      zet(box, 'uitleg',
        (partner ? 'Gezamenlijk toetsingsinkomen: ' : 'Toetsingsinkomen: ') + euro(inkomen) + '<br>' +
        'Standaardpremie' + (partner ? ' (twee keer)' : '') + ': ' + euro(z.standaardpremie) + '<br>' +
        'Normpremie: ' + pct(partner ? C.zorgtoeslag_normpercentage_partners : C.zorgtoeslag_normpercentage_alleenstaand) +
        ' van ' + euro(z.drempelinkomen) + (inkomen > z.drempelinkomen
          ? ' + ' + pct(C.zorgtoeslag_afbouwpercentage) + ' van het inkomen daarboven (' + euro(inkomen - z.drempelinkomen) + ')'
          : '') + ' = ' + euroCent(z.normpremie) + '<br>' +
        (inkomen > z.inkomensgrens
          ? 'Uw inkomen is hoger dan de grens van ' + euro(z.inkomensgrens) + ', dus de zorgtoeslag is nul.'
          : 'Zorgtoeslag per jaar: ' + euro(z.standaardpremie) + ' &minus; ' + euroCent(z.normpremie) +
            (z.half ? ', daarvan de helft' : '') + ' = ' + euroCent(z.jaar) + '<br>' +
            'Per maand: ' + euroCent(z.maandExact) + '; Dienst Toeslagen betaalt hele euro\'s, naar beneden afgerond.'), true);
      var melding = '';
      if (z.reden === 'vermogen') {
        melding = 'Met een vermogen boven ' + euro(z.vermogensgrens) + (partner ? ' (samen)' : '') + ' op 1 januari heeft u dat hele jaar geen recht op zorgtoeslag, ook niet bij een laag inkomen.';
      } else if (z.reden === 'inkomen') {
        melding = 'Boven een toetsingsinkomen van ' + euro(z.inkomensgrens) + (partner ? ' (samen)' : '') + ' is er geen zorgtoeslag.';
      } else if (z.half) {
        melding = 'Uw partner is niet verzekerd voor de Wet op de zorgtoeslag (bijvoorbeeld als militair). Dan krijgt u de helft van de berekende zorgtoeslag.';
      }
      zet(box, 'melding', melding);
    },

    /* Huurtoeslag: deel A + B + C min de inkomenscorrectie D (rekenregels.js). */
    'huurtoeslag': function (box, C) {
      var R = window.BHZRekenregels;
      var personen = parseInt(keuze(box, 'personen'), 10) || 1;
      var iemand21 = keuze(box, 'leeftijd') !== 'jonger';
      var inkomen = bedrag(box, 'inkomen') + (personen > 1 ? bedrag(box, 'inkomen_anderen') : 0);
      var huur = bedrag(box, 'huur');
      var h = R.huurtoeslag(C, {
        kaleHuur: huur,
        personen: personen,
        iemand21: iemand21,
        kindOfHandicap: keuze(box, 'kind') === 'ja',
        inkomen: inkomen,
        vermogenTeHoog: keuze(box, 'vermogen') === 'ja'
      });
      zet(box, 'maand', euro(h.maand));
      zet(box, 'jaar', euro(h.jaar));
      zet(box, 'deel_a', euroCent(h.a));
      zet(box, 'deel_bc', euroCent(h.b + h.c));
      zet(box, 'correctie', h.d ? '− ' + euroCent(h.d) : euroCent(0));
      zet(box, 'nulpunt', h.nulpunt && h.reden !== 'vermogen'
        ? 'Bij deze huur en dit huishouden krijgt u huurtoeslag tot een inkomen van ongeveer <strong>' + euro(Math.floor(h.nulpunt / 100) * 100) + '</strong> per jaar.'
        : '', true);
      zet(box, 'uitleg',
        'Rekenhuur: ' + euroCent(h.rekenhuur) + (h.boven_huurgrens ? ' (uw huur, maar niet meer dan de huurgrens van ' + euroCent(h.huurgrens) + ')' : '') + '<br>' +
        'A. Van de basishuur (' + euroCent(h.basishuur) + ', die betaalt u zelf) tot ' + euroCent(h.kwaliteitskortingsgrens) + ': 100% vergoed = ' + euroCent(h.a) + '<br>' +
        (h.jongeren ? '' :
          'B. Van ' + euroCent(h.kwaliteitskortingsgrens) + ' tot ' + euroCent(h.aftoppingsgrens) + ': ' + pct(C.huurtoeslag_vergoeding_tot_aftoppingsgrens) + ' vergoed = ' + euroCent(h.b) + '<br>' +
          'C. Boven ' + euroCent(h.aftoppingsgrens) + ': ' + pct(C.huurtoeslag_vergoeding_boven_aftoppingsgrens) + ' vergoed = ' + euroCent(h.c) + '<br>') +
        'D. Inkomenscorrectie: ' + (h.d
          ? '(' + euro(inkomen) + ' &minus; ' + euro(h.ijkpunt) + ') &times; ' + pct(h.afbouw) + ' &divide; 12 = ' + euroCent(h.d)
          : 'geen, uw inkomen is niet hoger dan ' + euro(h.ijkpunt)) + '<br>' +
        'Huurtoeslag per maand: A + B + C &minus; D, naar beneden afgerond op hele euro\'s.', true);
      var melding = '';
      if (h.reden === 'vermogen') {
        melding = 'Met een vermogen boven de grens op 1 januari heeft u dat hele jaar geen recht op huurtoeslag, ook niet bij een laag inkomen.';
      } else if (h.reden === 'huur') {
        melding = 'Uw kale huur is niet hoger dan de basishuur van ' + euroCent(h.basishuur) + '. Dat deel betaalt iedereen zelf, dus er is geen huurtoeslag.';
      } else if (h.reden === 'inkomen') {
        melding = 'Bij dit inkomen valt de huurtoeslag weg: de inkomenscorrectie (' + euroCent(h.d) + ') is groter dan de toeslag over uw huur (' + euroCent(h.a + h.b + h.c) + ').';
      } else if (h.boven_huurgrens) {
        melding = h.jongeren
          ? 'Iedereen in uw huishouden is jonger dan 21. Dan telt de huur tot ' + euroCent(h.huurgrens) + '; over het deel daarboven krijgt u geen huurtoeslag.'
          : 'Uw huur is hoger dan ' + euroCent(h.huurgrens) + '. U kunt toch huurtoeslag krijgen, maar alleen over de huur tot dat bedrag.';
      }
      zet(box, 'melding', melding);
    }
  };

  /* Belastingteruggave: ingehouden loonheffing min de belasting die u echt
     verschuldigd bent (rekenregels.js). Alleen loon, onder de AOW-leeftijd. */
  REKENHULPEN['belastingteruggave'] = function (box, C) {
    var R = window.BHZRekenregels;
    var r = R.belastingteruggave(C, {
      loon: bedrag(box, 'loon'),
      ingehouden: bedrag(box, 'ingehouden'),
      aow: keuze(box, 'aow') === 'ja'
    });
    // eerst afronden op hele euro's, dan aftrekken: dan klopt de som die de bezoeker narekent
    var heffing = Math.round(r.heffing);
    var ahk = Math.min(Math.round(r.ahk), heffing);
    var ak = Math.min(Math.round(r.ak), heffing - ahk);
    var verschuldigd = heffing - ahk - ak;
    var verschil = Math.round(r.ingehouden) - verschuldigd;
    var terug = verschil >= 0;
    zet(box, 'kop', r.reden ? 'Uw teruggave' : terug ? 'U krijgt ongeveer terug' : 'U betaalt ongeveer bij');
    zet(box, 'bedrag', r.reden ? '–' : euro(Math.abs(verschil)));
    zet(box, 'heffing', euro(heffing));
    zet(box, 'ahk', '− ' + euro(ahk));
    zet(box, 'ak', '− ' + euro(ak));
    zet(box, 'verschuldigd', euro(verschuldigd));
    zet(box, 'ingehouden', euro(r.ingehouden));
    zet(box, 'uitleg',
      'Belasting over ' + euro(bedrag(box, 'loon')) + ' loon: ' + pct(C.box1_schijf1_tarief) + ' tot ' + euro(C.box1_schijf1_grens) +
      ', ' + pct(C.box1_schijf2_tarief) + ' tot ' + euro(C.box1_schijf2_grens) + ', daarboven ' + pct(C.box1_schijf3_tarief) + ' = ' + euro(r.heffing) + '<br>' +
      'Algemene heffingskorting: ' + euro(r.ahk) + '<br>' +
      'Arbeidskorting: ' + euro(r.ak) + '<br>' +
      'Een heffingskorting verlaagt alleen de belasting die er is, dus samen nooit meer dan ' + euro(r.heffing) + '<br>' +
      'Belasting die u echt betaalt: ' + euro(verschuldigd) + '<br>' +
      'Al ingehouden: ' + euro(r.ingehouden) + '; het verschil krijgt u terug of betaalt u bij.', true);
    var melding = '';
    if (r.reden === 'aow') {
      melding = 'Voor wie in 2026 de AOW-leeftijd bereikt, gelden andere tarieven en kortingen. Bereken uw ouderenkorting met de rekentool ouderenkorting, of laat het ons gratis narekenen.';
    } else if (r.ingehouden === 0 && bedrag(box, 'loon') > 0) {
      melding = 'Vul ook de ingehouden loonheffing in; die staat op uw jaaropgave.';
    } else if (!terug) {
      melding = 'Er is minder ingehouden dan u verschuldigd bent. Meestal komt dat doordat twee werkgevers tegelijk de loonheffingskorting toepasten. Geef die korting bij maar één werkgever op.';
    }
    zet(box, 'melding', melding);
  };

  /* Erfbelasting en schenkbelasting: bedrag min vrijstelling, dan twee tarieven
     (rekenregels.js). Dezelfde rekentool voor beide, met eigen meldingen. */
  function erfschenk(soort) {
    return function (box, C) {
      var R = window.BHZRekenregels;
      var relatie = keuze(box, 'relatie');
      var r = R.erfschenkbelasting(C, { soort: soort, relatie: relatie, bedrag: bedrag(box, 'bedrag') });
      zet(box, 'belasting', euro(r.belasting));
      zet(box, 'vrijstelling', '− ' + euro(r.vrijstelling));
      zet(box, 'belastbaar', euro(r.belastbaar));
      zet(box, 'uitleg',
        'Bedrag: ' + euro(bedrag(box, 'bedrag')) + '<br>' +
        'Vrijstelling: &minus; ' + euro(r.vrijstelling) + '<br>' +
        'Belastbaar: ' + euro(r.belastbaar) + '<br>' +
        pct(r.tariefLaag) + ' over ' + euro(Math.min(r.belastbaar, r.grens)) + ' = ' + euro(r.laag) +
        (r.belastbaar > r.grens ? '<br>' + pct(r.tariefHoog) + ' over het deel boven ' + euro(r.grens) + ' (' + euro(r.belastbaar - r.grens) + ') = ' + euro(r.hoog) : '') + '<br>' +
        (soort === 'erf' ? 'Erfbelasting' : 'Schenkbelasting') + ': ' + euro(r.belasting), true);
      var m = {
        'erf/partner': 'Krijgt u door het overlijden ook een nabestaandenpensioen of lijfrente? Dan is uw vrijstelling lager, maar in 2026 nooit lager dan ' + euro(C.erf_vrijstelling_partner_minimaal) + '. Samenwonend? Dan telt u alleen als partner met een notarieel samenlevingscontract, of als u allebei minstens 5 jaar op hetzelfde adres staat ingeschreven.',
        'erf/kind-beperking': 'Deze hogere vrijstelling geldt alleen als u door uw beperking de komende 3 jaar waarschijnlijk minder dan de helft verdient van iemand zonder beperking, en de overledene meer dan de helft van uw levensonderhoud betaalde.',
        'erf/ouder': 'Erven beide ouders? Dan geldt de vrijstelling voor hen samen.',
        'schenk/kind': 'Geven u en uw partner allebei? Dan geldt de vrijstelling voor u samen. Tel alle schenkingen aan dit kind in 2026 bij elkaar op.',
        'schenk/kind-eenmalig': 'Eén keer per kind, als het kind of zijn partner tussen 18 en 40 jaar is. Uw kind vraagt de vrijstelling aan in zijn aangifte schenkbelasting.',
        'schenk/kind-studie': 'Alleen voor een dure studie of opleiding, als uw kind tussen 18 en 40 jaar is. Er gelden extra voorwaarden; laat het ons nakijken.',
        'schenk/kleinkind': 'Geven opa en oma allebei? Dan geldt de vrijstelling voor hen samen, als zij partners zijn voor de schenkbelasting.'
      }[soort + '/' + relatie] || '';
      zet(box, 'melding', m);
    };
  }
  REKENHULPEN['erfbelasting'] = erfschenk('erf');
  REKENHULPEN['schenkbelasting'] = erfschenk('schenk');

  /* Zorgkosten: verhoging over de verhoogbare kosten, dan de drempel eraf
     (rekenregels.js, volgorde uit het Handboek 2026). */
  REKENHULPEN['zorgkosten'] = function (box, C) {
    var R = window.BHZRekenregels;
    var aow = keuze(box, 'aow') === 'ja';
    var r = R.zorgkosten(C, {
      partner: keuze(box, 'partner') === 'ja',
      drempelinkomen: bedrag(box, 'inkomen'),
      aow: aow,
      behandeling: bedrag(box, 'behandeling'),
      verhoogbaar: bedrag(box, 'medicijnen') + bedrag(box, 'overig'),
      ziekenbezoek: bedrag(box, 'ziekenbezoek')
    });
    // eerst afronden, dan optellen en aftrekken: dan klopt de som op het scherm
    var kosten = Math.round(r.verhoogbaar + r.behandeling + r.ziekenbezoek);
    var verhoging = Math.round(r.verhoging);
    var drempel = Math.round(r.drempel);
    var aftrek = Math.max(0, kosten + verhoging - drempel);
    zet(box, 'aftrek', euro(aftrek));
    zet(box, 'kosten', euro(kosten));
    zet(box, 'verhoging', r.verhogingPct ? '+ ' + euro(verhoging) : 'geen');
    zet(box, 'drempel', '− ' + euro(drempel));
    zet(box, 'voordeel', aftrek && !aow
      ? 'Valt uw inkomen in de eerste schijf, dan levert dit ongeveer <strong>' + euro(aftrek * C.box1_schijf1_tarief) + '</strong> op (' + pct(C.box1_schijf1_tarief) + ' van de aftrek).'
      : aftrek ? 'Wat de aftrek oplevert, hangt af van uw belastingtarief; met de AOW-leeftijd is dat lager. Wij rekenen het gratis voor u uit.' : '', true);
    zet(box, 'uitleg',
      'Medicijnen, hulpmiddelen, vervoer en de rest: ' + euro(r.verhoogbaar) + '<br>' +
      (r.verhogingPct
        ? 'Verhoging: ' + pct(r.verhogingPct) + ' daarvan = ' + euro(r.verhoging) + ' (uw drempelinkomen is niet hoger dan ' + euro(C.zorgkosten_verhoging_grens) + ')<br>'
        : 'Geen verhoging: uw drempelinkomen is hoger dan ' + euro(C.zorgkosten_verhoging_grens) + '<br>') +
      'Behandelingen en ziekenbezoek, zonder verhoging: ' + euro(r.behandeling + r.ziekenbezoek) + '<br>' +
      'Drempel bij een drempelinkomen van ' + euro(bedrag(box, 'inkomen')) + ': &minus; ' + euro(r.drempel) + '<br>' +
      'Aftrek: ' + euro(aftrek), true);
    zet(box, 'melding', aftrek === 0 && kosten > 0
      ? 'Uw zorgkosten blijven onder de drempel van ' + euro(drempel) + '. Dan is er dit jaar geen aftrek. Heeft uw partner ook zorgkosten? Tel die mee als u het hele jaar fiscale partners bent.'
      : '');
  };

  /* data-rh-als="veld=waarde" of "veld!=waarde": alleen tonen als dat geldt */
  function zichtbaarheid(box) {
    var els = box.querySelectorAll('[data-rh-als]');
    for (var i = 0; i < els.length; i++) {
      var m = /^([a-z_]+)(!?=)(.*)$/.exec(els[i].getAttribute('data-rh-als'));
      if (!m) continue;
      var w = keuze(box, m[1]);
      els[i].hidden = m[2] === '=' ? w !== m[3] : w === m[3];
    }
  }

  function start(box, cijfers) {
    var naam = box.getAttribute('data-rekenhulp');
    var reken = REKENHULPEN[naam];
    if (!reken) return;
    if (['zorgtoeslag', 'huurtoeslag', 'belastingteruggave', 'erfbelasting', 'schenkbelasting', 'zorgkosten'].indexOf(naam) !== -1 && !window.BHZRekenregels) {
      zet(box, 'melding', 'De rekentool kan nu niet laden. Bel of app ons op 06 19 71 18 48, dan rekenen wij het voor u uit.');
      return;
    }
    var C = {};
    Object.keys(cijfers).forEach(function (k) {
      if (cijfers[k] && cijfers[k].waarde !== undefined) C[k] = getal(cijfers[k].waarde);
    });
    function opnieuw() { zichtbaarheid(box); reken(box, C); vulFormulieren(); }
    box.addEventListener('input', opnieuw);
    box.addEventListener('change', opnieuw);
    box.addEventListener('input', telGebruik);
    box.addEventListener('change', telGebruik);
    opnieuw();
    box.setAttribute('data-rh-klaar', '1');
  }

  var boxen = document.querySelectorAll('[data-rekenhulp]');
  if (boxen.length) {
    fetch('/data/fiscale-cijfers.json', { headers: { Accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (j) {
        for (var i = 0; i < boxen.length; i++) start(boxen[i], j.cijfers || {});
      })
      .catch(function () {
        for (var i = 0; i < boxen.length; i++) {
          zet(boxen[i], 'melding', 'De rekentool kan de cijfers nu niet laden. Bel of app ons op 06 19 71 18 48, dan rekenen wij het voor u uit.');
        }
      });
  }

  /* ---------- het formulier onder de rekentool ---------- */

  function labelVan(el) {
    if (el.id) {
      var l = document.querySelector('label[for="' + el.id + '"]');
      if (l) return tekst(l.querySelector('.rh-label') || l);
    }
    var omhul = el.closest('label');
    if (omhul) return tekst(omhul.querySelector('span') || omhul);
    return el.name || el.id || 'veld';
  }

  function samenvatting(calc) {
    var invoer = [], uitkomst = [];
    var velden = calc.querySelectorAll('input, select');
    for (var i = 0; i < velden.length; i++) {
      var el = velden[i];
      if (el.type === 'hidden' || el.type === 'button') continue;
      if (el.closest('[hidden]')) continue;
      if ((el.type === 'radio' || el.type === 'checkbox') && !el.checked) continue;
      var waarde = el.tagName === 'SELECT' ? tekst(el.options[el.selectedIndex]) : el.value;
      invoer.push([labelVan(el), waarde]);
    }
    var uit = calc.querySelectorAll('[data-rh-uitkomst]');
    for (var j = 0; j < uit.length; j++) {
      var t = tekst(uit[j]);
      if (t) uitkomst.push([uit[j].getAttribute('data-rh-uitkomst'), t]);
    }
    return JSON.stringify({ invoer: invoer, uitkomst: uitkomst });
  }

  /* één keer per paginabezoek; de code staat in het formulier (rekentool) */
  var geteld = false;
  function telGebruik() {
    if (geteld) return;
    var veld = document.querySelector('form[data-rh-lead] input[name="rekentool"]');
    if (!veld || typeof window.bhzTel !== 'function') return;
    geteld = true;
    window.bhzTel('rekentool', veld.value);
  }

  function vulFormulieren() {
    var calc = document.querySelector('[data-rh-calc]');
    if (!calc) return;
    var forms = document.querySelectorAll('form[data-rh-lead]');
    for (var i = 0; i < forms.length; i++) {
      var veldB = forms[i].querySelector('input[name="berekening"]');
      if (veldB) veldB.value = samenvatting(calc);
    }
  }

  /* De oudere rekentools op de blogs hebben hun eigen script; wacht een tik
     tot dat de uitkomst heeft bijgewerkt. Vlak voor het versturen nog een keer,
     in de capture-fase, dus vóór formulier.js de gegevens verzamelt. */
  var oudeCalc = document.querySelector('[data-rh-calc]:not([data-rekenhulp])');
  if (oudeCalc) {
    ['input', 'change'].forEach(function (soort) {
      oudeCalc.addEventListener(soort, function () { setTimeout(vulFormulieren, 0); telGebruik(); });
    });
  }
  document.addEventListener('submit', function (e) {
    if (e.target && e.target.hasAttribute && e.target.hasAttribute('data-rh-lead')) vulFormulieren();
  }, true);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', vulFormulieren);
  else vulFormulieren();
})();
