/*
 * rekenhulp.js
 * De rekentools op /rekentools/ (voorlopige teruggave, ouderenkorting) en het
 * formulier "gratis laten narekenen" onder elke rekentool, ook op de blogs die
 * een eigen rekentool hebben.
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
    }
  };

  function start(box, cijfers) {
    var naam = box.getAttribute('data-rekenhulp');
    var reken = REKENHULPEN[naam];
    if (!reken) return;
    var C = {};
    Object.keys(cijfers).forEach(function (k) {
      if (cijfers[k] && cijfers[k].waarde !== undefined) C[k] = getal(cijfers[k].waarde);
    });
    function opnieuw() { reken(box, C); vulFormulieren(); }
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
