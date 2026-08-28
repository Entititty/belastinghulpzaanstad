/*
 * tellingen.js — conversiemeting zonder cookies.
 *
 * Meet vijf dingen: een klik op WhatsApp, op een telefoonnummer, op een
 * e-mailadres, het versturen van een formulier, en het afhaken halverwege
 * een formulier.
 *
 * Waarom naast Google Analytics: GA4 ziet alleen bezoekers die de
 * cookiebalk accepteren en geen adblocker draaien. Dat is een fractie, en
 * juist bij deze doelgroep een onbekende fractie. Deze telling loopt over
 * de eigen server, zonder cookies en zonder herkenning, dus hij telt
 * iedereen.
 *
 * Wat er de deur uit gaat: het soort gebeurtenis, het pad van de pagina,
 * en bij afhaken de NAAM van het laatst aangeraakte veld. Meer niet. Geen
 * IP-adres, geen sessie, geen verwijzende pagina, geen veldwaarden. De
 * server schrijft er een tijdstip bij, afgerond op het hele uur.
 *
 * Meten mag nooit in de weg zitten. Alles gaat met sendBeacon: de browser
 * zet het bericht in de wachtrij en gaat meteen door. Er wordt niet
 * gewacht op een antwoord en er wordt nergens preventDefault aangeroepen.
 * Ligt de server plat, dan opent WhatsApp gewoon.
 */
(function () {
  'use strict';

  var ENDPOINT = '/t';
  var SLEUTEL  = 'bhz-niet-meten';

  /* -------------------------------------------------------------------
   * WHITELIST VELDNAMEN — dit is de enige plek waar deze lijst staat.
   * scripts/tellingen-rapport.js leest hem hier letterlijk uit, tussen de
   * twee markeringen hieronder. Zo kunnen de meting en het rapport niet
   * uit elkaar lopen.
   *
   * Waarom een whitelist en geen doorgeefluik: bij afhaken sturen we een
   * veldnaam mee. Een naam die hier niet in staat wordt "overig". Daarmee
   * kan een veld dat later wordt toegevoegd nooit ongemerkt in de log
   * belanden, en kan niemand via een zelfgemaakt verzoek eigen tekst in
   * het bestand krijgen.
   *
   * Veldwaarden gaan er nooit in, ook niet afgekapt en ook niet het
   * eerste teken. In deze formulieren staan namen, telefoonnummers en
   * e-mailadressen; dat is precies wat hier niet hoort.
   * ------------------------------------------------------------------- */
  /* VELDEN-BEGIN */
  var VELDEN = ['naam', 'telefoon', 'email', 'onderwerp', 'bericht', 'dagdeel', 'akkoord'];
  /* VELDEN-EINDE */

  /* ---------------- eigen bezoek uitzetten, mechanisme 1 ----------------
   * Per apparaat. Open eenmalig https://belastinghulpzaanstad.nl/?mijzelf=1
   * op de telefoon, tablet of laptop; die blijft dan uit de tellingen.
   * ?mijzelf=0 zet hem weer aan. Werkt alleen op dit apparaat en alleen in
   * deze browser — daarom staat er in nginx een tweede filter op IP-adres,
   * dat wel voor elk apparaat in huis werkt. Zie nginx-tellingen.conf.
   */
  function uit() {
    try { return localStorage.getItem(SLEUTEL) === '1'; } catch (e) { return false; }
  }

  function schakelaar() {
    var m = /[?&]mijzelf=([01])/.exec(window.location.search || '');
    if (!m) return;
    var aan = m[1] === '1';
    try {
      if (aan) localStorage.setItem(SLEUTEL, '1');
      else localStorage.removeItem(SLEUTEL);
    } catch (e) { return; }
    /* bevestiging, want anders weet je op een telefoon niet of het gelukt is */
    var b = document.createElement('div');
    b.setAttribute('role', 'status');
    b.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:9999;' +
      'padding:14px 18px;font:600 1rem/1.4 system-ui,sans-serif;text-align:center;' +
      'background:#14695f;color:#fff';
    b.textContent = aan
      ? 'Dit apparaat telt niet meer mee in de conversiemeting.'
      : 'Dit apparaat telt weer mee in de conversiemeting.';
    function plak() { document.body.appendChild(b); }
    if (document.body) plak(); else document.addEventListener('DOMContentLoaded', plak);
  }

  /* ---------------- versturen ---------------- */
  function pad() {
    var p = (window.location.pathname || '/').toLowerCase();
    if (p.length > 80) p = p.slice(0, 80);
    return /^[a-z0-9/._-]*$/.test(p) ? p : 'overig';
  }

  var laatsteKlik = 0;

  function stuur(gebeurtenis, veld) {
    if (uit()) return;
    var q = ENDPOINT + '?e=' + encodeURIComponent(gebeurtenis) +
            '&p=' + encodeURIComponent(pad());
    if (veld) q += '&v=' + encodeURIComponent(veld);
    try {
      if (navigator.sendBeacon) { navigator.sendBeacon(q); return; }
      new Image().src = q;   /* oude browsers; ook zonder wachten */
    } catch (e) { /* meten mag nooit iets breken */ }
  }

  /* ---------------- klikken ---------------- */
  function soort(a) {
    var h = (a.getAttribute('href') || '').toLowerCase();
    if (h.indexOf('tel:') === 0) return 'tel';
    if (h.indexOf('mailto:') === 0) return 'mail';
    if (h.indexOf('wa.me/') !== -1 || h.indexOf('api.whatsapp.com/send') !== -1) return 'whatsapp';
    return null;
  }

  /* In de capture-fase, zodat we er zeker bij zijn voordat een ander
   * script het event tegenhoudt. We houden zelf niets tegen. */
  document.addEventListener('click', function (ev) {
    var t = ev.target;
    var a = t && t.closest ? t.closest('a[href]') : null;
    if (!a) return;
    var s = soort(a);
    if (!s) return;
    laatsteKlik = Date.now();
    stuur(s);
  }, true);

  /* ---------------- formulieren ---------------- */
  var aangeraakt = null;    /* naam van het laatst aangeraakte veld */
  var afgehandeld = false;  /* verstuurd of al als afhaken geteld */

  function naamVan(el) {
    var n = (el.getAttribute('name') || '').toLowerCase();
    return VELDEN.indexOf(n) !== -1 ? n : 'overig';
  }

  function raak(ev) {
    var el = ev.target;
    if (!el || !el.name || el.type === 'hidden') return;
    aangeraakt = naamVan(el);
  }

  function afhaken() {
    if (afgehandeld || !aangeraakt) return;
    /* Klikte iemand net op WhatsApp of belde hij, dan is dat de reden dat
     * de pagina wegvalt. Die klik is al geteld; dit er als afhaken bij
     * tellen maakt het beeld twee keer somberder dan het is. */
    if (Date.now() - laatsteKlik < 3000) return;
    afgehandeld = true;
    stuur('form_abandon', aangeraakt);
  }

  function start() {
    schakelaar();

    var forms = document.querySelectorAll('form');
    for (var i = 0; i < forms.length; i++) {
      (function (f) {
        f.addEventListener('focusin', raak);
        f.addEventListener('input', raak);
        f.addEventListener('submit', function () {
          afgehandeld = true;
          /* Dit is een poging. De browser laat een ongeldig formulier niet
           * tot hier komen, maar of Formspree hem aanneemt weten we hier
           * niet. Het rapport noemt het daarom "verstuurd (poging)". */
          stuur('form_submit');
        });
      })(forms[i]);
    }

    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') afhaken();
    });
    window.addEventListener('pagehide', afhaken);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
