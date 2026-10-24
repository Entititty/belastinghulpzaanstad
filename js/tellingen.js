/*
 * tellingen.js — conversiemeting zonder cookies.
 *
 * Meet zeven dingen: een klik op WhatsApp, op een telefoonnummer, op een
 * e-mailadres, het versturen van een formulier, het afhaken halverwege een
 * formulier, een binnenkomst via een flyer of partner ("bezoek"), en het
 * gebruik van een rekentool.
 *
 * Waarom naast Google Analytics: GA4 ziet alleen bezoekers die de
 * cookiebalk accepteren en geen adblocker draaien. Dat is een fractie, en
 * juist bij deze doelgroep een onbekende fractie. Deze telling loopt over
 * de eigen server, zonder cookies en zonder herkenning, dus hij telt
 * iedereen.
 *
 * Wat er de deur uit gaat: het soort gebeurtenis, het pad van de pagina,
 * bij afhaken de NAAM van het laatst aangeraakte veld, welke knop het was
 * (menu, balk onderin, zwevend, ...), de broncategorie (flyer, zoekmachine,
 * direct, ...) en bij een flyer of partner de campagne- of partnercode. Meer
 * niet. Geen IP-adres, geen sessie, geen verwijzende URL, geen veldwaarden.
 * De server schrijft er een tijdstip bij, afgerond op het hele uur.
 *
 * HERKOMST. Waar een bezoek vandaan komt (landingspagina, het domein van de
 * verwijzende site, de utm-codes, een ?ref=partnercode) staat in
 * sessionStorage: alleen in dit tabblad, weg zodra het sluit, zonder
 * identificatienummer. Het gaat alleen mee als de bezoeker zelf een
 * formulier verstuurt (formulier.js vraagt het op met bhzHerkomst()). Kwam
 * iemand via een flyer of partner, dan zet dit script dat ook achter de
 * WhatsApp-tekst, bijvoorbeeld "(via flyer Rosmolenwijk)"; de bezoeker ziet
 * dat en kan het weghalen.
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
  var H_SLEUTEL = 'bhz-herkomst';

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
  var VELDEN = ['naam', 'telefoon', 'email', 'dienst', 'voorkeurstijd', 'opmerking', 'akkoord', 'onderwerp', 'bericht', 'dagdeel'];
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

  function pad() {
    var p = (window.location.pathname || '/').toLowerCase();
    if (p.length > 80) p = p.slice(0, 80);
    return /^[a-z0-9/._-]*$/.test(p) ? p : 'overig';
  }

  /* ------------------------------------------------------------------
   * BRON — dezelfde logica als app/lib/bron.js (de server rekent de bron
   * van een aanvraag uit, dit script die van een klik). Wijzig ze samen;
   * app/test/bron.test.js legt ze met een tabel naast elkaar.
   * ------------------------------------------------------------------ */
  /* BRON-BEGIN */
  var AI = ['chatgpt.com', 'chat.openai.com', 'perplexity.ai', 'copilot.microsoft.com', 'gemini.google.com', 'claude.ai'];
  var ZOEK = ['google.', 'bing.com', 'duckduckgo.com', 'ecosia.org', 'search.yahoo.com', 'yahoo.com', 'startpage.com', 'qwant.com', 'search.brave.com'];
  var SOCIAL = ['facebook.com', 'm.facebook.com', 'l.facebook.com', 'lm.facebook.com', 'instagram.com', 'l.instagram.com',
    'linkedin.com', 'lnkd.in', 'x.com', 't.co', 'twitter.com', 'nextdoor.nl', 'nextdoor.com', 'youtube.com', 'tiktok.com', 'pinterest.com', 'reddit.com'];
  function past(host, lijst) {
    for (var i = 0; i < lijst.length; i++) {
      var d = lijst[i];
      if (d.slice(-1) === '.') { if (host.indexOf(d) === 0 || host.indexOf('.' + d) !== -1) return true; }
      else if (host === d || host.slice(-(d.length + 1)) === '.' + d) return true;
    }
    return false;
  }
  function bepaalBron(h) {
    var src = String(h.utm_source || '').toLowerCase();
    var med = String(h.utm_medium || '').toLowerCase();
    var camp = String(h.utm_campaign || '').toLowerCase();
    if (h.ref) return { bron: 'partner', detail: h.partnerNaam || h.ref };
    if (src === 'flyer' || med === 'print' || med === 'flyer') return { bron: 'flyer', detail: camp || src };
    if (camp === 'bedrijfsprofiel' || src === 'gbp') return { bron: 'bedrijfsprofiel', detail: 'Google' };
    if (/^(cpc|ppc|paid|ads?|betaald|display|paid-?social)$/.test(med)) return { bron: 'advertentie', detail: [src, camp].filter(Boolean).join(' / ') };
    if (med === 'email' || med === 'e-mail' || src === 'herinnering' || src === 'nieuwsbrief') return { bron: 'e-mail', detail: camp || src };
    if (src) return { bron: 'campagne', detail: [src, med, camp].filter(Boolean).join(' / ') };
    var v = String(h.verwijzer || '').toLowerCase().replace(/^www\./, '');
    if (v) {
      if (past(v, AI)) return { bron: 'ai', detail: v };
      if (past(v, ZOEK)) return { bron: 'zoekmachine', detail: v };
      if (past(v, SOCIAL)) return { bron: 'social', detail: v };
      return { bron: 'verwijzing', detail: v };
    }
    return { bron: 'direct', detail: '' };
  }
  /* BRON-EINDE */

  /* ---------------- herkomst van dit bezoek ---------------- */
  function schoon(s) {
    s = String(s || '').toLowerCase().replace(/^\s+|\s+$/g, '');
    return /^[a-z0-9 ._+\-\/]{1,80}$/.test(s) ? s : '';
  }
  function code(s) {
    s = String(s || '').toLowerCase().replace(/^\s+|\s+$/g, '');
    return /^[a-z0-9-]{1,40}$/.test(s) ? s : '';
  }
  function verwijzer() {
    var m = /^https?:\/\/([^\/:?#]+)/i.exec(document.referrer || '');
    if (!m) return '';
    var host = m[1].toLowerCase();
    if (host === window.location.hostname) return '';
    return host.replace(/^www\./, '');
  }
  function leesHerkomst() {
    try { var s = sessionStorage.getItem(H_SLEUTEL); return s ? JSON.parse(s) : null; } catch (e) { return null; }
  }
  function schrijfHerkomst(h) {
    try { sessionStorage.setItem(H_SLEUTEL, JSON.stringify(h)); } catch (e) { /* privévenster: dan zonder */ }
  }

  var params = {};
  try {
    var zp = new URLSearchParams(window.location.search);
    params = { us: schoon(zp.get('utm_source')), um: schoon(zp.get('utm_medium')), uc: schoon(zp.get('utm_campaign')),
               un: schoon(zp.get('utm_content')), ref: code(zp.get('ref')) };
  } catch (e) { params = {}; }
  var campagneLanding = !!(params.us || params.ref);
  var nieuw = { l: pad(), r: verwijzer(), us: params.us || '', um: params.um || '', uc: params.uc || '', un: params.un || '', ref: params.ref || '' };
  var herkomst = leesHerkomst();
  /* Een nieuwe campagne of een nieuwe verwijzende site overschrijft: de
   * laatste aanleiding telt. Binnen de site doorklikken verandert niets. */
  if (!herkomst || campagneLanding || nieuw.r) { herkomst = nieuw; schrijfHerkomst(herkomst); }

  var B = bepaalBron({ ref: herkomst.ref, utm_source: herkomst.us, utm_medium: herkomst.um, utm_campaign: herkomst.uc, verwijzer: herkomst.r }).bron;
  var C = code(String(herkomst.ref || ((B === 'flyer' || B === 'advertentie' || B === 'e-mail' || B === 'campagne') ? herkomst.uc : '')).replace(/[ ._+\/]+/g, '-'));

  function apparaat() {
    var ua = navigator.userAgent || '';
    if (/iPad|Tablet|PlayBook|Silk|Kindle/i.test(ua) || (/Android/i.test(ua) && !/Mobile/i.test(ua)) ||
        (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'tablet';
    if (/Mobi|iPhone|iPod|Android|Windows Phone/i.test(ua)) return 'mobiel';
    return 'computer';
  }

  /* Voor formulier.js: gaat alleen mee als de bezoeker zelf verstuurt */
  window.bhzHerkomst = function () {
    return {
      landing: herkomst.l || '', verwijzer: herkomst.r || '', utm_source: herkomst.us || '', utm_medium: herkomst.um || '',
      utm_campaign: herkomst.uc || '', utm_content: herkomst.un || '', ref: herkomst.ref || '', apparaat: apparaat()
    };
  };

  /* ---------------- versturen ---------------- */
  var laatsteKlik = 0;

  function stuur(gebeurtenis, veld, knop) {
    if (uit()) return;
    var q = ENDPOINT + '?e=' + encodeURIComponent(gebeurtenis) +
            '&p=' + encodeURIComponent(pad());
    if (veld) q += '&v=' + encodeURIComponent(veld);
    if (knop) q += '&k=' + encodeURIComponent(knop);
    if (B) q += '&b=' + encodeURIComponent(B);
    if (C) q += '&c=' + encodeURIComponent(C);
    try {
      if (navigator.sendBeacon) { navigator.sendBeacon(q); return; }
      new Image().src = q;   /* oude browsers; ook zonder wachten */
    } catch (e) { /* meten mag nooit iets breken */ }
  }

  /* Voor rekenhulp.js: één keer per rekentool per paginabezoek */
  var rekentoolGeteld = {};
  window.bhzTel = function (gebeurtenis, knop) {
    if (gebeurtenis !== 'rekentool' || !/^[a-z0-9-]{1,40}$/.test(knop || '') || rekentoolGeteld[knop]) return;
    rekentoolGeteld[knop] = true;
    stuur('rekentool', '', knop);
  };

  /* ---------------- klikken ---------------- */
  function soort(a) {
    var h = (a.getAttribute('href') || '').toLowerCase();
    if (h.indexOf('tel:') === 0) return 'tel';
    if (h.indexOf('mailto:') === 0) return 'mail';
    if (h.indexOf('wa.me/') !== -1 || h.indexOf('api.whatsapp.com/send') !== -1) return 'whatsapp';
    return null;
  }

  /* Welke knop: de plek op de pagina, niet de tekst. Vaste lijst. */
  function knopVan(a) {
    if (pad() === '/bedankt/') return 'bedankt';
    if (a.closest('.bhz-mobilebar')) return 'balk';
    if (a.closest('.boa-zweef')) return 'zwevend';
    if (a.closest('#nav, nav.nav')) return 'menu';
    if (a.closest('footer')) return 'footer';
    if (a.closest('.form-melding')) return 'melding';
    if (a.closest('.hero, #home')) return 'hero';
    if (a.closest('section.cta, #contact, #terugbellen, .blog-cta-box, .mid-cta')) return 'slot';
    if (a.closest('.boa, .cta-paar')) return 'paar';
    return 'tekst';
  }

  /* "(via flyer Rosmolenwijk)" of "(via partner jansen)" achter de WhatsApp-tekst */
  function bronTekst() {
    if (herkomst.ref) return 'via partner ' + herkomst.ref;
    if (B === 'flyer' && herkomst.uc) {
      var naam = herkomst.uc.replace(/[-_+]+/g, ' ');
      return 'via flyer ' + naam.charAt(0).toUpperCase() + naam.slice(1);
    }
    return '';
  }
  function metBron(href) {
    var extra = bronTekst();
    if (!extra || /%28via%20|\(via /.test(href)) return href;
    var m = /([?&]text=)([^&#]*)/.exec(href);
    if (m) {
      var t;
      try { t = decodeURIComponent(m[2].replace(/\+/g, ' ')); } catch (e) { return href; }
      return href.replace(m[0], m[1] + encodeURIComponent(t + ' (' + extra + ')'));
    }
    return href + (href.indexOf('?') === -1 ? '?' : '&') + 'text=' + encodeURIComponent('Hoi! Ik heb een vraag. (' + extra + ')');
  }

  /* In de capture-fase, zodat we er zeker bij zijn voordat een ander
   * script het event tegenhoudt. We houden zelf niets tegen; de nieuwe
   * WhatsApp-link staat erin voordat de browser hem opent. */
  document.addEventListener('click', function (ev) {
    var t = ev.target;
    var a = t && t.closest ? t.closest('a[href]') : null;
    if (!a) return;
    var s = soort(a);
    if (!s) return;
    if (s === 'whatsapp') {
      var nieuweHref = metBron(a.getAttribute('href'));
      if (nieuweHref !== a.getAttribute('href')) a.setAttribute('href', nieuweHref);
    }
    laatsteKlik = Date.now();
    stuur(s, '', knopVan(a));
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

    /* binnengekomen via een flyer of partner: één keer per landing tellen */
    if (campagneLanding) {
      var gezien = '';
      try { gezien = sessionStorage.getItem('bhz-bezoek') || ''; } catch (e) { gezien = ''; }
      if (gezien !== window.location.search) {
        stuur('bezoek');
        try { sessionStorage.setItem('bhz-bezoek', window.location.search); } catch (e) { /* zonder */ }
      }
    }

    var forms = document.querySelectorAll('form');
    for (var i = 0; i < forms.length; i++) {
      (function (f) {
        f.addEventListener('focusin', raak);
        f.addEventListener('input', raak);
        f.addEventListener('submit', function () {
          afgehandeld = true;
          /* Dit is een poging. De browser laat een ongeldig formulier niet
           * tot hier komen, maar of de server hem aanneemt weten we hier
           * niet. Het rapport noemt het daarom "verstuurd (poging)". Wat
           * echt binnenkwam, staat in /beheer. */
          stuur('form_submit', '', /herinnering/.test(f.getAttribute('action') || '') ? 'herinnering' : 'formulier');
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
