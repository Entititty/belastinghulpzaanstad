/*
 * Belastinghulp Zaanstad — cookie consent + Google Consent Mode v2
 * Zelf-gehost, geen externe CMP. Laadt synchroon in <head> vóór gtag.js.
 *
 * Gedrag:
 *  - Consent-defaults staan op 'denied' (analytics/ads) totdat de bezoeker kiest.
 *    Google Analytics laadt dan cookieloos (Consent Mode v2 pings).
 *  - Microsoft Clarity kent geen Consent Mode en wordt PAS geïnjecteerd na 'Accepteren'.
 *  - Keuze wordt onthouden in localStorage; bij een volgende bezoek verschijnt de balk niet meer.
 */
(function () {
  var STORAGE_KEY = 'bhz_consent_v1';
  var CLARITY_ID  = 'w6ziuhbtlm';

  // --- Consent Mode v2 defaults (moet vóór gtag('config') draaien) ---
  window.dataLayer = window.dataLayer || [];
  function gtag() { dataLayer.push(arguments); }
  window.gtag = window.gtag || gtag;

  gtag('consent', 'default', {
    ad_storage: 'denied',
    ad_user_data: 'denied',
    ad_personalization: 'denied',
    analytics_storage: 'denied',
    functionality_storage: 'granted',
    personalization_storage: 'denied',
    security_storage: 'granted',
    wait_for_update: 500
  });

  function readConsent() {
    try { return localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
  }
  function writeConsent(v) {
    try { localStorage.setItem(STORAGE_KEY, v); } catch (e) {}
  }

  function loadClarity() {
    if (window.__bhzClarityLoaded) return;
    window.__bhzClarityLoaded = true;
    (function (c, l, a, r, i, t, y) {
      c[a] = c[a] || function () { (c[a].q = c[a].q || []).push(arguments); };
      t = l.createElement(r); t.async = 1; t.src = 'https://www.clarity.ms/tag/' + i;
      y = l.getElementsByTagName(r)[0]; y.parentNode.insertBefore(t, y);
    })(window, document, 'clarity', 'script', CLARITY_ID);
  }

  function grantAll() {
    gtag('consent', 'update', {
      ad_storage: 'granted',
      ad_user_data: 'granted',
      ad_personalization: 'granted',
      analytics_storage: 'granted',
      personalization_storage: 'granted'
    });
    loadClarity();
  }

  // Bij eerdere toestemming meteen toepassen (zonder balk).
  var stored = readConsent();
  if (stored === 'granted') { grantAll(); }

  // Publieke helper zodat de privacypagina de keuze kan resetten.
  window.bhzResetConsent = function () {
    try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
    location.reload();
  };

  function injectStyles() {
    if (document.getElementById('bhz-consent-style')) return;
    var css =
      '#bhz-consent{position:fixed;left:16px;bottom:16px;z-index:9998;max-width:440px;' +
      'background:#fff;color:#2c2520;border:1px solid rgba(44,37,32,0.12);border-radius:14px;' +
      'box-shadow:0 10px 40px rgba(44,37,32,0.18);padding:20px 22px;font-size:0.92rem;line-height:1.55;' +
      'font-family:inherit;}' +
      '#bhz-consent h2{font-size:1.02rem;margin:0 0 8px;color:#15756A;font-weight:700;}' +
      '#bhz-consent p{margin:0 0 14px;color:#4a3f35;}' +
      '#bhz-consent a{color:#15756A;text-decoration:underline;}' +
      '#bhz-consent .bhz-btns{display:flex;gap:10px;flex-wrap:wrap;}' +
      '#bhz-consent button{cursor:pointer;border-radius:100px;font-weight:700;font-size:0.9rem;' +
      'padding:10px 20px;border:2px solid #15756A;font-family:inherit;}' +
      '#bhz-accept{background:#15756A;color:#fff;}' +
      '#bhz-accept:hover{background:#146B61;border-color:#146B61;}' +
      '#bhz-reject{background:transparent;color:#15756A;}' +
      '#bhz-reject:hover{background:rgba(26,138,125,0.08);}' +
      '@media(max-width:560px){#bhz-consent{left:12px;right:12px;bottom:12px;max-width:none;}}';
    var s = document.createElement('style');
    s.id = 'bhz-consent-style';
    s.textContent = css;
    document.head.appendChild(s);
  }

  function isEnglish() {
    var l = (document.documentElement.getAttribute('lang') || '').toLowerCase();
    return l.indexOf('en') === 0;
  }

  function buildBanner() {
    if (readConsent()) return; // keuze al gemaakt
    injectStyles();
    var en = isEnglish();
    var wrap = document.createElement('div');
    wrap.id = 'bhz-consent';
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-live', 'polite');
    wrap.setAttribute('aria-label', en ? 'Cookie notice' : 'Cookiemelding');
    wrap.innerHTML = en
      ? '<h2>Cookies on this site</h2>' +
        '<p>We use anonymous statistics (Google Analytics and Microsoft Clarity) to improve the site. ' +
        'We only place these with your consent. Read more in our ' +
        '<a href="/en/privacy/">privacy policy</a>.</p>' +
        '<div class="bhz-btns">' +
        '<button id="bhz-accept" type="button">Accept</button>' +
        '<button id="bhz-reject" type="button">Decline</button>' +
        '</div>'
      : '<h2>Cookies op deze site</h2>' +
        '<p>Wij gebruiken anonieme statistieken (Google Analytics en Microsoft Clarity) om de site te ' +
        'verbeteren. Die plaatsen we alleen met uw toestemming. Meer weten? Lees ons ' +
        '<a href="/privacy/">privacybeleid</a>.</p>' +
        '<div class="bhz-btns">' +
        '<button id="bhz-accept" type="button">Accepteren</button>' +
        '<button id="bhz-reject" type="button">Weigeren</button>' +
        '</div>';
    document.body.appendChild(wrap);

    function close() { if (wrap.parentNode) wrap.parentNode.removeChild(wrap); }
    document.getElementById('bhz-accept').addEventListener('click', function () {
      writeConsent('granted'); grantAll(); close();
    });
    document.getElementById('bhz-reject').addEventListener('click', function () {
      writeConsent('denied'); close();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildBanner);
  } else {
    buildBanner();
  }
})();
