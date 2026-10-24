/* /beheer — het beetje JavaScript dat er is (de CSP staat geen inline scripts toe).
 * - formulieren en knoppen met data-bevestig vragen eerst "weet u het zeker?"
 * - filters gaan meteen als u een keuze maakt
 * - een gekozen CSV-bestand komt in het tekstvak (data-naar), ook als Excel
 *   het als Windows-1252 opsloeg in plaats van UTF-8
 * - een knop met data-kopieer zet de tekst van dat veld op het klembord
 * - grafieken: een tooltip bij aanwijzen, aantikken of met Tab (data-tip);
 *   de tekst gaat er met textContent in, nooit als HTML */
(function () {
  'use strict';
  document.addEventListener('submit', function (e) {
    var f = e.target;
    var knop = e.submitter;
    var vraag = (knop && knop.getAttribute('data-bevestig')) || (f && f.getAttribute && f.getAttribute('data-bevestig'));
    if (vraag && !window.confirm(vraag)) e.preventDefault();
  });
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el && el.form && el.form.hasAttribute('data-direct') && el.tagName === 'SELECT') el.form.submit();
    if (el && el.type === 'file' && el.hasAttribute('data-naar') && el.files && el.files[0]) {
      var doel = document.getElementById(el.getAttribute('data-naar'));
      el.files[0].arrayBuffer().then(function (buf) {
        var tekst;
        try { tekst = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch (x) { tekst = new TextDecoder('windows-1252').decode(buf); }
        if (doel) doel.value = tekst;
      });
    }
  });
  document.addEventListener('click', function (e) {
    var knop = e.target && e.target.closest ? e.target.closest('[data-kopieer]') : null;
    var veld = knop && document.getElementById(knop.getAttribute('data-kopieer'));
    if (!veld) return;
    veld.select();
    var klaar = function () { knop.textContent = 'Gekopieerd'; };
    if (navigator.clipboard) navigator.clipboard.writeText(veld.value).then(klaar, function () {});
    else if (document.execCommand('copy')) klaar();
  });

  var tip = null, actief = null;
  function doel(e) { return e.target && e.target.closest ? e.target.closest('[data-tip]') : null; }
  function toon(el) {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'tip';
      tip.setAttribute('role', 'tooltip');
      document.body.appendChild(tip);
    }
    tip.textContent = el.getAttribute('data-tip');
    tip.hidden = false;
    actief = el;
    var r = el.getBoundingClientRect();
    var x = Math.min(window.innerWidth - tip.offsetWidth - 8, Math.max(8, r.left + r.width / 2 - tip.offsetWidth / 2));
    var y = r.top - tip.offsetHeight - 8;
    if (y < 8) y = Math.min(window.innerHeight - tip.offsetHeight - 8, r.bottom + 8);
    tip.style.left = x + 'px';
    tip.style.top = y + 'px';
  }
  function verberg() { if (tip) tip.hidden = true; actief = null; }
  document.addEventListener('pointerover', function (e) { var el = doel(e); if (el) toon(el); });
  document.addEventListener('pointerout', function (e) { var el = doel(e); if (el && el === actief) verberg(); });
  document.addEventListener('focusin', function (e) { var el = doel(e); if (el) toon(el); });
  document.addEventListener('focusout', function (e) { var el = doel(e); if (el && el === actief) verberg(); });
  window.addEventListener('scroll', verberg, { passive: true });
})();
