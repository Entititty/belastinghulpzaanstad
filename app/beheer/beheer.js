/* /beheer — het beetje JavaScript dat er is (de CSP staat geen inline scripts toe).
 * - formulieren met data-bevestig vragen eerst "weet u het zeker?"
 * - filters gaan meteen als u een keuze maakt
 * - grafieken: een tooltip bij aanwijzen, aantikken of met Tab (data-tip);
 *   de tekst gaat er met textContent in, nooit als HTML */
(function () {
  'use strict';
  document.addEventListener('submit', function (e) {
    var f = e.target;
    var vraag = f && f.getAttribute && f.getAttribute('data-bevestig');
    if (vraag && !window.confirm(vraag)) e.preventDefault();
  });
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (el && el.form && el.form.hasAttribute('data-direct') && el.tagName === 'SELECT') el.form.submit();
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
