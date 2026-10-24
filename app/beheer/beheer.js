/* /beheer — het beetje JavaScript dat er is (de CSP staat geen inline scripts toe).
 * - formulieren met data-bevestig vragen eerst "weet u het zeker?"
 * - filters op de lijst gaan meteen als u een keuze maakt */
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
})();
