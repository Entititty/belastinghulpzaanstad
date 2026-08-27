/*
 * formulier.js
 * Laat de bezoeker zien of zijn bericht is verstuurd.
 *
 * Waarom dit bestaat: de formulieren stuurden de bezoeker terug naar
 * /contact/?ok=1 of ?fout=1, maar geen enkele pagina deed iets met die
 * parameter. Je vulde het formulier in, kwam terug op dezelfde pagina en
 * wist niets. Voor een doelgroep die toch al twijfelt of het gelukt is, is
 * dat de slechtste uitkomst.
 *
 * Het bericht komt boven het eerste formulier, krijgt focus, en wordt door
 * een schermlezer voorgelezen (role="status"). Daarna wordt de parameter uit
 * de adresbalk gehaald, zodat vernieuwen niet opnieuw "verstuurd" meldt.
 */
(function () {
  'use strict';

  var TEKST = {
    nl: {
      ok: 'Uw bericht is verstuurd. Wij nemen zo snel mogelijk contact met u op, meestal dezelfde dag.',
      fout: 'Het versturen is niet gelukt. Bel of app ons op 06 19 71 18 48, dan regelen wij het direct.'
    },
    en: {
      ok: 'Your message has been sent. We will contact you as soon as possible, usually the same day.',
      fout: 'Sending failed. Call or WhatsApp us on 06 19 71 18 48 and we will sort it out right away.'
    }
  };

  function taal() {
    var l = (document.documentElement.getAttribute('lang') || 'nl').slice(0, 2).toLowerCase();
    return TEKST[l] ? l : 'nl';
  }

  function melding(soort) {
    var t = TEKST[taal()][soort];
    var box = document.createElement('div');
    box.id = 'form-melding';
    box.setAttribute('role', 'status');
    box.setAttribute('tabindex', '-1');

    var gelukt = soort === 'ok';
    box.style.cssText = [
      'margin:0 0 22px',
      'padding:16px 18px',
      'border-radius:12px',
      'font-size:1rem',
      'line-height:1.5',
      'font-weight:600',
      'background:' + (gelukt ? '#e6f5f3' : '#fff3d6'),
      'color:' + (gelukt ? '#14695f' : '#8b5a00'),
      'border:2px solid ' + (gelukt ? '#14695f' : '#8b5a00')
    ].join(';');

    box.textContent = (gelukt ? '✓ ' : '! ') + t;
    return box;
  }

  function start() {
    var p = new URLSearchParams(window.location.search);
    var soort = p.has('ok') ? 'ok' : (p.has('fout') ? 'fout' : null);
    if (!soort) return;

    var form = document.querySelector('form');
    if (!form) return;

    var box = melding(soort);
    var doel = form.closest('.form-card') || form;
    doel.parentNode.insertBefore(box, doel);

    box.focus();
    box.scrollIntoView({ block: 'center' });

    // parameter weghalen zodat vernieuwen niets opnieuw meldt
    p.delete('ok'); p.delete('fout');
    var rest = p.toString();
    history.replaceState(null, '', window.location.pathname + (rest ? '?' + rest : ''));
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
