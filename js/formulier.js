/*
 * formulier.js
 * Verstuurt de formulieren zonder de bezoeker van de site te halen, en laat
 * zien of het gelukt is.
 *
 * Waarom niet gewoon de standaard POST: Formspree negeert het veld _next en
 * stuurt de bezoeker naar zijn eigen /thanks. Gemeten:
 *     POST -> 302, Location: /thanks
 * Dat is een Engelse pagina op formspree.io. Voor iemand die net zijn
 * telefoonnummer heeft achtergelaten is dat precies het verkeerde moment om
 * op een vreemd domein te belanden.
 *
 * Dus: onderscheppen, met fetch versturen, en het antwoord hier tonen. De
 * melding krijgt focus en wordt voorgelezen door een schermlezer.
 *
 * Zonder JavaScript blijft het formulier werken. Dan doet de browser de
 * gewone POST, komt het bericht nog steeds aan, en eindigt de bezoeker op de
 * bedankpagina van Formspree. Minder mooi, maar niets raakt kwijt.
 */
(function () {
  'use strict';

  var TEKST = {
    nl: {
      ok: 'Uw bericht is verstuurd. Wij nemen zo snel mogelijk contact met u op, meestal dezelfde dag.',
      fout: 'Het versturen is niet gelukt. Bel of app ons op 06 19 71 18 48, dan regelen wij het direct.',
      bezig: 'Versturen…'
    },
    en: {
      ok: 'Your message has been sent. We will contact you as soon as possible, usually the same day.',
      fout: 'Sending failed. Call or WhatsApp us on 06 19 71 18 48 and we will sort it out right away.',
      bezig: 'Sending…'
    }
  };

  function taal() {
    var l = (document.documentElement.getAttribute('lang') || 'nl').slice(0, 2).toLowerCase();
    return TEKST[l] ? l : 'nl';
  }
  var T = TEKST[taal()];

  function maakMelding(soort) {
    var gelukt = soort === 'ok';
    var box = document.createElement('div');
    box.className = 'form-melding';
    box.setAttribute('role', gelukt ? 'status' : 'alert');
    box.setAttribute('tabindex', '-1');
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
    box.textContent = (gelukt ? '✓ ' : '! ') + T[soort];
    return box;
  }

  function toon(form, soort) {
    var doel = form.closest('.form-card') || form;

    var oud = doel.parentNode.querySelector('.form-melding');
    if (oud) oud.parentNode.removeChild(oud);

    var box = maakMelding(soort);
    doel.parentNode.insertBefore(box, doel);

    // gelukt: het formulier weg, er is niets meer te doen
    if (soort === 'ok') form.style.display = 'none';

    box.focus();
    box.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  function knop(form) {
    return form.querySelector('button[type="submit"], button:not([type]), input[type="submit"]');
  }

  function versturen(form, e) {
    e.preventDefault();

    // de browser laat de verplichte velden zelf zien
    if (typeof form.reportValidity === 'function' && !form.reportValidity()) return;

    var b = knop(form);
    var labelVoor = b ? (b.textContent || b.value) : null;
    if (b) {
      b.disabled = true;
      if ('textContent' in b && b.tagName === 'BUTTON') b.textContent = T.bezig;
      else b.value = T.bezig;
    }

    function herstel() {
      if (!b) return;
      b.disabled = false;
      if (b.tagName === 'BUTTON') b.textContent = labelVoor;
      else b.value = labelVoor;
    }

    fetch(form.action, {
      method: 'POST',
      body: new FormData(form),
      headers: { Accept: 'application/json' }
    }).then(function (r) {
      if (r.ok) { toon(form, 'ok'); return; }
      herstel(); toon(form, 'fout');
    }).catch(function () {
      herstel(); toon(form, 'fout');
    });
  }

  function start() {
    var forms = document.querySelectorAll('form[action*="formspree.io"]');
    for (var i = 0; i < forms.length; i++) {
      (function (f) {
        f.addEventListener('submit', function (e) { versturen(f, e); });
      })(forms[i]);
    }

    /* Terugkeer via een gewone POST, als Formspree ooit toch doorverwijst naar
     * /contact/?ok=1. Kost niets en vangt dat geval op. */
    var p = new URLSearchParams(window.location.search);
    var soort = p.has('ok') ? 'ok' : (p.has('fout') ? 'fout' : null);
    if (soort && forms.length) {
      toon(forms[0], soort);
      if (soort === 'fout') forms[0].style.display = '';
      p.delete('ok'); p.delete('fout');
      var rest = p.toString();
      history.replaceState(null, '', window.location.pathname + (rest ? '?' + rest : ''));
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
