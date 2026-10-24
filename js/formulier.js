/*
 * formulier.js
 * Verstuurt de formulieren naar de eigen server (/api/), en laat zien of het
 * gelukt is.
 *
 * Een aanvraag die lukt, gaat door naar /bedankt/ ("wat gebeurt er nu").
 * Lukt het niet, dan blijft de bezoeker op de pagina en ziet in gewone taal
 * wat er mis is; het veld in kwestie wordt rood en krijgt de focus. Ligt de
 * server plat, dan staat er: bel of app ons. De melding wordt voorgelezen
 * door een schermlezer.
 *
 * Wat er meegaat naast de ingevulde velden: de pagina, de vorige pagina op
 * deze site, en de herkomst van het bezoek uit js/tellingen.js (landings-
 * pagina, domein van de verwijzer, utm-codes, partnercode, soort apparaat),
 * plus hoeveel seconden het formulier open stond (tegen spambots).
 *
 * Zonder JavaScript blijft alles werken: de browser doet een gewone POST en
 * de server stuurt door naar /bedankt/, of toont een eenvoudige foutpagina.
 *
 * Ook voor de herinneringslijst: aanmelden, en op /herinnering/bevestigen/
 * en /herinnering/afmelden/ het token uit de link in de mail.
 */
(function () {
  'use strict';

  var TEKST = {
    nl: {
      ok: 'Uw bericht is verstuurd. Wij nemen zo snel mogelijk contact met u op, meestal dezelfde dag.',
      fout: 'Het versturen is niet gelukt. Bel of app ons op 06 19 71 18 48, dan regelen wij het direct.',
      bezig: 'Versturen…',
      herinnering: 'Bijna klaar. Wij hebben u een mail gestuurd: klik op de knop in die mail om uw aanmelding te bevestigen. Ziet u niets? Kijk dan ook bij de ongewenste mail.'
    },
    en: {
      ok: 'Your message has been sent. We will contact you as soon as possible, usually the same day.',
      fout: 'Sending failed. Call or WhatsApp us on 06 19 71 18 48 and we will sort it out right away.',
      bezig: 'Sending…',
      herinnering: 'Almost done. We have sent you an email: click the button in it to confirm.'
    }
  };

  function taal() {
    var l = (document.documentElement.getAttribute('lang') || 'nl').slice(0, 2).toLowerCase();
    return TEKST[l] ? l : 'nl';
  }
  var T = TEKST[taal()];
  var GELADEN = Date.now();

  function maakMelding(soort, tekst) {
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
    box.textContent = (gelukt ? '✓ ' : '! ') + (tekst || T[soort]);
    return box;
  }

  function toon(form, soort, tekst) {
    var doel = form.closest('.form-card') || form;

    var oud = doel.parentNode.querySelector('.form-melding');
    if (oud) oud.parentNode.removeChild(oud);

    var box = maakMelding(soort, tekst);
    doel.parentNode.insertBefore(box, doel);

    // gelukt: het formulier weg, er is niets meer te doen
    if (soort === 'ok') form.style.display = 'none';

    box.focus();
    box.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }

  function knop(form) {
    return form.querySelector('button[type="submit"], button:not([type]), input[type="submit"]');
  }

  /* alle ingevulde velden, zoals de browser ze zelf zou versturen */
  function velden(form) {
    var p = new URLSearchParams();
    for (var i = 0; i < form.elements.length; i++) {
      var el = form.elements[i];
      if (!el.name || el.disabled) continue;
      if (el.type === 'submit' || el.type === 'button' || el.type === 'file') continue;
      if ((el.type === 'checkbox' || el.type === 'radio') && !el.checked) continue;
      p.append(el.name, el.value);
    }
    return p;
  }

  /* het pad van de vorige pagina, alleen als die op deze site was */
  function vorigePagina() {
    var m = /^https?:\/\/([^\/?#]+)(\/[^?#]*)?/i.exec(document.referrer || '');
    if (!m || m[1] !== window.location.host) return '';
    return m[2] || '/';
  }

  function herkomst(p) {
    p.set('h_pagina', window.location.pathname);
    var vorige = vorigePagina();
    if (vorige) p.set('h_vorige', vorige);
    var h = typeof window.bhzHerkomst === 'function' ? window.bhzHerkomst() : null;
    if (h) {
      if (h.landing) p.set('h_landing', h.landing);
      if (h.verwijzer) p.set('h_verwijzer', h.verwijzer);
      if (h.utm_source) p.set('h_utm_source', h.utm_source);
      if (h.utm_medium) p.set('h_utm_medium', h.utm_medium);
      if (h.utm_campaign) p.set('h_utm_campaign', h.utm_campaign);
      if (h.utm_content) p.set('h_utm_content', h.utm_content);
      if (h.ref) p.set('h_ref', h.ref);
      if (h.apparaat) p.set('h_apparaat', h.apparaat);
    }
    p.set('h_duur', ((Date.now() - GELADEN) / 1000).toFixed(1));
  }

  /* de velden die de server afkeurde: rood, en de eerste krijgt de focus */
  function markeer(form, fouten) {
    var eerste = null;
    for (var naam in fouten) {
      if (!Object.prototype.hasOwnProperty.call(fouten, naam)) continue;
      var el = form.querySelector('[name="' + naam + '"]');
      if (!el || el.type === 'hidden') continue;
      el.setAttribute('aria-invalid', 'true');
      var details = el.closest('details');
      if (details) details.open = true;
      if (!eerste) eerste = el;
    }
    return eerste;
  }

  function versturen(form, e) {
    e.preventDefault();

    // de browser laat de verplichte velden zelf zien
    if (typeof form.reportValidity === 'function' && !form.reportValidity()) return;

    var b = knop(form);
    var labelVoor = b ? (b.textContent || b.value) : null;
    if (b) {
      b.disabled = true;
      if (b.tagName === 'BUTTON') b.textContent = T.bezig;
      else b.value = T.bezig;
    }

    function herstel() {
      if (!b) return;
      b.disabled = false;
      if (b.tagName === 'BUTTON') b.textContent = labelVoor;
      else b.value = labelVoor;
    }

    var actie = form.getAttribute('action');
    var p = velden(form);
    if (actie === '/api/aanvraag' || actie === '/api/herinnering') herkomst(p);

    fetch(actie, {
      method: 'POST',
      body: p,
      headers: { Accept: 'application/json' }
    }).then(function (r) {
      return r.json().then(function (j) { return j; }, function () { return null; });
    }).then(function (j) {
      if (j && j.ok) {
        if (j.volgende) { window.location.href = j.volgende; return; }
        toon(form, 'ok', form.getAttribute('data-gelukt') || (actie === '/api/herinnering' ? T.herinnering : T.ok));
        return;
      }
      herstel();
      if (j && j.fouten) {
        var eerste = markeer(form, j.fouten);
        var zinnen = [];
        for (var k in j.fouten) if (Object.prototype.hasOwnProperty.call(j.fouten, k)) zinnen.push(j.fouten[k]);
        toon(form, 'fout', zinnen.join(' '));
        if (eerste) eerste.focus();
        return;
      }
      toon(form, 'fout', (j && j.fout) || T.fout);
    }).catch(function () {
      herstel();
      toon(form, 'fout', T.fout);
    });
  }

  /* Op de contactpagina: kwam de bezoeker van een dienstpagina, dan staat
   * "Waar gaat het over?" alvast goed. De lijst staat in data/aanvraag.json. */
  function dienstVooraf(forms) {
    var vorige = vorigePagina();
    if (!vorige) return;
    var selects = [];
    for (var i = 0; i < forms.length; i++) {
      var s = forms[i].querySelector('select[name="dienst"]');
      if (s && s.value === 'onbekend') selects.push(s);
    }
    if (!selects.length) return;
    fetch('/data/aanvraag.json', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (cfg) {
        if (!cfg || !cfg.dienst_per_pagina) return;
        var beste = '', dienst = '';
        for (var pad in cfg.dienst_per_pagina) {
          if (vorige.indexOf(pad) === 0 && pad.length > beste.length) { beste = pad; dienst = cfg.dienst_per_pagina[pad]; }
        }
        if (!dienst) return;
        selects.forEach(function (s) { if (s.value === 'onbekend') s.value = dienst; });
      })
      .catch(function () { /* dan kiest de bezoeker zelf */ });
  }

  /* /herinnering/bevestigen/ en /afmelden/: het token uit de link */
  function token(forms) {
    var t = new URLSearchParams(window.location.search).get('t') || '';
    for (var i = 0; i < forms.length; i++) {
      var veld = forms[i].querySelector('input[name="t"]');
      if (!veld) continue;
      veld.value = t;
      if (!t) {
        toon(forms[i], 'fout', 'Deze link is niet compleet. Open de link opnieuw vanuit de mail, of mail ons op info@belastinghulpzaanstad.nl.');
        forms[i].style.display = 'none';
      } else if (forms[i].hasAttribute('data-auto')) {
        /* afmelden is één klik: de klik op de link in de mail */
        versturen(forms[i], { preventDefault: function () {} });
      }
    }
  }

  function start() {
    var forms = document.querySelectorAll('form[action^="/api/"]');
    for (var i = 0; i < forms.length; i++) {
      (function (f) {
        f.addEventListener('submit', function (e) { versturen(f, e); });
        f.addEventListener('input', function (e) {
          if (e.target && e.target.getAttribute('aria-invalid')) e.target.removeAttribute('aria-invalid');
        });
      })(forms[i]);
    }
    dienstVooraf(forms);
    token(forms);

    /* Oude terugweg: /contact.php stuurt met ?fout=1 naar /contact/ (nginx).
     * Kost niets en vangt dat geval op. */
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
