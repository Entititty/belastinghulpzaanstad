/* Toegankelijkheid (Taak 9)
   1. Tekstgrootte-schakelaar A / A+ / A++ (onthoudt de keuze in localStorage).
   2. FAQ-knoppen: aria-expanded bijhouden voor schermlezers.
   3. Decoratieve icoon-emoji: aria-hidden zetten. */
(function () {
  var KEY = 'bhz-tekstgrootte';
  var root = document.documentElement;
  // Engelse pagina's krijgen Engelse labels; de knoppen en links blijven gelijk.
  var EN = (root.getAttribute('lang') || '').slice(0, 2) === 'en';

  function apply(scale) {
    if (scale === 'l' || scale === 'xl') root.setAttribute('data-fontscale', scale);
    else root.removeAttribute('data-fontscale');
  }

  // Herstel opgeslagen keuze zo vroeg mogelijk
  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) {}
  if (saved) apply(saved);

  function markPressed(group, scale) {
    var btns = group.querySelectorAll('button');
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute('aria-pressed', btns[i].getAttribute('data-scale') === scale ? 'true' : 'false');
    }
  }

  /* De CSS hoort bij dit bestand, niet bij elke pagina apart. Stond eerder
     inline in maar 2 van de 93 pagina's; op de rest was de balk onopgemaakt
     en deed de tekstgrootte-schakelaar niets. */
  function injectCss() {
    if (document.getElementById('bhz-a11y-css')) return;
    var regels = [
    'html[data-fontscale="l"]{font-size:20px}',
    'html[data-fontscale="xl"]{font-size:23px}',
    '.ts-switch{position:fixed;right:16px;bottom:88px;z-index:9998;display:flex;align-items:center;gap:5px;background:#fff;border:1px solid rgba(44,37,32,0.15);border-radius:100px;padding:5px 9px;box-shadow:0 4px 16px rgba(44,37,32,0.18)}',
    '.ts-switch-label{font-size:0.78rem;color:#6b5e50}',
    '.ts-switch button{min-width:48px;min-height:48px;border:1px solid rgba(44,37,32,0.18);background:#faf8f4;border-radius:8px;font-weight:700;color:#2c2520;cursor:pointer;line-height:1}',
    '.ts-switch button[aria-pressed="true"]{background:#15756a;color:#fff;border-color:#15756a}',
    '.bhz-mobilebar{display:none}',
    '@media(max-width:600px){.ts-switch{right:8px;bottom:80px;padding:4px 6px;gap:3px}.ts-switch-label{display:none}.ts-switch button{min-width:48px;min-height:48px;font-size:0.9rem}}',
    '@media(max-width:768px){',
    '.bhz-mobilebar{display:flex;align-items:stretch;position:fixed;left:0;right:0;bottom:0;z-index:9997;background:#fff;border-top:1px solid rgba(44,37,32,0.12);box-shadow:0 -2px 12px rgba(44,37,32,0.12)}',
    '.bhz-mobilebar a{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;min-height:56px;padding:6px 4px;text-decoration:none;color:#2c2520;font-size:0.8rem;font-weight:700}',
    '.bhz-mobilebar a.bel{background:#15756a;color:#fff}',
    '.bhz-mobilebar a.wa{background:#188741;color:#fff}',
    '.bhz-mobilebar .of{align-self:center;position:relative;z-index:1;margin:0 -10px;padding:2px 5px;border-radius:100px;background:#fff;color:#2c2520;font-size:0.7rem;font-weight:800;line-height:1;box-shadow:0 1px 4px rgba(44,37,32,0.25)}',
    '.bhz-mobilebar .ic{font-size:1.2rem}',
    'body{padding-bottom:56px}',
    '.wa-float,.boa-zweef{display:none !important}',
    '.ts-switch{bottom:64px}',
    '}'
    ].join('');
    var st = document.createElement('style');
    st.id = 'bhz-a11y-css';
    st.textContent = regels;
    document.head.appendChild(st);
  }
  function buildSwitcher() {
    if (document.querySelector('.ts-switch')) return;
    var box = document.createElement('div');
    box.className = 'ts-switch';
    box.setAttribute('role', 'group');
    box.setAttribute('aria-label', EN ? 'Text size' : 'Tekstgrootte aanpassen');
    box.innerHTML =
      '<span class="ts-switch-label" aria-hidden="true">' + (EN ? 'Text' : 'Tekst') + '</span>' +
      '<button type="button" data-scale="normal" aria-label="' + (EN ? 'A, normal text size' : 'A, normale tekstgrootte') + '">A</button>' +
      '<button type="button" data-scale="l" aria-label="' + (EN ? 'A+, larger text' : 'A+, grotere tekst') + '">A+</button>' +
      '<button type="button" data-scale="xl" aria-label="' + (EN ? 'A++, largest text' : 'A++, grootste tekst') + '">A++</button>';
    box.addEventListener('click', function (e) {
      var b = e.target.closest('button');
      if (!b) return;
      var scale = b.getAttribute('data-scale');
      apply(scale);
      try { localStorage.setItem(KEY, scale); } catch (err) {}
      markPressed(box, scale);
    });
    document.body.appendChild(box);
    markPressed(box, saved || 'normal');
  }

  function wireFaq() {
    var btns = document.querySelectorAll('.faq-question');
    for (var i = 0; i < btns.length; i++) {
      if (!btns[i].hasAttribute('aria-expanded')) btns[i].setAttribute('aria-expanded', 'false');
      var arrow = btns[i].querySelector('.faq-arrow');
      if (arrow) arrow.setAttribute('aria-hidden', 'true');
    }
    document.addEventListener('click', function (e) {
      var b = e.target.closest('.faq-question');
      if (!b) return;
      // Laat de bestaande toggleFaq eerst lopen, lees dan de status.
      setTimeout(function () {
        var item = b.closest('.faq-item');
        b.setAttribute('aria-expanded', item && item.classList.contains('active') ? 'true' : 'false');
      }, 0);
    });
  }

  function hideDecorativeEmoji() {
    var hasEmoji = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{2190}-\u{21FF}\u{2B05}-\u{2B07}]/u;
    var hasText = /[0-9A-Za-zÀ-ɏ]/;
    var els = document.querySelectorAll('div, span');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.children.length === 0) {
        var t = (el.textContent || '').trim();
        if (t && t.length <= 6 && hasEmoji.test(t) && !hasText.test(t)) el.setAttribute('aria-hidden', 'true');
      }
    }
  }

  /* Dezelfde twee knoppen als op de pagina: "Bel of app" (links bellen, rechts
     WhatsApp, elk één tik) en "Bel mij terug". Heeft de pagina zelf een
     terugbelformulier, dan gaat die knop daarheen. */
  /* De balk is hoger dan de 56px die de CSS onderaan vrijhoudt (icoon plus
   * tekst; met grotere letters nog hoger). Meet hem en houd precies die
   * ruimte vrij, anders valt de onderkant van elke pagina erachter. */
  function ruimteOnderBalk(bar) {
    function zet() {
      var h = getComputedStyle(bar).display === 'none' ? 0 : Math.ceil(bar.getBoundingClientRect().height);
      document.body.style.paddingBottom = h ? h + 'px' : '';
    }
    zet();
    window.addEventListener('resize', zet);
    if (window.ResizeObserver) new ResizeObserver(zet).observe(bar);
  }

  function buildMobileBar() {
    var bestaand = document.querySelector('.bhz-mobilebar');
    if (bestaand) { ruimteOnderBalk(bestaand); return; }
    var bar = document.createElement('nav');
    bar.className = 'bhz-mobilebar';
    bar.setAttribute('aria-label', EN ? 'Quick contact' : 'Snel contact');
    var terug = document.getElementById('terugbellen') ? '#terugbellen' : '/contact/#terugbellen';
    bar.innerHTML =
      '<a class="bel" href="tel:+31619711848" rel="nofollow"><span class="ic" aria-hidden="true">📞</span>' + (EN ? 'Call' : 'Bel') + '</a>' +
      '<span class="of" aria-hidden="true">' + (EN ? 'or' : 'of') + '</span>' +
      '<a class="wa" href="https://wa.me/31619711848' + (EN ? '?text=Hi!%20I%20have%20a%20question.' : '') + '" rel="nofollow" aria-label="' + (EN ? 'WhatsApp' : 'App via WhatsApp') + '"><span class="ic" aria-hidden="true">💬</span>' + (EN ? 'WhatsApp' : 'App') + '</a>' +
      '<a href="' + terug + '"><span class="ic" aria-hidden="true">📅</span>' + (EN ? 'Call me back' : 'Bel mij terug') + '</a>';
    document.body.appendChild(bar);
    ruimteOnderBalk(bar);
  }

  function init() {
    injectCss();
    buildSwitcher();
    buildMobileBar();
    wireFaq();
    try { hideDecorativeEmoji(); } catch (e) {}
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
