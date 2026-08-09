/* Toegankelijkheid (Taak 9)
   1. Tekstgrootte-schakelaar A / A+ / A++ (onthoudt de keuze in localStorage).
   2. FAQ-knoppen: aria-expanded bijhouden voor schermlezers.
   3. Decoratieve icoon-emoji: aria-hidden zetten. */
(function () {
  var KEY = 'bhz-tekstgrootte';
  var root = document.documentElement;

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

  function buildSwitcher() {
    if (document.querySelector('.ts-switch')) return;
    var box = document.createElement('div');
    box.className = 'ts-switch';
    box.setAttribute('role', 'group');
    box.setAttribute('aria-label', 'Tekstgrootte aanpassen');
    box.innerHTML =
      '<span class="ts-switch-label" aria-hidden="true">Tekst</span>' +
      '<button type="button" data-scale="normal" aria-label="Normale tekstgrootte">A</button>' +
      '<button type="button" data-scale="l" aria-label="Grotere tekst">A+</button>' +
      '<button type="button" data-scale="xl" aria-label="Grootste tekst">A++</button>';
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

  function buildMobileBar() {
    if (document.querySelector('.bhz-mobilebar')) return;
    var bar = document.createElement('nav');
    bar.className = 'bhz-mobilebar';
    bar.setAttribute('aria-label', 'Snel contact');
    bar.innerHTML =
      '<a href="tel:+31619711848" rel="nofollow"><span class="ic" aria-hidden="true">📞</span>Bellen</a>' +
      '<a href="/contact/#terugbellen"><span class="ic" aria-hidden="true">📅</span>Terugbellen</a>' +
      '<a class="wa" href="https://wa.me/31619711848" rel="nofollow"><span class="ic" aria-hidden="true">💬</span>WhatsApp</a>';
    document.body.appendChild(bar);
  }

  function init() {
    buildSwitcher();
    buildMobileBar();
    wireFaq();
    try { hideDecorativeEmoji(); } catch (e) {}
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
