/* Seizoensbanner — kiest op basis van de huidige maand de juiste boodschap
   uit /data/seizoen.json en vult de #uitstel-strip. De HTML bevat al de
   boodschap voor de huidige periode als fallback (werkt ook zonder JS).
   Teksten bewerken? Zie /data/seizoen.json — geen code nodig. */
(function () {
  var strip = document.getElementById('uitstel-strip');
  if (!strip) return;
  fetch('/data/seizoen.json')
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var m = new Date().getMonth() + 1;
      var p = null;
      for (var i = 0; i < d.perioden.length; i++) {
        var x = d.perioden[i];
        if (m >= x.van_maand && m <= x.tot_maand) { p = x; break; }
      }
      if (!p) return;
      var badge = document.getElementById('seizoen-badge');
      var title = document.getElementById('seizoen-title');
      var desc = document.getElementById('seizoen-desc');
      var chip = document.getElementById('seizoen-chip');
      var cta = document.getElementById('seizoen-cta');
      if (badge) badge.textContent = '⏰ ' + p.badge;
      if (title) title.innerHTML = p.titel;
      if (desc) desc.textContent = p.desc;
      if (chip) chip.textContent = '✓ ' + p.chip;
      if (cta) {
        cta.textContent = '💬 ' + p.cta_label + ' →';
        cta.href = 'https://wa.me/31619711848?text=' + p.wa_text;
      }
    })
    .catch(function () { /* fallback: HTML-standaard blijft staan */ });
})();
