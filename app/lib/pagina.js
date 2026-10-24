'use strict';
/*
 * pagina.js — een eenvoudige pagina in de huisstijl, voor wat de app zelf
 * moet laten zien: een foutmelding zonder JavaScript, of "kijk in uw mail".
 *
 * De gewone pagina's (bedankt, herinnering) zijn statische HTML in de repo en
 * gaan door alle controles van de build. Dit is alleen het vangnet voor de
 * paar gevallen waarin de browser geen JavaScript draait.
 */
const fs = require('fs');
const { esc } = require('./berichten');

let cache = { tijd: 0, naam: null };
function stylesheet(root) {
  const nu = Date.now();
  if (nu - cache.tijd > 60e3) {
    let naam = null;
    try { naam = fs.readdirSync(root).find((n) => /^belasting\.[0-9a-f]{8}\.min\.css$/.test(n)) || null; } catch (e) { naam = null; }
    cache = { tijd: nu, naam };
  }
  return cache.naam ? '/' + cache.naam : null;
}

const PAAR = '<div class="cta-paar" style="margin-top:22px;"><span class="boa" role="group" aria-label="Bel of app">' +
  '<a href="tel:+31619711848" class="boa-bel" rel="nofollow"><span aria-hidden="true">&#128222;</span> Bel<span class="boa-nr"> 06&nbsp;&ndash;&nbsp;19&nbsp;71&nbsp;18&nbsp;48</span></a>' +
  '<span class="boa-of" aria-hidden="true">of</span>' +
  '<a href="https://wa.me/31619711848" class="boa-app" rel="nofollow" aria-label="App via WhatsApp"><span aria-hidden="true">&#128172;</span> App</a></span></div>';

/* alineas: HTML, dus al ontsnapt door de aanroeper */
function pagina(root, titel, alineas, opties) {
  const css = stylesheet(root);
  const o = opties || {};
  return '<!doctype html><html lang="nl"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="robots" content="noindex, nofollow">' +
    '<title>' + esc(titel) + ' | Belastinghulp Zaanstad</title>' +
    (css ? '<link rel="stylesheet" href="' + css + '">' : '') +
    '</head><body style="background:#FAF6F0;">' +
    '<main style="padding:48px 16px 64px;"><div class="container" style="max-width:640px;">' +
    '<p style="margin:0 0 28px;"><a href="/" style="color:var(--clr-teal);font-weight:800;text-decoration:none;font-size:1.1rem;">Belastinghulp Zaanstad</a></p>' +
    '<h1 style="font-family:var(--font-display);font-size:1.9rem;line-height:1.25;color:var(--clr-deep);margin:0 0 18px;">' + esc(titel) + '</h1>' +
    alineas.map((a) => '<p style="font-size:1.08rem;line-height:1.7;color:var(--clr-bark);margin:0 0 14px;">' + a + '</p>').join('') +
    (o.zonderKnoppen ? '' : PAAR) +
    (o.terug ? '<p style="margin-top:26px;"><a href="' + esc(o.terug) + '" class="tekstlink">&larr; Terug</a></p>' : '') +
    '</div></main></body></html>';
}

module.exports = { pagina };
