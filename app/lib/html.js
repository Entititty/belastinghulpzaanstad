'use strict';
/*
 * html.js — HTML maken in /beheer zonder dat ingevulde tekst HTML kan worden.
 *
 *   h`<p>${naam}</p>`          naam wordt altijd ontsnapt
 *   h`<ul>${lijst.map(...)}</ul>`  een lijst van h`` wordt aan elkaar gezet
 *   veilig(s)                  alleen voor HTML die we zelf maken (svg, opgebouwde HTML)
 *
 * In /beheer staat alles wat bezoekers invullen. Een naam als
 * "<script>...</script>" mag daar nooit iets doen; de CSP staat bovendien geen
 * inline scripts toe.
 */
class Veilig {
  constructor(s) { this.html = s; }
  toString() { return this.html; }
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function waarde(v) {
  if (v === null || v === undefined || v === false) return '';
  if (v instanceof Veilig) return v.html;
  if (Array.isArray(v)) return v.map(waarde).join('');
  return esc(v);
}

function h(delen, ...waarden) {
  let s = delen[0];
  for (let i = 0; i < waarden.length; i++) s += waarde(waarden[i]) + delen[i + 1];
  return new Veilig(s);
}

function veilig(s) { return new Veilig(String(s)); }

module.exports = { h, veilig, esc, Veilig };
