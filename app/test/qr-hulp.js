'use strict';
/*
 * qr-hulp.js — een QR-code terughalen uit wat de app maakt (SVG of PDF), om
 * module voor module te vergelijken met wat qr.maak() bedoelde.
 */

/* de bedoelde code als rijen van true/false */
function matrixVan(q) {
  return Array.from({ length: q.grootte }, (_, y) => Array.from({ length: q.grootte }, (_, x) => !!q.donker(x, y)));
}

/* SVG van qr.svg(): per rij "M{x} {y}h{l}v1h-{l}z", met een witte rand */
function uitSvg(svg) {
  const z = Number(/viewBox="0 0 (\d+) \1"/.exec(svg)[1]);
  const vierkant = [...svg.matchAll(/M(\d+) (\d+)h(\d+)v1h-\d+z/g)].map((m) => m.slice(1).map(Number));
  const rand = Math.min(...vierkant.map((v) => v[0]));
  const n = z - 2 * rand;
  const m = Array.from({ length: n }, () => new Array(n).fill(false));
  for (const [x, y, l] of vierkant) for (let i = 0; i < l; i++) m[y - rand][x - rand + i] = true;
  return m;
}

/* PDF van pdf.qr(): per donker stuk een regel "x y b h re", elk vlak 0,05 pt hoger dan
 * een module. De linkerbovenhoek is altijd donker (zoekpatroon), dus de kleinste x en
 * de hoogste bovenkant zijn de oorsprong. */
function uitPdf(tekst, n) {
  const vlakken = [...tekst.matchAll(/^([\d.]+) ([\d.]+) ([\d.]+) ([\d.]+) re$/gm)].map((m) => m.slice(1).map(Number));
  const s = vlakken[0][3] - 0.05;
  const x0 = Math.min(...vlakken.map((v) => v[0]));
  const boven0 = Math.max(...vlakken.map((v) => v[1] + v[3]));
  const m = Array.from({ length: n }, () => new Array(n).fill(false));
  for (const [x, y, b, h] of vlakken) {
    const r = Math.round((boven0 - (y + h)) / s);
    const c = Math.round((x - x0) / s);
    for (let i = 0; i < Math.round(b / s); i++) m[r][c + i] = true;
  }
  return m;
}

module.exports = { matrixVan, uitSvg, uitPdf };
