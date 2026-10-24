'use strict';
/*
 * qr.js — QR-codes maken, zonder pakketten.
 *
 * Voor de code om de inlog-app te koppelen (beheer-gebruiker.js), voor
 * partnerkaarten en voor flyers per buurt. Alleen de byte-modus (UTF-8), want
 * daar past alles in. Volgt ISO/IEC 18004: Reed-Solomon over GF(256), blokken
 * en interleaving per versie, de acht maskers met strafpunten, formaat- en
 * versie-informatie. De tabellen zijn die uit de norm.
 *
 * app/test/qr.test.js leest elke code weer terug (maskers eraf, codewoorden
 * eruit, Reed-Solomon-controle, data) en vergelijkt hem met een bekende
 * bibliotheek. Scan een flyer toch altijd één keer met een telefoon voordat
 * hij naar de drukker gaat.
 *
 *   const qr = maak('https://...', 'M');   // { grootte, donker(x, y), versie, niveau, masker }
 *   svg(qr, { rand: 4, schaal: 8 })         // <svg ...>
 *   terminal(qr)                            // tekst met halve blokjes, voor in een terminal
 */

const NIVEAUS = { L: 0, M: 1, Q: 2, H: 3 };
/* bits voor de formaatinformatie: L=01, M=00, Q=11, H=10 */
const FORMAAT_BITS = { L: 1, M: 0, Q: 3, H: 2 };

/* per niveau (L, M, Q, H) en versie (1..40): foutcorrectie-codewoorden per blok, en het aantal blokken */
const ECC_PER_BLOK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
];
const BLOKKEN = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
];

/* ---------------- GF(256) en Reed-Solomon ---------------- */
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function () {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
function maal(a, b) { return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]; }

/* generator (x - a^0)(x - a^1)...(x - a^(n-1)), coefficienten van hoog naar laag, zonder de leidende 1 */
function generator(n) {
  let g = [1];
  for (let i = 0; i < n; i++) {
    const nieuw = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      nieuw[j] ^= g[j];
      nieuw[j + 1] ^= maal(g[j], EXP[i]);
    }
    g = nieuw;
  }
  return g.slice(1);
}
function reedSolomon(data, n) {
  const g = generator(n);
  const rest = new Array(n).fill(0);
  for (const b of data) {
    const factor = b ^ rest.shift();
    rest.push(0);
    for (let i = 0; i < n; i++) rest[i] ^= maal(g[i], factor);
  }
  return rest;
}

/* ---------------- capaciteit ---------------- */
function modulesVoorData(versie) {
  let n = (16 * versie + 128) * versie + 64;
  if (versie >= 2) {
    const a = Math.floor(versie / 7) + 2;
    n -= (25 * a - 10) * a - 55;
    if (versie >= 7) n -= 36;
  }
  return n;
}
function datawoorden(versie, niveau) {
  const i = NIVEAUS[niveau];
  return Math.floor(modulesVoorData(versie) / 8) - ECC_PER_BLOK[i][versie] * BLOKKEN[i][versie];
}

/* posities van de uitlijningspatronen */
function uitlijning(versie) {
  if (versie === 1) return [];
  const aantal = Math.floor(versie / 7) + 2;
  const stap = versie === 32 ? 26 : Math.ceil((versie * 4 + 4) / (aantal * 2 - 2)) * 2;
  const r = [6];
  for (let pos = versie * 4 + 10; r.length < aantal; pos -= stap) r.splice(1, 0, pos);
  return r;
}

/* ---------------- BCH voor formaat- en versie-informatie ---------------- */
function formaatBits(niveau, masker) {
  const d = (FORMAAT_BITS[niveau] << 3) | masker;
  let r = d;
  for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537);
  return ((d << 10) | r) ^ 0x5412;
}
function versieBits(versie) {
  let r = versie;
  for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
  return (versie << 12) | r;
}

const MASKERS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
];

/* ---------------- de matrix ---------------- */
function nieuweMatrix(versie) {
  const n = versie * 4 + 17;
  return {
    n,
    m: Array.from({ length: n }, () => new Array(n).fill(false)),
    vast: Array.from({ length: n }, () => new Array(n).fill(false))
  };
}
function zet(q, x, y, donker) { q.m[y][x] = donker; q.vast[y][x] = true; }

function functiepatronen(q, versie) {
  const n = q.n;
  for (let i = 0; i < n; i++) { zet(q, 6, i, i % 2 === 0); zet(q, i, 6, i % 2 === 0); }
  const zoeker = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy;
        if (x < 0 || y < 0 || x >= n || y >= n) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        zet(q, x, y, d !== 2 && d !== 4);
      }
    }
  };
  zoeker(3, 3); zoeker(n - 4, 3); zoeker(3, n - 4);
  const pos = uitlijning(versie);
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === pos.length - 1) || (i === pos.length - 1 && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) zet(q, pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }
  /* plekken voor formaat- en versie-informatie alvast reserveren */
  zetFormaat(q, 'M', 0);
  if (versie >= 7) zetVersie(q, versie);
}

function zetFormaat(q, niveau, masker) {
  const bits = formaatBits(niveau, masker);
  const bit = (i) => ((bits >>> i) & 1) !== 0;
  const n = q.n;
  for (let i = 0; i <= 5; i++) zet(q, 8, i, bit(i));
  zet(q, 8, 7, bit(6));
  zet(q, 8, 8, bit(7));
  zet(q, 7, 8, bit(8));
  for (let i = 9; i < 15; i++) zet(q, 14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) zet(q, n - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) zet(q, 8, n - 15 + i, bit(i));
  zet(q, 8, n - 8, true);
}

function zetVersie(q, versie) {
  const bits = versieBits(versie);
  for (let i = 0; i < 18; i++) {
    const d = ((bits >>> i) & 1) !== 0;
    const a = q.n - 11 + (i % 3), b = Math.floor(i / 3);
    zet(q, a, b, d);
    zet(q, b, a, d);
  }
}

/* de datamodules in volgorde: in kolomparen van rechts naar links, zigzag op en neer */
function dataPosities(q) {
  const r = [];
  const n = q.n;
  for (let rechts = n - 1; rechts >= 1; rechts -= 2) {
    if (rechts === 6) rechts = 5;
    for (let v = 0; v < n; v++) {
      for (let j = 0; j < 2; j++) {
        const x = rechts - j;
        const omhoog = ((rechts + 1) & 2) === 0;
        const y = omhoog ? n - 1 - v : v;
        if (!q.vast[y][x]) r.push([x, y]);
      }
    }
  }
  return r;
}

function strafpunten(q) {
  const n = q.n, m = q.m;
  let straf = 0;
  /* N1 en N3, per rij en per kolom */
  const lijn = (get) => {
    let p = 0, kleur = get(0), lengte = 1;
    for (let i = 1; i < n; i++) {
      const c = get(i);
      if (c === kleur) { lengte++; } else { if (lengte >= 5) p += lengte - 2; kleur = c; lengte = 1; }
    }
    if (lengte >= 5) p += lengte - 2;
    /* 1:1:3:1:1 met 4 licht ervoor of erna; buiten de code is alles licht */
    const licht = (k) => k < 0 || k >= n || !get(k);
    for (let i = 0; i + 6 < n; i++) {
      if (get(i) && !get(i + 1) && get(i + 2) && get(i + 3) && get(i + 4) && !get(i + 5) && get(i + 6)) {
        if (licht(i - 1) && licht(i - 2) && licht(i - 3) && licht(i - 4)) p += 40;
        if (licht(i + 7) && licht(i + 8) && licht(i + 9) && licht(i + 10)) p += 40;
      }
    }
    return p;
  };
  for (let y = 0; y < n; y++) straf += lijn((i) => m[y][i]);
  for (let x = 0; x < n; x++) straf += lijn((i) => m[i][x]);
  /* N2: blokken van 2x2 */
  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) straf += 3;
    }
  }
  /* N4: verhouding donker */
  let donker = 0;
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (m[y][x]) donker++;
  const k = Math.ceil(Math.abs(donker * 20 - n * n * 10) / (n * n)) - 1;
  straf += Math.max(0, k) * 10;
  return straf;
}

/* ---------------- maken ---------------- */
function maak(tekst, niveau, opties) {
  const o = opties || {};
  niveau = niveau || 'M';
  if (!(niveau in NIVEAUS)) throw new Error('onbekend niveau ' + niveau);
  const data = Buffer.from(String(tekst), 'utf8');

  let versie = o.versie || 0;
  if (!versie) {
    for (let v = 1; v <= 40; v++) {
      const bits = 4 + (v < 10 ? 8 : 16) + data.length * 8;
      if (bits <= datawoorden(v, niveau) * 8) { versie = v; break; }
    }
    if (!versie) throw new Error('te veel tekst voor een QR-code');
  }
  const capaciteit = datawoorden(versie, niveau) * 8;

  /* bitstroom */
  const bits = [];
  const schrijf = (waarde, lengte) => { for (let i = lengte - 1; i >= 0; i--) bits.push((waarde >>> i) & 1); };
  schrijf(4, 4);
  schrijf(data.length, versie < 10 ? 8 : 16);
  for (const b of data) schrijf(b, 8);
  if (bits.length > capaciteit) throw new Error('past niet in versie ' + versie);
  schrijf(0, Math.min(4, capaciteit - bits.length));
  schrijf(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capaciteit; pad ^= 0xec ^ 0x11) schrijf(pad, 8);
  const woorden = [];
  for (let i = 0; i < bits.length; i += 8) {
    let w = 0;
    for (let j = 0; j < 8; j++) w = (w << 1) | bits[i + j];
    woorden.push(w);
  }

  /* blokken en foutcorrectie */
  const ni = NIVEAUS[niveau];
  const aantalBlokken = BLOKKEN[ni][versie];
  const eccLengte = ECC_PER_BLOK[ni][versie];
  const totaal = Math.floor(modulesVoorData(versie) / 8);
  const korteBlokken = aantalBlokken - (totaal % aantalBlokken);
  const korteLengte = Math.floor(totaal / aantalBlokken);
  const blokken = [];
  for (let i = 0, k = 0; i < aantalBlokken; i++) {
    const lengte = korteLengte - eccLengte + (i < korteBlokken ? 0 : 1);
    const d = woorden.slice(k, k + lengte);
    k += lengte;
    blokken.push({ d, e: reedSolomon(d, eccLengte) });
  }
  const reeks = [];
  for (let i = 0; i < korteLengte - eccLengte + 1; i++) for (const b of blokken) if (i < b.d.length) reeks.push(b.d[i]);
  for (let i = 0; i < eccLengte; i++) for (const b of blokken) reeks.push(b.e[i]);

  /* matrix met data, dan het beste masker */
  const q = nieuweMatrix(versie);
  functiepatronen(q, versie);
  const posities = dataPosities(q);
  posities.forEach(([x, y], i) => {
    const w = reeks[i >> 3];
    q.m[y][x] = w !== undefined && ((w >>> (7 - (i & 7))) & 1) === 1;
  });
  let beste = null;
  const maskers = o.masker !== undefined ? [o.masker] : [0, 1, 2, 3, 4, 5, 6, 7];
  for (const masker of maskers) {
    const kopie = { n: q.n, m: q.m.map((r) => r.slice()), vast: q.vast };
    for (const [x, y] of posities) if (MASKERS[masker](x, y)) kopie.m[y][x] = !kopie.m[y][x];
    zetFormaat(kopie, niveau, masker);
    const p = strafpunten(kopie);
    if (!beste || p < beste.p) beste = { p, m: kopie.m, masker };
  }
  return {
    grootte: q.n, versie, niveau, masker: beste.masker, matrix: beste.m,
    donker: (x, y) => beste.m[y][x]
  };
}

/* ---------------- uitvoer ---------------- */
function svg(qr, opties) {
  const o = opties || {};
  const rand = o.rand === undefined ? 4 : o.rand;
  const schaal = o.schaal || 8;
  const z = qr.grootte + rand * 2;
  /* per rij de donkere stukken samengevoegd: een veel kleiner bestand */
  let pad = '';
  for (let y = 0; y < qr.grootte; y++) {
    for (let x = 0; x < qr.grootte; x++) {
      if (!qr.donker(x, y)) continue;
      let lengte = 1;
      while (x + lengte < qr.grootte && qr.donker(x + lengte, y)) lengte++;
      pad += 'M' + (x + rand) + ' ' + (y + rand) + 'h' + lengte + 'v1h-' + lengte + 'z';
      x += lengte - 1;
    }
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + z + ' ' + z + '" width="' + z * schaal + '" height="' + z * schaal +
    '" shape-rendering="crispEdges"' + (o.titel ? ' role="img" aria-label="' + String(o.titel).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;') + '"' : '') + '>' +
    '<rect width="' + z + '" height="' + z + '" fill="#fff"/><path d="' + pad + '" fill="#000"/></svg>';
}

/* Voor in een terminal: twee rijen per regel met halve blokjes, licht op donker omgekeerd
 * zodat het ook in een donkere terminal scant. */
function terminal(qr) {
  const rand = 2;
  const z = qr.grootte + rand * 2;
  const d = (x, y) => x >= rand && y >= rand && x < qr.grootte + rand && y < qr.grootte + rand && qr.donker(x - rand, y - rand);
  const regels = [];
  for (let y = 0; y < z; y += 2) {
    let r = '';
    for (let x = 0; x < z; x++) {
      const boven = !d(x, y), onder = y + 1 < z ? !d(x, y + 1) : false;
      r += boven && onder ? '█' : boven ? '▀' : onder ? '▄' : ' ';
    }
    regels.push(r);
  }
  return regels.join('\n');
}

/* voor de test, die de code weer terugleest */
function functieKaart(versie) {
  const q = nieuweMatrix(versie);
  functiepatronen(q, versie);
  return { vast: q.vast, posities: dataPosities(q) };
}

module.exports = {
  maak, svg, terminal, datawoorden, formaatBits, versieBits, uitlijning, reedSolomon, MASKERS, NIVEAUS,
  ECC_PER_BLOK, BLOKKEN, modulesVoorData, functieKaart
};
