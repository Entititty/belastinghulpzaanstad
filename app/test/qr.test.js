'use strict';
/*
 * De QR-encoder, gecontroleerd door elke code weer terug te lezen zoals een
 * scanner dat doet: formaatinformatie (met BCH-controle), maskers eraf,
 * codewoorden uit de blokken, Reed-Solomon per blok, en de data terug.
 * Een tweede controle tegen een bekende bibliotheek staat buiten de repo
 * (zie de rapportage); scan een flyer altijd ook met een telefoon.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const qr = require('../lib/qr');

const NIVEAU_UIT_BITS = { 1: 'L', 0: 'M', 3: 'Q', 2: 'H' };

function lees(code) {
  const m = code.matrix;
  const n = m.length;
  const versie = (n - 17) / 4;
  assert.ok(Number.isInteger(versie) && versie >= 1 && versie <= 40, 'grootte ' + n);
  const get = (x, y) => m[y][x];

  /* formaat, eerste kopie */
  const plek = [];
  for (let i = 0; i <= 5; i++) plek.push([8, i]);
  plek.push([8, 7], [8, 8], [7, 8]);
  for (let i = 9; i < 15; i++) plek.push([14 - i, 8]);
  let bits = 0;
  plek.forEach(([x, y], i) => { if (get(x, y)) bits |= 1 << i; });
  /* tweede kopie moet gelijk zijn */
  let bits2 = 0;
  for (let i = 0; i < 8; i++) if (get(n - 1 - i, 8)) bits2 |= 1 << i;
  for (let i = 8; i < 15; i++) if (get(8, n - 15 + i)) bits2 |= 1 << i;
  assert.equal(bits2, bits, 'twee kopieën van de formaatinformatie verschillen');
  assert.equal(get(8, n - 8), true, 'de vaste donkere module ontbreekt');
  const f = bits ^ 0x5412;
  const niveau = NIVEAU_UIT_BITS[f >>> 13];
  const masker = (f >>> 10) & 7;
  assert.equal(qr.formaatBits(niveau, masker), bits, 'BCH van de formaatinformatie klopt niet');

  /* versie-informatie vanaf versie 7 */
  if (versie >= 7) {
    let v = 0;
    for (let i = 0; i < 18; i++) if (get(n - 11 + (i % 3), Math.floor(i / 3))) v |= 1 << i;
    assert.equal(v, qr.versieBits(versie), 'versie-informatie klopt niet');
  }

  /* data lezen, masker eraf */
  const { posities } = qr.functieKaart(versie);
  const totaal = Math.floor(qr.modulesVoorData(versie) / 8);
  const woorden = new Array(totaal).fill(0);
  for (let i = 0; i < totaal * 8; i++) {
    const [x, y] = posities[i];
    const bit = get(x, y) !== qr.MASKERS[masker](x, y);
    if (bit) woorden[i >> 3] |= 1 << (7 - (i & 7));
  }

  /* blokken terug, Reed-Solomon per blok */
  const ni = qr.NIVEAUS[niveau];
  const aantal = qr.BLOKKEN[ni][versie];
  const ecc = qr.ECC_PER_BLOK[ni][versie];
  const kort = aantal - (totaal % aantal);
  const kortLengte = Math.floor(totaal / aantal) - ecc;
  const blokken = Array.from({ length: aantal }, (_, i) => ({ d: [], e: [], lengte: kortLengte + (i < kort ? 0 : 1) }));
  let k = 0;
  for (let i = 0; i < kortLengte + 1; i++) for (const b of blokken) if (i < b.lengte) b.d.push(woorden[k++]);
  for (let i = 0; i < ecc; i++) for (const b of blokken) b.e.push(woorden[k++]);
  assert.equal(k, totaal);
  for (const b of blokken) assert.deepEqual(qr.reedSolomon(b.d, ecc), b.e, 'Reed-Solomon klopt niet');

  /* bitstroom: byte-modus */
  const data = [].concat(...blokken.map((b) => b.d));
  let pos = 0;
  const lees = (len) => { let w = 0; for (let i = 0; i < len; i++, pos++) w = (w << 1) | ((data[pos >> 3] >>> (7 - (pos & 7))) & 1); return w; };
  assert.equal(lees(4), 4, 'geen byte-modus');
  const lengte = lees(versie < 10 ? 8 : 16);
  const bytes = [];
  for (let i = 0; i < lengte; i++) bytes.push(lees(8));
  return { tekst: Buffer.from(bytes).toString('utf8'), versie, niveau, masker };
}

const VOORBEELDEN = [
  'a',
  'https://belastinghulpzaanstad.nl/',
  'https://belastinghulpzaanstad.nl/senioren/?utm_source=flyer&utm_medium=print&utm_campaign=rosmolenwijk&utm_content=senioren',
  'https://belastinghulpzaanstad.nl/diensten/voorlopige-teruggave/?utm_source=flyer&utm_medium=print&utm_campaign=koog-aan-de-zaan-noord&utm_content=woningbezitters',
  'otpauth://totp/Belastinghulp%20Zaanstad:stan?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Belastinghulp%20Zaanstad&algorithm=SHA1&digits=6&period=30',
  'Zoë en één €-teken: UTF-8',
  'x'.repeat(300)
];

test('elke code leest terug tot dezelfde tekst, op alle niveaus', () => {
  for (const tekst of VOORBEELDEN) {
    for (const niveau of ['L', 'M', 'Q', 'H']) {
      const code = qr.maak(tekst, niveau);
      const r = lees(code);
      assert.equal(r.tekst, tekst);
      assert.equal(r.niveau, niveau);
      assert.equal(r.versie, code.versie);
    }
  }
});

test('alle acht maskers zijn geldig', () => {
  for (let masker = 0; masker < 8; masker++) {
    const code = qr.maak(VOORBEELDEN[2], 'M', { masker });
    const r = lees(code);
    assert.equal(r.masker, masker);
    assert.equal(r.tekst, VOORBEELDEN[2]);
  }
});

test('de kleinste versie die past, en de bekende capaciteit', () => {
  /* versie 1-M bevat 14 bytes, versie 1-L 17 bytes (norm, tabel 7) */
  assert.equal(qr.maak('x'.repeat(14), 'M').versie, 1);
  assert.equal(qr.maak('x'.repeat(15), 'M').versie, 2);
  assert.equal(qr.maak('x'.repeat(17), 'L').versie, 1);
  assert.equal(qr.datawoorden(1, 'M'), 16);
  assert.equal(qr.datawoorden(10, 'H'), 122);
  assert.equal(qr.datawoorden(40, 'L'), 2956);
  assert.deepEqual(qr.uitlijning(7), [6, 22, 38]);
  assert.deepEqual(qr.uitlijning(32), [6, 34, 60, 86, 112, 138]);
});

test('formaatinformatie: bekende waarde uit de norm', () => {
  /* niveau M, masker 5: 100000011001110 (ISO/IEC 18004, bijlage C) */
  assert.equal(qr.formaatBits('M', 5).toString(2).padStart(15, '0'), '100000011001110');
  /* versie 7: 000111110010010100 */
  assert.equal(qr.versieBits(7).toString(2).padStart(18, '0'), '000111110010010100');
});

test('svg en terminal', () => {
  /* 33 tekens: versie 3 bij niveau M (29 modules), plus 4 rand aan elke kant */
  const code = qr.maak('https://belastinghulpzaanstad.nl/', 'M');
  assert.equal(code.versie, 3);
  const s = qr.svg(code, { titel: 'QR-code' });
  assert.ok(s.startsWith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 37 37"'), s.slice(0, 80));
  assert.match(s, /aria-label="QR-code"/);
  /* de svg tekent precies de donkere modules */
  let donker = 0;
  for (let y = 0; y < code.grootte; y++) for (let x = 0; x < code.grootte; x++) if (code.donker(x, y)) donker++;
  const getekend = [...s.matchAll(/h(\d+)v1/g)].reduce((a, m) => a + Number(m[1]), 0);
  assert.equal(getekend, donker);
  const t = qr.terminal(code);
  assert.equal(t.split('\n').length, Math.ceil((code.grootte + 4) / 2));
});
