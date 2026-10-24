'use strict';
/* De rekenhulpjes van scripts/buurtscore.js (het ophalen bij CBS en PDOK zelf
 * is netwerk; dat is met de hand gecontroleerd, zie de rapportage). */
const test = require('node:test');
const assert = require('node:assert/strict');
const b = require('../../scripts/buurtscore.js');

test('percentielrang: 0 tot 100, gelijke waarden dezelfde rang, leeg blijft leeg', () => {
  assert.deepEqual(b.percentielen([10, 20, 30, null]), [0, 50, 100, null]);
  assert.deepEqual(b.percentielen([5, 5, 9]), [25, 25, 100]);
  assert.deepEqual(b.percentielen([7]), [50]);
});

test('buurtnaam als campagnecode: kort, zonder accenten, past in de klikmeting', () => {
  assert.equal(b.slug('Westerkoog Oost'), 'westerkoog-oost');
  assert.equal(b.slug('J.J. Allanbuurt'), 'j-j-allanbuurt');
  assert.equal(b.slug('Neck (gedeeltelijk)'), 'neck-gedeeltelijk');
  assert.equal(b.slug('Verspr.h. ten noorden van De Middentocht'), 'verspr-h-ten-noorden-van-de-middentocht');
  const lang = b.slug('Een hele lange buurtnaam die veel te lang is voor een code');
  assert.ok(lang.length <= 40 && /^[a-z0-9-]+$/.test(lang) && !lang.endsWith('-'));
});

test('vereenvoudigen houdt de vorm en de eindpunten', () => {
  const lijn = [[0, 0], [1, 0.1], [2, -0.1], [3, 0.05], [4, 0], [4, 4], [0, 4], [0, 0]];
  const v = b.vereenvoudig(lijn, 0.5);
  assert.deepEqual(v[0], [0, 0]);
  assert.deepEqual(v[v.length - 1], [0, 0]);
  assert.ok(v.length < lijn.length);
  assert.ok(v.some((p) => p[0] === 4 && p[1] === 4), 'hoekpunt blijft');
  const m = b.oppervlakEnMidden([[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]]);
  assert.equal(m.a, 16);
  assert.equal(Math.round(m.x), 2);
  assert.equal(Math.round(m.y), 2);
});

test('CBS-kolommen per jaar: volgnummer weg, en 65+ als som zodra het CBS die splitst', () => {
  const k2025 = b.kolomSleutels([{ Key: 'ID' }, { Key: 'k_65JaarOfOuder_12' }, { Key: 'Koopwoningen_47' }]);
  assert.deepEqual(k2025.n65, ['k_65JaarOfOuder_12']);
  assert.deepEqual(k2025.koop, ['Koopwoningen_47']);
  assert.equal(k2025.vermogen, undefined, 'kolom die er niet is, valt weg');
  const k2026 = b.kolomSleutels([{ Key: 'k_65JaarTot80Jaar_12' }, { Key: 'k_80JaarOfOuder_13' }]);
  assert.deepEqual(k2026.n65, ['k_65JaarTot80Jaar_12', 'k_80JaarOfOuder_13']);
  assert.equal(b.kolomSleutels([{ Key: 'k_65JaarTot80Jaar_12' }]).n65, undefined, 'half gesplitst telt niet');
});

test('leeg cijfer: eerst het gevraagde jaar, dan het jaar ervoor, dan twee jaar ervoor', () => {
  const tabel = (jaar, rijen) => ({ jaar, perCode: new Map(Object.entries(rijen)) });
  const t = [tabel(2026, { BU1: { koop: null, huur: 40 } }), tabel(2025, { BU1: { koop: 61 } }), tabel(2024, { BU1: { koop: 59, vermogen: 80 } })];
  assert.deepEqual(b.kies('BU1', 'huur', t), { v: 40, jaar: 2026 });
  assert.deepEqual(b.kies('BU1', 'koop', t), { v: 61, jaar: 2025 });
  assert.deepEqual(b.kies('BU1', 'vermogen', t), { v: 80, jaar: 2024 });
  assert.deepEqual(b.kies('BU1', 'armoede', t), { v: null, jaar: null });
  assert.deepEqual(b.kies('BU2', 'huur', t), { v: null, jaar: null });
});

test('PDOK-velden van 2025 en 2026', () => {
  assert.equal(b.buurtcodeVan({ buurtcode: 'BU04790101' }), 'BU04790101');
  assert.equal(b.buurtcodeVan({ bu_code: 'BU04791111' }), 'BU04791111');
  assert.equal(b.gemeentecodeVan({ gemeentecode: 'GM0479' }), 'GM0479');
  assert.equal(b.gemeentecodeVan({ gm_code: 'GM0431' }), 'GM0431');
});

test('elke doelgroep heeft een landingspagina die bestaat, en gewichten die optellen tot 1', () => {
  const fs = require('fs');
  const path = require('path');
  for (const dg of b.DOELGROEPEN) {
    assert.ok(fs.existsSync(path.join(__dirname, '..', '..', dg.landing, 'index.html')), dg.landing);
    assert.equal(Math.round(Object.values(dg.gewichten).reduce((a, w) => a + w, 0) * 100), 100, dg.code);
  }
});
