'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./hulp');
const o = require('../lib/overzicht');

test('periode en emmers', () => {
  /* woensdag 4 november 2026; 13 weken = deze week en de 12 ervoor */
  const p = o.periode('13', '2026-11-04', null);
  assert.equal(p.van, '2026-08-10');
  assert.equal(o.maandag('2026-11-04'), '2026-11-02');
  assert.deepEqual(p.vorige, { van: '2026-05-11', tot: '2026-08-09' });
  const e = o.emmers(p.van, p.tot);
  assert.equal(e.soort, 'week');
  assert.equal(e.lijst.length, 13);
  assert.equal(e.lijst[0].label, '10 aug');
  const m = o.emmers('2025-11-01', '2026-11-04');
  assert.equal(m.soort, 'maand');
  assert.equal(m.lijst.length, 13);
  assert.equal(m.lijst[2].label, "jan '26");
  assert.equal(o.periode('jaar', '2026-11-04').van, '2026-01-01');
  assert.equal(o.periode('alles', '2026-11-04', '2026-09-01').van, '2026-09-01');
});

test('ronde schaal en campagnecode', () => {
  assert.deepEqual([0, 3, 5, 7, 12, 26, 140].map(o.mooiMax), [4, 4, 5, 10, 20, 50, 200]);
  assert.equal(o.campagneCode('Koog aan de Zaan/Noord'), 'koog-aan-de-zaan-noord');
});

test('kolommen: dunne kolommen, labels zonder NaN, tooltip als tekst', () => {
  const punten = Array.from({ length: 13 }, (_, i) => ({ label: i + ' nov', waarde: i % 4, tip: 'Week <' + i + '>' }));
  const svg = o.kolommen(punten, 360, 'Aanvragen').html;
  assert.ok(!/NaN|undefined/.test(svg));
  assert.equal((svg.match(/<path /g) || []).length, punten.filter((p) => p.waarde > 0).length);
  assert.match(svg, /data-tip="Week &lt;3&gt;"/);
  assert.equal((svg.match(/class="hit"/g) || []).length, 13);
});

test('de pagina: kerncijfers, grafieken, bronnen, rekentools, flyers en knoppen', async () => {
  const t = await startApp({ start: '2026-11-04T19:00:00Z' });
  try {
    const voeg = t.db.prepare(`INSERT INTO aanvragen (aangemaakt, kanaal, formulier, naam, telefoon, dienst, rekentool, bron, bron_detail, utm_campaign,
      grondslag, status, omzet_centen, gewijzigd) VALUES (?, 'formulier', 'terugbellen', ?, '+31600000000', ?, ?, ?, ?, ?, 'toestemming', ?, ?, 'x')`);
    voeg.run('2026-11-03T18:00:00.000Z', 'A', 'voorlopige-teruggave', null, 'flyer', 'rosmolenwijk', 'rosmolenwijk', 'klant', 14900);
    voeg.run('2026-11-02T18:00:00.000Z', 'B', 'voorlopige-teruggave', 'voorlopige-teruggave', 'flyer', 'rosmolenwijk', 'rosmolenwijk', 'nieuw', null);
    voeg.run('2026-10-20T18:00:00.000Z', 'C', 'aangifte', null, 'zoekmachine', 'google.nl', null, 'klant', 5900);
    voeg.run('2026-06-01T18:00:00.000Z', 'D', 'aangifte', null, 'direct', null, null, 'nieuw', null); /* vorige periode */
    const klik = t.db.prepare('INSERT INTO klikken (dag, e, p, k, b, c, n) VALUES (?, ?, ?, ?, ?, ?, ?)');
    klik.run('2026-11-03', 'bezoek', '/senioren/', '', 'flyer', 'rosmolenwijk', 9);
    klik.run('2026-11-03', 'whatsapp', '/senioren/', 'balk', 'flyer', 'rosmolenwijk', 3);
    klik.run('2026-11-03', 'tel', '/', 'hero', 'direct', '', 2);
    klik.run('2026-11-01', 'rekentool', '/rekentools/voorlopige-teruggave/', 'voorlopige-teruggave', 'direct', '', 5);
    const b = await t.beheer();
    const r = await b.haal('/beheer/overzicht?periode=13');
    assert.equal(r.status, 200);
    const s = (await r.text()).replace(/>\s+</g, '><');
    assert.ok(!/\d\.\d{3,}/.test(s), 'coördinaten afgerond');
    /* kerncijfers: 3 aanvragen (de vierde valt in de vorige periode), 2 klant, 67%, € 208 */
    assert.match(s, /<div class="kpi-label">Aanvragen<\/div><div class="kpi-waarde">3<\/div><div class="kpi-delta op">▲ \+2 t\.o\.v\. de periode ervoor/);
    assert.match(s, /<div class="kpi-waarde">67%<\/div>/);
    assert.match(s, /<div class="kpi-waarde">€ 208<\/div>/);
    assert.match(s, /Klikken op bellen of WhatsApp<\/div><div class="kpi-waarde">5</);
    /* twee keer elke grafiek (smal en breed) en een tabel erbij */
    assert.equal((s.match(/<svg class="grafiek"/g) || []).length, 4);
    assert.match(s, /<summary>Als tabel<\/summary>/);
    assert.ok(!/NaN/.test(s));
    /* flyertrechter */
    assert.match(s, /<td>rosmolenwijk<\/td><td class="getal">9<\/td><td class="getal">3<\/td><td class="getal">2<\/td><td class="getal">1<\/td><td class="getal">€ 149<\/td>/);
    /* rekentool: 5 keer gebruikt, 1 aanvraag = 20% */
    assert.match(s, /<td>Voorlopige teruggave<\/td><td class="getal">5<\/td>[\s\S]*?<td class="getal">1<\/td><td class="getal">20%<\/td>/);
    assert.match(s, /Balk onderin \(telefoon\)/);
    assert.match(s, /<td>Flyer<\/td><td class="getal">2<\/td>/);
    /* tot 26 weken per week; is er een oudere aanvraag, dan per maand */
    assert.match(await (await b.haal('/beheer/overzicht?periode=alles')).text(), /Aanvragen per week/);
    voeg.run('2025-09-15T18:00:00.000Z', 'E', 'aangifte', null, 'direct', null, null, 'nieuw', null);
    const alles = await (await b.haal('/beheer/overzicht?periode=alles')).text();
    assert.match(alles, /Aanvragen per maand/);
    assert.match(alles, /Sep 2025: 1 aanvraag/);
    /* nu inlezen */
    const inl = await b.stuur('/beheer/overzicht/inlezen', {});
    assert.equal(inl.status, 303);
    assert.equal(inl.headers.get('location'), '/beheer/overzicht?m=ingelezen');
    /* het menu toont nu ook Overzicht */
    assert.match(s, /<a href="\/beheer\/overzicht" aria-current="page">Overzicht<\/a>/);
  } finally {
    await t.stop();
  }
});
