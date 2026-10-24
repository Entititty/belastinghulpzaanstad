'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const v = require('../lib/valideer');

test('telefoon: Nederlandse en buitenlandse schrijfwijzen', () => {
  const goed = [
    ['06 12345678', '+31612345678', 'mobiel', '06 12 34 56 78'],
    ['06-12 34 56 78', '+31612345678', 'mobiel'],
    ['06.12.34.56.78', '+31612345678', 'mobiel'],
    ['+31 6 1234 5678', '+31612345678', 'mobiel'],
    ['+31 (0)6 12345678', '+31612345678', 'mobiel'],
    ['+310612345678', '+31612345678', 'mobiel'],
    ['0031612345678', '+31612345678', 'mobiel'],
    ['31612345678', '+31612345678', 'mobiel'],
    ['612345678', '+31612345678', 'mobiel'],
    ['0687654321', '+31687654321', 'mobiel'],
    ['075 123 4567', '+31751234567', 'vast', '075 123 4567'],
    ['(075) 1234567', '+31751234567', 'vast'],
    ['0299-123456', '+31299123456', 'vast', '0299 12 34 56'],
    ['020 123 45 67', '+31201234567', 'vast'],
    ['085 123 4567', '+31851234567', 'vast'],
    ['+44 7911 123456', '+447911123456', 'buitenland'],
    ['0049 151 23456789', '+4915123456789', 'buitenland']
  ];
  for (const [invoer, waarde, soort, weergave] of goed) {
    const r = v.telefoon(invoer);
    assert.equal(r.waarde, waarde, invoer);
    assert.equal(r.soort, soort, invoer);
    if (weergave) assert.equal(r.weergave, weergave, invoer);
  }
  const fout = ['', '   ', '1234', '06123', '0612345678901', '0800 1234', '0900 1234567', '0900-1234', '0661234567',
    '0671234567', '0612 34 56 7a', '+31 6 123', '++31612345678', '06+12345678', '0970 12345678', '0691234567', 'bel mij'];
  for (const invoer of fout) assert.ok(v.telefoon(invoer).fout, 'zou fout moeten zijn: ' + JSON.stringify(invoer));
});

test('telefoonWeergave van een opgeslagen nummer', () => {
  assert.equal(v.telefoonWeergave('+31612345678'), '06 12 34 56 78');
  assert.equal(v.telefoonWeergave('+31751234567'), '075 123 4567');
  assert.equal(v.telefoonWeergave('+447911123456'), '+447911123456');
});

test('e-mail', () => {
  assert.equal(v.email(' Jan.de.Vries@Ziggo.NL ').waarde, 'jan.de.vries@ziggo.nl');
  assert.equal(v.email('a+b@mail.co.uk').waarde, 'a+b@mail.co.uk');
  assert.ok(v.email('').leeg);
  for (const x of ['jan', 'jan@', '@ziggo.nl', 'jan@ziggo', 'jan@@ziggo.nl', 'jan de vries@ziggo.nl', 'jan@zig go.nl', '<jan@x.nl>']) {
    assert.ok(v.email(x).fout, x);
  }
});

test('naam: leeg, te lang, spam', () => {
  assert.equal(v.naam('  Jan   de  Vries ').waarde, 'Jan de Vries');
  assert.equal(v.naam('Zoë Ünal-Ağaoğlu').waarde, 'Zoë Ünal-Ağaoğlu');
  assert.equal(v.naam('J').fout, 'leeg');
  assert.equal(v.naam('x'.repeat(81)).fout, 'te-lang');
  assert.equal(v.naam('12345').fout, 'ongeldig');
  assert.ok(v.naam('Koop nu http://spam.example').spam);
});

test('opmerking: lengte en links', () => {
  assert.equal(v.tekst('Graag na 19:00\r\nbellen', 1000).waarde, 'Graag na 19:00\nbellen');
  assert.equal(v.tekst('x'.repeat(1001), 1000).fout, 'te-lang');
  assert.ok(!v.tekst('zie www.belastingdienst.nl', 1000).spam);
  assert.ok(v.tekst('http://a.example en http://b.example', 1000).spam);
});

test('herkomst: pad, domein, utm, ref', () => {
  assert.equal(v.pad('/Senioren/?utm_source=flyer'), '/senioren/');
  assert.equal(v.pad('https://belastinghulpzaanstad.nl/contact/#terugbellen'), '/contact/');
  assert.equal(v.pad('javascript:alert(1)'), '');
  assert.equal(v.pad('/<script>/'), '');
  assert.equal(v.domein('www.google.nl'), 'google.nl');
  assert.equal(v.domein('evil"<>'), '');
  assert.equal(v.campagne('Rosmolenwijk'), 'rosmolenwijk');
  assert.equal(v.campagne('<b>'), '');
  assert.equal(v.refCode('Jansen-Makelaardij'), 'jansen-makelaardij');
  assert.equal(v.refCode('jansen makelaardij'), '');
});

test('berekening: JSON, oude platte tekst en troep', () => {
  const j = v.berekening(JSON.stringify({ invoer: [['WOZ-waarde', '305000']], uitkomst: [['Per maand', '€ 339']] }));
  assert.deepEqual(j, { invoer: [['WOZ-waarde', '305000']], uitkomst: [['Per maand', '€ 339']] });
  assert.deepEqual(v.berekening('Rekentool: x\nWOZ: 1'), { tekst: 'Rekentool: x\nWOZ: 1' });
  assert.equal(v.berekening(''), null);
  assert.equal(v.berekening('x'.repeat(7000)), null);
  const veel = v.berekening(JSON.stringify({ invoer: Array.from({ length: 50 }, (_, i) => ['v' + i, String(i)]) }));
  assert.equal(veel.invoer.length, 30);
});
