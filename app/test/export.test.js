'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { csv, xlsx, kolomLetter } = require('../lib/export');
const { leesZip, crc32 } = require('../lib/zip');

const TABEL = {
  naam: 'Aanvragen',
  kolommen: [{ kop: 'Naam' }, { kop: 'Telefoon' }, { kop: 'Omzet', soort: 'euro' }, { kop: 'Opmerking' }],
  rijen: [
    ['Zoë de Vries', '06 12 34 56 78', 89, 'Graag "na" 19:00; dank'],
    ['=HYPERLINK("http://kwaad.example")', '+447911123456', null, 'regel 1\nregel 2'],
    ['@SUM(1)', '-1', 59.5, '<script>&']
  ]
};

test('CSV: puntkomma, BOM, aanhalingstekens en geen formules', () => {
  const s = csv(TABEL);
  assert.ok(s.startsWith('﻿Naam;Telefoon;Omzet;Opmerking\r\n'));
  const r = s.slice(1).split('\r\n');
  assert.equal(r[1], 'Zoë de Vries;06 12 34 56 78;89;"Graag ""na"" 19:00; dank"');
  assert.equal(r[2], '"\'=HYPERLINK(""http://kwaad.example"")";\'+447911123456;;"regel 1\nregel 2"');
  assert.equal(r[3], "'@SUM(1);'-1;59,5;<script>&");
});

test('zip: crc32 en terugleesbaar', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
});

test('xlsx: geldige zip met de verwachte onderdelen, tekst nooit als formule', () => {
  const buf = xlsx([TABEL, { naam: 'Tweede: blad?', kolommen: [{ kop: 'A' }], rijen: [['x']] }], new Date(2026, 10, 2, 20, 0, 0));
  assert.equal(buf.readUInt32LE(0), 0x04034b50);
  const z = leesZip(buf);
  for (const n of ['[Content_Types].xml', '_rels/.rels', 'xl/workbook.xml', 'xl/_rels/workbook.xml.rels', 'xl/styles.xml', 'xl/worksheets/sheet1.xml', 'xl/worksheets/sheet2.xml']) {
    assert.ok(z[n], 'ontbreekt: ' + n);
  }
  const blad = z['xl/worksheets/sheet1.xml'].toString('utf8');
  assert.match(blad, /<c r="A1" t="inlineStr" s="1"><is><t xml:space="preserve">Naam<\/t><\/is><\/c>/);
  assert.match(blad, /<c r="C2" s="2"><v>89<\/v><\/c>/);
  assert.match(blad, /<t xml:space="preserve">=HYPERLINK\(&quot;http:\/\/kwaad\.example&quot;\)<\/t>/);
  assert.match(blad, /&lt;script&gt;&amp;/);
  assert.ok(!/<f>/.test(blad), 'geen formules');
  assert.match(blad, /<autoFilter ref="A1:D4"\/>/);
  assert.match(z['xl/workbook.xml'].toString(), /name="Tweede  blad "/);
  /* elk XML-deel begint netjes en heeft gesloten tags (grove controle) */
  for (const [n, d] of Object.entries(z)) {
    const s = d.toString('utf8');
    assert.ok(s.startsWith('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'), n);
    const open = (s.match(/<[a-zA-Z][^>]*>/g) || []).filter((t) => !t.endsWith('/>')).length;
    const dicht = (s.match(/<\/[a-zA-Z]/g) || []).length;
    assert.equal(open, dicht, 'tags in ' + n);
  }
});

test('kolomletters', () => {
  assert.deepEqual([0, 25, 26, 27, 51, 52, 701, 702].map(kolomLetter), ['A', 'Z', 'AA', 'AB', 'AZ', 'BA', 'ZZ', 'AAA']);
});
