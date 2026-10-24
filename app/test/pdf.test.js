'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const pdf = require('../lib/pdf');
const qr = require('../lib/qr');
const { matrixVan, uitPdf } = require('./qr-hulp');

/* de opbouw: elke plek in de xref wijst naar "n 0 obj", startxref naar "xref", /Length klopt.
 * Geeft de inhoud (content stream) terug. */
function opbouw(buf) {
  const s = buf.toString('latin1');
  assert.ok(s.startsWith('%PDF-1.4\n'));
  assert.ok(s.endsWith('%%EOF\n'));
  const startxref = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(s)[1]);
  assert.equal(s.slice(startxref, startxref + 5), 'xref\n');
  const aantal = Number(/^xref\n0 (\d+)\n/.exec(s.slice(startxref))[1]);
  const regels = s.slice(startxref).split('\n').slice(2, 2 + aantal);
  assert.equal(regels[0], '0000000000 65535 f ');
  regels.forEach((r, i) => {
    assert.equal(r.length + 1, 20, 'een xref-regel is 20 bytes');
    if (i) assert.equal(s.slice(Number(r.slice(0, 10))).split('\n')[0], i + ' 0 obj');
  });
  assert.match(s, new RegExp('trailer\\n<< /Size ' + aantal + ' /Root 1 0 R /Info 7 0 R >>'));
  const m = /<< \/Length (\d+) >>\nstream\n/.exec(s);
  const begin = m.index + m[0].length;
  assert.equal(s.slice(begin + Number(m[1]), begin + Number(m[1]) + 10), '\nendstream');
  return s.slice(begin, begin + Number(m[1]));
}

test('tekst: WinAnsi met é, ’ en €, haakjes ontsnapt, breedtes uit de metriek', () => {
  assert.equal(pdf.pdfTekst('Café (€ 5) \\'), '(Caf\\351 \\(\\200 5\\) \\\\)');
  assert.equal(pdf.pdfTekst('’s avonds'), '(\\222s avonds)');
  assert.equal(pdf.pdfTekst('日本'), '(??)');
  assert.equal(pdf.breedte('Hello', 10, false), 22.78);
  assert.equal(pdf.breedte('Hello', 10, true), 24.45);
  assert.equal(pdf.breedte('ï', 10, false), 2.78);
});

test('afbreken op woorden, en een te lang woord op tekens', () => {
  const r = pdf.afbreken('een twee drie vier vijf zes', 60, 12, false);
  assert.ok(r.length > 1);
  assert.equal(r.join(' '), 'een twee drie vier vijf zes');
  for (const regel of r) assert.ok(pdf.breedte(regel, 12, false) <= 60, regel);
  const adres = 'belastinghulpzaanstad.nl/diensten/voorlopige-teruggave/?ref=jansen-makelaardij';
  const lang = pdf.afbreken(adres, 100, 8, false);
  assert.ok(lang.length > 1);
  assert.equal(lang.join(''), adres);
  for (const regel of lang) assert.ok(pdf.breedte(regel, 8, false) <= 100, regel);
});

test('een pagina: opbouw klopt, tekst op de goede plek, de QR-code vlakje voor vlakje', () => {
  const d = pdf.document({ breedte: 420, hoogte: 595, titel: 'Proef (één)', datum: new Date('2026-11-02T19:00:00Z') });
  d.tekst(210, 60, 'Belastinghulp Zaanstad', { grootte: 24, vet: true, midden: true, kleur: '#15756a' });
  const y = d.alinea(40, 100, 340, 'Wij doen uw belastingaangifte bij u thuis in Zaanstad en omgeving, ook ’s avonds en in het weekend.', { grootte: 13, midden: true });
  assert.ok(y > 100 + 13 * 1.35, 'twee regels');
  d.lijn(40, 80, 380, 80, { kleur: '#d9d4cc' });
  d.vlak(40, 90, 10, 10, '#000000');
  const q = qr.maak('https://belastinghulpzaanstad.nl/senioren/?ref=test', 'M');
  d.qr(q, 125, 200, 170);
  const bytes = d.bytes();
  const stroom = opbouw(bytes);
  const x = 210 - pdf.breedte('Belastinghulp Zaanstad', 24, true) / 2;
  assert.ok(stroom.includes('BT /F2 24 Tf 0.08 0.46 0.42 rg ' + Math.round(x * 100) / 100 + ' 535 Td (Belastinghulp Zaanstad) Tj ET'));
  assert.ok(stroom.includes(' \\222s avonds'), 'de ’ als WinAnsi');
  assert.ok(stroom.includes('0.85 0.83 0.8 RG 1 w 40 515 m 380 515 l S'));
  assert.ok(stroom.includes('0 0 0 rg 40 495 10 10 re f'));
  assert.deepEqual(uitPdf(stroom, q.grootte), matrixVan(q));
  const s = bytes.toString('latin1');
  assert.match(s, /\/Title \(Proef \\\(\\351\\351n\\\)\)/);
  assert.match(s, /\/CreationDate \(D:20261102190000Z\)/);
  assert.match(s, /\/BaseFont \/Helvetica \/Encoding \/WinAnsiEncoding/);
});
