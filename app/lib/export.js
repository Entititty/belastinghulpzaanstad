'use strict';
/*
 * export.js — tabellen naar CSV en naar een echt Excel-bestand (.xlsx).
 *
 * CSV: puntkomma als scheidingsteken en een BOM voorop, zodat Excel met
 * Nederlandse instellingen de kolommen en de é's goed toont. Een cel die met
 * = + - of @ begint, krijgt een ' ervoor: anders kan een kwaadwillende naam
 * in een formulier ("=HYPERLINK(...)") in Excel een formule worden.
 *
 * xlsx: tekst als inline strings (worden nooit een formule), getallen als
 * getallen, bedragen in euro's, kopregel vet en vastgezet, met een filter.
 *
 *   tabel = { naam: 'Aanvragen', kolommen: [{ kop, breedte?, soort?: 'getal'|'euro' }], rijen: [[...], ...] }
 */
const { maakZip } = require('./zip');

function csvCel(v) {
  if (v === null || v === undefined) return '';
  let s = typeof v === 'number' ? String(v).replace('.', ',') : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[;"\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function csv(tabel) {
  const regels = [tabel.kolommen.map((k) => csvCel(k.kop)).join(';')];
  for (const r of tabel.rijen) regels.push(r.map(csvCel).join(';'));
  return '\ufeff' + regels.join('\r\n') + '\r\n';
}

/* ---------------- xlsx ---------------- */
function xml(s) {
  return String(s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function kolomLetter(i) {
  let s = '';
  for (let n = i + 1; n > 0; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(65 + ((n - 1) % 26)) + s;
  return s;
}
function bladNaam(s) { return String(s).replace(/[[\]:*?/\\]/g, ' ').slice(0, 31) || 'Blad'; }

function blad(tabel) {
  const cols = tabel.kolommen.map((k, i) => '<col min="' + (i + 1) + '" max="' + (i + 1) + '" width="' + (k.breedte || 16) + '" customWidth="1"/>').join('');
  const rij = (cellen, r, kop) => '<row r="' + r + '">' + cellen.map((v, i) => {
    const ref = kolomLetter(i) + r;
    const soort = kop ? 'tekst' : (tabel.kolommen[i].soort || 'tekst');
    if (v === null || v === undefined || v === '') return '';
    if ((soort === 'getal' || soort === 'euro') && typeof v === 'number' && Number.isFinite(v)) {
      return '<c r="' + ref + '"' + (soort === 'euro' ? ' s="2"' : '') + '><v>' + v + '</v></c>';
    }
    return '<c r="' + ref + '" t="inlineStr"' + (kop ? ' s="1"' : '') + '><is><t xml:space="preserve">' + xml(v) + '</t></is></c>';
  }).join('') + '</row>';
  const laatste = kolomLetter(tabel.kolommen.length - 1) + (tabel.rijen.length + 1);
  return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
    '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>' +
    '<cols>' + cols + '</cols><sheetData>' +
    rij(tabel.kolommen.map((k) => k.kop), 1, true) +
    tabel.rijen.map((r, i) => rij(r, i + 2, false)).join('') +
    '</sheetData><autoFilter ref="A1:' + laatste + '"/></worksheet>';
}

function xlsx(tabellen, datum) {
  const lijst = Array.isArray(tabellen) ? tabellen : [tabellen];
  const bestanden = [
    { naam: '[Content_Types].xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
      '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
      '<Default Extension="xml" ContentType="application/xml"/>' +
      '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
      '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
      lijst.map((_, i) => '<Override PartName="/xl/worksheets/sheet' + (i + 1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>').join('') +
      '</Types>' },
    { naam: '_rels/.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
      '</Relationships>' },
    { naam: 'xl/workbook.xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
      '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' +
      lijst.map((t, i) => '<sheet name="' + xml(bladNaam(t.naam)) + '" sheetId="' + (i + 1) + '" r:id="rId' + (i + 1) + '"/>').join('') +
      '</sheets></workbook>' },
    { naam: 'xl/_rels/workbook.xml.rels', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      lijst.map((_, i) => '<Relationship Id="rId' + (i + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + (i + 1) + '.xml"/>').join('') +
      '<Relationship Id="rId' + (lijst.length + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' +
      '</Relationships>' },
    { naam: 'xl/styles.xml', data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
      '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
      '<numFmts count="1"><numFmt numFmtId="164" formatCode="&quot;€&quot; #,##0.00"/></numFmts>' +
      '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>' +
      '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>' +
      '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
      '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
      '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
      '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>' +
      '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs>' +
      '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
      '</styleSheet>' }
  ];
  lijst.forEach((t, i) => bestanden.push({ naam: 'xl/worksheets/sheet' + (i + 1) + '.xml', data: blad(t) }));
  return maakZip(bestanden, datum);
}

module.exports = { csv, csvCel, xlsx, kolomLetter };
