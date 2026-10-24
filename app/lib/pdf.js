'use strict';
/*
 * pdf.js — een kleine PDF-schrijver, voor de kaart die een partner afgeeft.
 *
 * Alleen wat de kaart nodig heeft: één pagina met tekst in Helvetica en
 * Helvetica-Bold, lijnen, vlakken en een QR-code als vlakjes (vector, dus
 * scherp op elke printer). Helvetica zit in elke PDF-lezer; er hoeft geen
 * lettertype in het bestand.
 *
 * Tekst gaat als WinAnsi (Windows-1252): é, ë, ’ en € werken; een teken dat
 * daar niet in zit, wordt een vraagteken. De letterbreedtes komen uit de
 * Adobe-metriek (AFM) van Helvetica, om te centreren en af te breken.
 *
 * Maten in punten (1/72 inch), gemeten vanaf linksboven met y naar beneden;
 * de schrijver rekent om naar de PDF-manier (linksonder, y omhoog).
 *
 *   const d = document({ breedte: 420, hoogte: 595, titel: 'Kaart' });   // A5
 *   d.tekst(210, 60, 'Hallo', { grootte: 20, vet: true, midden: true, kleur: '#15756a' });
 *   const y = d.alinea(40, 100, 340, 'Een langere tekst ...', { grootte: 12 });
 *   d.lijn(40, 80, 380, 80, { kleur: '#cccccc' });
 *   d.qr(qr.maak(adres, 'M'), 130, 200, 160);
 *   fs.writeFileSync('kaart.pdf', d.bytes());
 */

/* breedtes van de tekens 32 t/m 126, per 1000 eenheden van de lettergrootte */
const NORMAAL = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
  556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
  278, 278, 584, 584, 584, 556, 1015,
  667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
  278, 278, 278, 469, 556, 333,
  556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500,
  334, 260, 334, 584
];
const VET = [
  278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
  556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
  333, 333, 584, 584, 584, 611, 975,
  722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
  333, 278, 333, 584, 556, 333,
  556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500,
  389, 280, 389, 584
];
/* WinAnsi 0x80-0x9f: andere tekens dan in Unicode */
const HOOG = {
  '€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88, '‰': 0x89, 'Š': 0x8a, '‹': 0x8b, 'Œ': 0x8c, 'Ž': 0x8e,
  '‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97, '˜': 0x98, '™': 0x99, 'š': 0x9a, '›': 0x9b, 'œ': 0x9c, 'ž': 0x9e, 'Ÿ': 0x9f
};
/* [normaal, vet] voor de tekens buiten 32-126 die we gebruiken */
const EXTRA = {
  0x80: [556, 556], 0x85: [1000, 1000], 0x91: [222, 278], 0x92: [222, 278], 0x93: [333, 500], 0x94: [333, 500], 0x95: [350, 350],
  0x96: [556, 556], 0x97: [1000, 1000], 0xa0: [278, 278], 0xa9: [737, 737], 0xb0: [400, 400], 0xb7: [278, 278]
};

function winAnsi(teken) {
  const c = teken.codePointAt(0);
  if ((c >= 0x20 && c <= 0x7e) || (c >= 0xa0 && c <= 0xff)) return c;
  return HOOG[teken] || 0x3f;
}

function tekenBreedte(b, vet) {
  if (b >= 32 && b <= 126) return (vet ? VET : NORMAAL)[b - 32];
  if (EXTRA[b]) return EXTRA[b][vet ? 1 : 0];
  /* letters met een accent: zo breed als de letter zelf (í, ï: 278) */
  const basis = String.fromCharCode(b).normalize('NFD').charCodeAt(0);
  if (basis === 0x69) return 278;
  if (basis >= 32 && basis <= 126) return (vet ? VET : NORMAAL)[basis - 32];
  return 556;
}

/* breedte van een tekst in punten */
function breedte(tekst, grootte, vet) {
  let som = 0;
  for (const t of String(tekst)) som += tekenBreedte(winAnsi(t), vet);
  return (som * grootte) / 1000;
}

/* een PDF-string: ( ) en \ ontsnapt, alles buiten ASCII als octaal */
function pdfTekst(s) {
  let uit = '(';
  for (const t of String(s)) {
    const b = winAnsi(t);
    if (b === 0x28 || b === 0x29 || b === 0x5c) uit += '\\' + String.fromCharCode(b);
    else if (b > 0x7e) uit += '\\' + b.toString(8).padStart(3, '0');
    else uit += String.fromCharCode(b);
  }
  return uit + ')';
}

const getal = (x) => String(Math.round(x * 100) / 100);
function kleur(hex) {
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || '#000000');
  return [m[1], m[2], m[3]].map((x) => getal(parseInt(x, 16) / 255)).join(' ');
}

/* regels van hoogstens maxBreedte; een woord dat zelf te lang is, wordt afgekapt op tekens */
function afbreken(tekst, maxBreedte, grootte, vet) {
  const regels = [];
  let regel = '';
  for (const woord of String(tekst).split(/\s+/).filter(Boolean)) {
    const proef = regel ? regel + ' ' + woord : woord;
    if (breedte(proef, grootte, vet) <= maxBreedte) { regel = proef; continue; }
    if (regel) regels.push(regel);
    regel = '';
    let stuk = '';
    for (const t of woord) {
      if (breedte(stuk + t, grootte, vet) > maxBreedte && stuk) { regels.push(stuk); stuk = ''; }
      stuk += t;
    }
    regel = stuk;
  }
  if (regel) regels.push(regel);
  return regels;
}

function document(o) {
  const B = o.breedte || 420;
  const H = o.hoogte || 595;
  const inhoud = [];

  const d = {
    tekst(x, y, tekst, opties) {
      const p = opties || {};
      const grootte = p.grootte || 12;
      const xx = p.midden ? x - breedte(tekst, grootte, p.vet) / 2 : p.rechts ? x - breedte(tekst, grootte, p.vet) : x;
      inhoud.push('BT /' + (p.vet ? 'F2' : 'F1') + ' ' + getal(grootte) + ' Tf ' + kleur(p.kleur) + ' rg ' + getal(xx) + ' ' + getal(H - y) + ' Td ' + pdfTekst(tekst) + ' Tj ET');
    },
    /* tekst over meer regels; geeft de y van de regel daarna terug */
    alinea(x, y, maxBreedte, tekst, opties) {
      const p = opties || {};
      const grootte = p.grootte || 12;
      const regelHoogte = p.regelHoogte || grootte * 1.35;
      let yy = y;
      for (const r of afbreken(tekst, maxBreedte, grootte, p.vet)) {
        d.tekst(p.midden ? x + maxBreedte / 2 : x, yy, r, Object.assign({}, p, { grootte }));
        yy += regelHoogte;
      }
      return yy;
    },
    lijn(x1, y1, x2, y2, opties) {
      const p = opties || {};
      inhoud.push(kleur(p.kleur) + ' RG ' + getal(p.dikte || 1) + ' w ' + getal(x1) + ' ' + getal(H - y1) + ' m ' + getal(x2) + ' ' + getal(H - y2) + ' l S');
    },
    vlak(x, y, b, h, kleurHex) {
      inhoud.push(kleur(kleurHex) + ' rg ' + getal(x) + ' ' + getal(H - y - h) + ' ' + getal(b) + ' ' + getal(h) + ' re f');
    },
    /* QR-code van linksboven (x, y), maat x maat punten, zonder witte rand (die moet er
     * omheen vrij blijven). Per rij één vlak per donker stuk; elk vlak loopt 0,05 pt
     * door naar beneden, zodat er in geen enkele lezer een haarlijn tussen de rijen valt. */
    qr(q, x, y, maat) {
      const s = maat / q.grootte;
      const vlakken = [];
      for (let r = 0; r < q.grootte; r++) {
        for (let c = 0; c < q.grootte; c++) {
          if (!q.donker(c, r)) continue;
          let l = 1;
          while (c + l < q.grootte && q.donker(c + l, r)) l++;
          vlakken.push(getal(x + c * s) + ' ' + getal(H - y - (r + 1) * s - 0.05) + ' ' + getal(l * s) + ' ' + getal(s + 0.05) + ' re');
          c += l - 1;
        }
      }
      inhoud.push('0 0 0 rg\n' + vlakken.join('\n') + '\nf');
    },
    bytes() {
      const stroom = inhoud.join('\n');
      const t = o.datum || new Date();
      const datum = t.toISOString().replace(/[-:T]/g, '').slice(0, 14);
      const objecten = [
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + getal(B) + ' ' + getal(H) + '] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
        '<< /Length ' + Buffer.byteLength(stroom, 'latin1') + ' >>\nstream\n' + stroom + '\nendstream',
        '<< /Title ' + pdfTekst(o.titel || '') + ' /Producer (belastinghulpzaanstad.nl) /CreationDate (D:' + datum + 'Z) >>'
      ];
      let uit = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n';
      const plekken = [];
      objecten.forEach((obj, i) => {
        plekken.push(Buffer.byteLength(uit, 'latin1'));
        uit += (i + 1) + ' 0 obj\n' + obj + '\nendobj\n';
      });
      const xref = Buffer.byteLength(uit, 'latin1');
      uit += 'xref\n0 ' + (objecten.length + 1) + '\n0000000000 65535 f \n' + plekken.map((p) => String(p).padStart(10, '0') + ' 00000 n \n').join('');
      uit += 'trailer\n<< /Size ' + (objecten.length + 1) + ' /Root 1 0 R /Info 7 0 R >>\nstartxref\n' + xref + '\n%%EOF\n';
      return Buffer.from(uit, 'latin1');
    }
  };
  return d;
}

module.exports = { document, breedte, afbreken, pdfTekst, winAnsi };
