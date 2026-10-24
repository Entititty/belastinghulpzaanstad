'use strict';
/*
 * zip.js — een zip-bestand schrijven en lezen, alleen met zlib uit Node.
 * Nodig voor .xlsx (dat is een zip met XML erin). Geen versleuteling, geen
 * zip64: de bestanden hier zijn klein.
 */
const zlib = require('zlib');

const CRC = new Int32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC[n] = c;
}
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

/* datum en tijd in MS-DOS-formaat */
function dosTijd(d) {
  return {
    tijd: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2),
    datum: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()
  };
}

/* bestanden: [{ naam, data }] met data als Buffer of tekst */
function maakZip(bestanden, datum) {
  const { tijd, datum: dag } = dosTijd(datum || new Date());
  const delen = [];
  const centraal = [];
  let positie = 0;
  for (const b of bestanden) {
    const naam = Buffer.from(b.naam, 'utf8');
    const data = Buffer.isBuffer(b.data) ? b.data : Buffer.from(String(b.data), 'utf8');
    const ingepakt = zlib.deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const lokaal = Buffer.alloc(30);
    lokaal.writeUInt32LE(0x04034b50, 0);
    lokaal.writeUInt16LE(20, 4);
    lokaal.writeUInt16LE(0x0800, 6);
    lokaal.writeUInt16LE(8, 8);
    lokaal.writeUInt16LE(tijd, 10);
    lokaal.writeUInt16LE(dag, 12);
    lokaal.writeUInt32LE(crc, 14);
    lokaal.writeUInt32LE(ingepakt.length, 18);
    lokaal.writeUInt32LE(data.length, 22);
    lokaal.writeUInt16LE(naam.length, 26);
    lokaal.writeUInt16LE(0, 28);
    const kop = Buffer.alloc(46);
    kop.writeUInt32LE(0x02014b50, 0);
    kop.writeUInt16LE(20, 4);
    kop.writeUInt16LE(20, 6);
    kop.writeUInt16LE(0x0800, 8);
    kop.writeUInt16LE(8, 10);
    kop.writeUInt16LE(tijd, 12);
    kop.writeUInt16LE(dag, 14);
    kop.writeUInt32LE(crc, 16);
    kop.writeUInt32LE(ingepakt.length, 20);
    kop.writeUInt32LE(data.length, 24);
    kop.writeUInt16LE(naam.length, 28);
    kop.writeUInt32LE(positie, 42);
    delen.push(lokaal, naam, ingepakt);
    centraal.push(kop, naam);
    positie += lokaal.length + naam.length + ingepakt.length;
  }
  const cd = Buffer.concat(centraal);
  const eind = Buffer.alloc(22);
  eind.writeUInt32LE(0x06054b50, 0);
  eind.writeUInt16LE(bestanden.length, 8);
  eind.writeUInt16LE(bestanden.length, 10);
  eind.writeUInt32LE(cd.length, 12);
  eind.writeUInt32LE(positie, 16);
  return Buffer.concat(delen.concat([cd, eind]));
}

/* Lezen, voor de tests: { naam: Buffer } */
function leesZip(buf) {
  const eind = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eind < 0) throw new Error('geen zip');
  const aantal = buf.readUInt16LE(eind + 10);
  let p = buf.readUInt32LE(eind + 16);
  const uit = {};
  for (let i = 0; i < aantal; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('kapotte centrale map');
    const methode = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const nlen = buf.readUInt16LE(p + 28), elen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const lokaal = buf.readUInt32LE(p + 42);
    const naam = buf.slice(p + 46, p + 46 + nlen).toString('utf8');
    const start = lokaal + 30 + buf.readUInt16LE(lokaal + 26) + buf.readUInt16LE(lokaal + 28);
    const ruw = buf.slice(start, start + csize);
    const data = methode === 8 ? zlib.inflateRawSync(ruw) : ruw;
    if (crc32(data) !== crc) throw new Error('crc klopt niet: ' + naam);
    uit[naam] = data;
    p += 46 + nlen + elen + clen;
  }
  return uit;
}

module.exports = { maakZip, leesZip, crc32 };
