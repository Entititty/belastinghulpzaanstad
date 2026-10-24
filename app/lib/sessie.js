'use strict';
/*
 * sessie.js — inloggen op /beheer.
 *
 * Drie dingen tegelijk: gebruikersnaam, wachtwoord en een 6-cijferige code
 * uit een authenticator-app (TOTP, RFC 6238; bijvoorbeeld Google
 * Authenticator of Microsoft Authenticator). Een gestolen wachtwoord alleen
 * is dus niet genoeg.
 *
 * - Wachtwoord: scrypt met een eigen zout per gebruiker.
 * - Code: 30 seconden geldig, één stap speling naar voren en achteren voor
 *   een klok die iets afwijkt, en elke code maar één keer bruikbaar.
 * - Sessie: een willekeurig token in een cookie (__Host-, Secure, HttpOnly,
 *   SameSite=Strict); in de database staat alleen de SHA-256 ervan.
 * - Elke POST in /beheer heeft een CSRF-token uit de sessie bij zich.
 * - Na 5 foute pogingen per IP-adres in 15 minuten: 15 minuten dicht. Na 20
 *   foute pogingen in een uur, van welk adres ook: alles 15 minuten dicht en
 *   een mail aan Stan.
 */
const crypto = require('crypto');

/* ---------------- wachtwoord ---------------- */
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function hashWachtwoord(wachtwoord) {
  const zout = crypto.randomBytes(16);
  const h = crypto.scryptSync(String(wachtwoord), zout, 64, SCRYPT);
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, zout.toString('base64'), h.toString('base64')].join('$');
}

function controleerWachtwoord(wachtwoord, opgeslagen) {
  const d = String(opgeslagen || '').split('$');
  if (d.length !== 6 || d[0] !== 'scrypt') return false;
  const verwacht = Buffer.from(d[5], 'base64');
  const h = crypto.scryptSync(String(wachtwoord), Buffer.from(d[4], 'base64'), verwacht.length,
    { N: Number(d[1]), r: Number(d[2]), p: Number(d[3]), maxmem: SCRYPT.maxmem });
  return crypto.timingSafeEqual(h, verwacht);
}

/* ---------------- TOTP (RFC 6238, SHA-1, 6 cijfers, 30 seconden) ---------------- */
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(buf) {
  let bits = 0, waarde = 0, uit = '';
  for (const b of buf) {
    waarde = (waarde << 8) | b;
    bits += 8;
    while (bits >= 5) { uit += BASE32[(waarde >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) uit += BASE32[(waarde << (5 - bits)) & 31];
  return uit;
}
function vanBase32(tekst) {
  const s = String(tekst).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, waarde = 0;
  const uit = [];
  for (const c of s) {
    const i = BASE32.indexOf(c);
    if (i < 0) throw new Error('geen base32');
    waarde = (waarde << 5) | i;
    bits += 5;
    if (bits >= 8) { uit.push((waarde >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(uit);
}

function nieuwGeheim() { return base32(crypto.randomBytes(20)); }

function hotp(sleutel, teller, cijfers) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(teller));
  const h = crypto.createHmac('sha1', sleutel).update(b).digest();
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(code % 10 ** (cijfers || 6)).padStart(cijfers || 6, '0');
}

function totp(geheim, tijdMs, cijfers) {
  return hotp(vanBase32(geheim), Math.floor(tijdMs / 30000), cijfers);
}

/* De stap die bij deze code hoort (binnen één stap speling), of -1 */
function totpStap(geheim, code, tijdMs) {
  const c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return -1;
  const sleutel = vanBase32(geheim);
  const nu = Math.floor(tijdMs / 30000);
  for (const d of [0, -1, 1]) {
    const verwacht = hotp(sleutel, nu + d);
    if (crypto.timingSafeEqual(Buffer.from(verwacht), Buffer.from(c))) return nu + d;
  }
  return -1;
}

function otpauthUri(naam, geheim) {
  const uitgever = 'Belastinghulp Zaanstad';
  return 'otpauth://totp/' + encodeURIComponent(uitgever + ':' + naam) + '?secret=' + geheim +
    '&issuer=' + encodeURIComponent(uitgever) + '&algorithm=SHA1&digits=6&period=30';
}

/* ---------------- gebruikers ---------------- */
function maakGebruiker(db, klok, naam, wachtwoord) {
  if (!/^[a-z0-9._-]{2,40}$/i.test(naam)) throw new Error('gebruikersnaam: 2-40 letters, cijfers, punt, streep');
  if (String(wachtwoord).length < 12) throw new Error('het wachtwoord moet minstens 12 tekens hebben');
  const geheim = nieuwGeheim();
  const bestaand = db.prepare('SELECT id FROM gebruikers WHERE naam = ?').get(naam);
  if (bestaand) {
    db.prepare('UPDATE gebruikers SET wachtwoord = ?, totp_geheim = ?, laatste_code = NULL WHERE id = ?')
      .run(hashWachtwoord(wachtwoord), geheim, bestaand.id);
    db.prepare('DELETE FROM sessies WHERE gebruiker_id = ?').run(bestaand.id);
  } else {
    db.prepare('INSERT INTO gebruikers (naam, wachtwoord, totp_geheim, aangemaakt) VALUES (?, ?, ?, ?)')
      .run(naam, hashWachtwoord(wachtwoord), geheim, klok().toISOString());
  }
  return geheim;
}

/* ---------------- sessies ---------------- */
const COOKIE = '__Host-bhz';

function sha(t) { return crypto.createHash('sha256').update(String(t)).digest('hex'); }

function maakSessie(db, klok, gebruikerId, dagen) {
  const token = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  const nu = klok();
  const verloopt = new Date(nu.getTime() + dagen * 864e5);
  db.prepare('INSERT INTO sessies (token_hash, gebruiker_id, csrf, aangemaakt, verloopt) VALUES (?, ?, ?, ?, ?)')
    .run(sha(token), gebruikerId, csrf, nu.toISOString(), verloopt.toISOString());
  return { token, csrf, verloopt };
}

function zoekSessie(db, klok, token) {
  if (!token || typeof token !== 'string' || token.length > 100) return null;
  const s = db.prepare(`SELECT s.token_hash, s.csrf, s.verloopt, g.id AS gebruiker_id, g.naam FROM sessies s
    JOIN gebruikers g ON g.id = s.gebruiker_id WHERE s.token_hash = ?`).get(sha(token));
  if (!s || s.verloopt < klok().toISOString()) return null;
  return s;
}

function stopSessie(db, token) {
  if (token) db.prepare('DELETE FROM sessies WHERE token_hash = ?').run(sha(token));
}

function cookieKop(token, verloopt) {
  if (!token) return COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0';
  const sec = Math.max(0, Math.floor((verloopt.getTime() - Date.now()) / 1000));
  return COOKIE + '=' + token + '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=' + sec;
}

function csrfOk(sessie, waarde) {
  if (!sessie || typeof waarde !== 'string' || waarde.length !== sessie.csrf.length) return false;
  return crypto.timingSafeEqual(Buffer.from(waarde), Buffer.from(sessie.csrf));
}

/* ---------------- rem op inlogpogingen ---------------- */
class Rem {
  constructor() { this.perIp = new Map(); this.alle = []; this.dichtTot = 0; }
  /* 0 als het mag, anders het aantal seconden wachten */
  wacht(ip, nu) {
    if (this.dichtTot > nu) return Math.ceil((this.dichtTot - nu) / 1000);
    const x = (this.perIp.get(ip) || []).filter((t) => nu - t < 15 * 60e3);
    if (x.length >= 5) return Math.ceil((x[0] + 15 * 60e3 - nu) / 1000);
    return 0;
  }
  /* geeft true als dit de drempel voor "alles dicht" haalde */
  fout(ip, nu) {
    const x = (this.perIp.get(ip) || []).filter((t) => nu - t < 15 * 60e3);
    x.push(nu);
    this.perIp.set(ip, x);
    this.alle = this.alle.filter((t) => nu - t < 60 * 60e3);
    this.alle.push(nu);
    if (this.perIp.size > 1000) for (const [k, v] of this.perIp) if (!v.some((t) => nu - t < 15 * 60e3)) this.perIp.delete(k);
    if (this.alle.length >= 20 && this.dichtTot <= nu) { this.dichtTot = nu + 15 * 60e3; return true; }
    return false;
  }
  goed(ip) { this.perIp.delete(ip); }
}

module.exports = {
  hashWachtwoord, controleerWachtwoord, base32, vanBase32, nieuwGeheim, hotp, totp, totpStap, otpauthUri,
  maakGebruiker, maakSessie, zoekSessie, stopSessie, cookieKop, csrfOk, Rem, COOKIE
};
