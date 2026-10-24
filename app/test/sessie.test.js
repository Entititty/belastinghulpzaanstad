'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const s = require('../lib/sessie');

test('TOTP: de testvectoren uit RFC 6238 (SHA-1)', () => {
  const geheim = s.base32(Buffer.from('12345678901234567890'));
  assert.equal(geheim, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  const vectoren = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
    [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];
  for (const [t, code] of vectoren) {
    assert.equal(s.totp(geheim, t * 1000, 8), code, 'T=' + t);
    assert.equal(s.totp(geheim, t * 1000), code.slice(2), 'T=' + t + ', 6 cijfers');
  }
});

test('TOTP: één stap speling, verder niet', () => {
  const geheim = s.nieuwGeheim();
  const t = 1700000000000;
  const code = s.totp(geheim, t);
  assert.equal(s.totpStap(geheim, code, t), Math.floor(t / 30000));
  assert.ok(s.totpStap(geheim, code, t + 30000) >= 0, '30 seconden later nog goed');
  assert.equal(s.totpStap(geheim, code, t + 90000), -1, '90 seconden later niet meer');
  assert.equal(s.totpStap(geheim, '12345', t), -1);
  assert.equal(s.totpStap(geheim, 'abcdef', t), -1);
});

test('base32 heen en terug', () => {
  const b = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255, 7]);
  assert.deepEqual(s.vanBase32(s.base32(b)), b);
});

test('wachtwoord: scrypt met zout', () => {
  const h = s.hashWachtwoord('een lang wachtwoord');
  assert.match(h, /^scrypt\$16384\$8\$1\$/);
  assert.notEqual(h, s.hashWachtwoord('een lang wachtwoord'), 'elk keer een ander zout');
  assert.equal(s.controleerWachtwoord('een lang wachtwoord', h), true);
  assert.equal(s.controleerWachtwoord('een ander wachtwoord', h), false);
  assert.equal(s.controleerWachtwoord('x', 'onzin'), false);
});

test('otpauth-adres voor de app', () => {
  const u = s.otpauthUri('stan', 'JBSWY3DPEHPK3PXP');
  assert.equal(u, 'otpauth://totp/Belastinghulp%20Zaanstad%3Astan?secret=JBSWY3DPEHPK3PXP&issuer=Belastinghulp%20Zaanstad&algorithm=SHA1&digits=6&period=30');
});

test('rem: 5 fout per adres, 20 fout in totaal', () => {
  const r = new s.Rem();
  const t = 1e12;
  for (let i = 0; i < 4; i++) r.fout('a', t);
  assert.equal(r.wacht('a', t), 0);
  r.fout('a', t);
  assert.ok(r.wacht('a', t) > 0, 'na 5 fouten dicht');
  assert.equal(r.wacht('b', t), 0, 'een ander adres mag nog');
  assert.equal(r.wacht('a', t + 16 * 60e3), 0, 'na 15 minuten weer open');
  let alarm = false;
  for (let i = 0; i < 15; i++) alarm = r.fout('ip' + i, t) || alarm;
  assert.equal(alarm, true, 'bij 20 fouten in een uur: alarm');
  assert.ok(r.wacht('nieuw', t) > 0, 'en dan voor iedereen dicht');
});
