'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { bouw, maakMailer, zonderAdressen } = require('../lib/mail');
const smtp = require('../lib/smtp');
const dbm = require('../lib/db');
const nep = require('./nep-smtp');

test('bericht opbouwen: koppen en inhoud in UTF-8', () => {
  const data = bouw({
    van: 'info@belastinghulpzaanstad.nl', vanNaam: 'Belastinghulp Zaanstad', aan: 'a@b.nl',
    onderwerp: 'Nieuwe aanvraag: één test met een heel lang onderwerp dat over meerdere regels moet worden verdeeld',
    tekst: 'Regel één\n.begint met een punt', html: '<p>één</p>', headers: { 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' },
    datum: new Date('2026-11-02T19:00:00Z')
  });
  assert.match(data, /^From: "Belastinghulp Zaanstad" <info@belastinghulpzaanstad\.nl>\r\n/);
  assert.match(data, /\r\nDate: Mon, 2 Nov 2026 19:00:00 \+0000\r\n/);
  assert.match(data, /\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n/);
  assert.equal(nep.onderwerp(data), 'Nieuwe aanvraag: één test met een heel lang onderwerp dat over meerdere regels moet worden verdeeld');
  for (const r of data.split('\r\n')) assert.ok(r.length <= 998, 'regel te lang');
  for (const r of data.split('\r\n\r\n')[0].split('\r\n')) assert.ok(r.length <= 200, 'kopregel te lang: ' + r);
  assert.equal(nep.tekst(data), 'Regel één\n.begint met een punt');
  assert.equal(nep.html(data), '<p>één</p>');
});

test('smtp: aflevering met AUTH PLAIN en punt-verdubbeling', async () => {
  const s = await nep.startNepSmtp();
  try {
    const data = bouw({ van: 'info@belastinghulpzaanstad.nl', aan: 'x@y.nl', onderwerp: 'Hallo', tekst: 'a\n.\nb' });
    await smtp.verstuur({ host: '127.0.0.1', poort: s.poort, beveiliging: 'geen', gebruiker: 'gebr', wachtwoord: 'ww' },
      { van: 'info@belastinghulpzaanstad.nl', aan: 'x@y.nl', data: '.eerste regel\r\n' + data });
    assert.equal(s.berichten.length, 1);
    assert.equal(s.berichten[0].auth, '\0gebr\0ww');
    assert.equal(s.berichten[0].aan, 'x@y.nl');
    assert.match(s.berichten[0].data, /^\.eerste regel\r\n/);
  } finally {
    await s.sluit();
  }
});

test('smtp: onversleuteld naar buiten mag niet', async () => {
  await assert.rejects(smtp.verstuur({ host: 'smtp.voorbeeld.nl', poort: 25, beveiliging: 'geen' }, { van: 'a@b.nl', aan: 'c@d.nl', data: 'x' }), /alleen naar deze machine/);
});

test('wachtrij: opnieuw proberen, opgeven bij 550, verzonden = weg', async () => {
  const map = fs.mkdtempSync(path.join(os.tmpdir(), 'bhz-mail-'));
  const db = dbm.open(path.join(map, 't.db'));
  let nu = new Date('2026-11-02T19:00:00Z');
  const klok = () => new Date(nu.getTime());
  const logs = [];
  const env = { SMTP_HOST: '127.0.0.1', SMTP_POORT: '1', SMTP_BEVEILIGING: 'geen', MAIL_VAN: 'info@belastinghulpzaanstad.nl' };
  const m = maakMailer({ db, klok, env, log: (n, t) => logs.push(t) });
  try {
    /* poort 1: geen server, dus mislukt */
    m.inWachtrij({ soort: 'melding', aan: 'stan@voorbeeld.nl', onderwerp: 'x', tekst: 'y' });
    await m.verwerk();
    let r = db.prepare('SELECT * FROM uitgaand').get();
    assert.equal(r.pogingen, 1);
    assert.equal(r.volgende_poging, '2026-11-02T19:01:00.000Z');
    assert.ok(!logs.join('\n').includes('stan@voorbeeld.nl'), 'adres in de log');

    const s = await nep.startNepSmtp({ weiger: ['weg@voorbeeld.nl'] });
    env.SMTP_POORT = String(s.poort);
    await m.verwerk();
    assert.equal(s.berichten.length, 0, 'nog niet aan de beurt');
    nu = new Date('2026-11-02T19:02:00Z');
    m.inWachtrij({ soort: 'herinnering', aan: 'weg@voorbeeld.nl', onderwerp: 'x', tekst: 'y' });
    await m.verwerk();
    await m.verwerk();
    assert.equal(s.berichten.length, 1);
    assert.equal(db.prepare('SELECT COUNT(*) n FROM uitgaand WHERE gestopt IS NULL').get().n, 0);
    r = db.prepare('SELECT * FROM uitgaand').get();
    assert.ok(r.gestopt, '550 = opgeven');
    assert.equal(r.fout.includes('weg@voorbeeld.nl'), false);
    await s.sluit();
  } finally {
    db.close();
    fs.rmSync(map, { recursive: true, force: true });
  }
});

test('vangnet: via de Brevo-API (HTTPS) in plaats van SMTP', async () => {
  const http = require('http');
  const ontvangen = [];
  let antwoord = 201;
  const api = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      ontvangen.push({ sleutel: req.headers['api-key'], pad: req.url, json: JSON.parse(body) });
      res.writeHead(antwoord, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  });
  await new Promise((r) => api.listen(0, '127.0.0.1', r));
  const map = fs.mkdtempSync(path.join(os.tmpdir(), 'bhz-api-'));
  const db = dbm.open(path.join(map, 't.db'));
  const env = {
    MAIL_VIA: 'brevo-api', BREVO_API_SLEUTEL: 'xkeysib-test', MAIL_VAN: 'info@belastinghulpzaanstad.nl',
    BREVO_API_URL: 'http://127.0.0.1:' + api.address().port + '/v3/smtp/email'
  };
  const m = maakMailer({ db, klok: () => new Date('2026-11-02T19:00:00Z'), env, log: () => {} });
  try {
    assert.equal(m.ingesteld(), true);
    m.inWachtrij({ soort: 'herinnering', aan: 'a@b.nl', onderwerp: 'Één onderwerp', tekst: 'tekst', html: '<p>html</p>', headers: { 'List-Unsubscribe': '<https://x/af?t=1>' } });
    await m.verwerk();
    assert.equal(ontvangen.length, 1);
    const j = ontvangen[0].json;
    assert.equal(ontvangen[0].sleutel, 'xkeysib-test');
    assert.equal(ontvangen[0].pad, '/v3/smtp/email');
    /* geen toestemming voor volgen: Brevo telt opens en kliks dan alleen anoniem */
    assert.deepEqual(j.to, [{ email: 'a@b.nl', contactPixelTrackingConsent: false }]);
    assert.equal(j.sender.email, 'info@belastinghulpzaanstad.nl');
    assert.equal(j.subject, 'Één onderwerp');
    assert.equal(j.htmlContent, '<p>html</p>');
    assert.equal(j.headers['List-Unsubscribe'], '<https://x/af?t=1>');
    assert.equal(db.prepare('SELECT COUNT(*) n FROM uitgaand').get().n, 0);

    antwoord = 401;
    m.inWachtrij({ soort: 'signaal', aan: 'stan@voorbeeld.nl', onderwerp: 'x', tekst: 'platte <tekst>' });
    await m.verwerk();
    const r = db.prepare('SELECT * FROM uitgaand').get();
    assert.equal(r.pogingen, 1);
    assert.equal(r.gestopt, null, 'verkeerde sleutel: later opnieuw, na het aanpassen van app.env');
    assert.match(ontvangen[1].json.htmlContent, /platte &lt;tekst&gt;/);
  } finally {
    db.close();
    api.close();
    fs.rmSync(map, { recursive: true, force: true });
  }
});

test('adressen uit foutmeldingen', () => {
  assert.equal(zonderAdressen('550 5.1.1 <jan@ziggo.nl>: Recipient rejected'), '550 5.1.1 <[adres]>: Recipient rejected');
});
