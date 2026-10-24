'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, terugbellen } = require('./hulp');
const nep = require('./nep-smtp');

let t;
test.before(async () => { t = await startApp(); });
test.after(async () => { await t.stop(); });

let ipTeller = 0;
const ip = () => ({ 'X-Real-IP': '198.51.100.' + (++ipTeller) });
const aantal = () => t.db.prepare('SELECT COUNT(*) AS n FROM aanvragen').get().n;

test('geldige aanvraag: opgeslagen met toestemming en herkomst, melding aan Stan', async () => {
  await t.wachtrijLeeg();
  const voor = t.smtp.berichten.length;
  const r = await t.post('/api/aanvraag', terugbellen({
    h_pagina: '/senioren/', h_vorige: '/', h_landing: '/zaandam/', h_verwijzer: 'www.google.nl', h_apparaat: 'mobiel',
    email: 'jan@ziggo.nl', opmerking: 'Graag na 19:00'
  }), ip());
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { ok: true, volgende: '/bedankt/' });
  const a = t.db.prepare('SELECT * FROM aanvragen ORDER BY id DESC LIMIT 1').get();
  assert.equal(a.naam, 'Jan de Vries');
  assert.equal(a.telefoon, '+31612345678');
  assert.equal(a.telefoon_soort, 'mobiel');
  assert.equal(a.dienst, 'voorlopige-teruggave');
  assert.equal(a.voorkeurstijd, 'weekend-avond');
  assert.equal(a.toestemming_versie, 'terugbellen-2026-10');
  assert.equal(a.toestemming_tekst, t.config.toestemming['terugbellen-2026-10']);
  assert.equal(a.toestemming_tijd, a.aangemaakt);
  assert.equal(a.grondslag, 'toestemming');
  assert.equal(a.pagina, '/senioren/');
  assert.equal(a.landingspagina, '/zaandam/');
  assert.equal(a.verwijzer, 'google.nl');
  assert.equal(a.bron, 'zoekmachine');
  assert.equal(a.apparaat, 'mobiel');
  assert.equal(a.status, 'nieuw');

  const mails = await t.mails(voor + 1);
  const m = mails[mails.length - 1];
  assert.equal(m.aan, 'stan@voorbeeld.nl');
  const onderwerp = nep.onderwerp(m.data);
  assert.equal(onderwerp, 'Nieuwe aanvraag: Voorlopige teruggave (weekend avond)');
  assert.ok(!onderwerp.includes('Jan'), 'geen naam in het onderwerp');
  const tekst = nep.tekst(m.data);
  assert.match(tekst, /Bel: tel:\+31612345678 {2}\(06 12 34 56 78\)/);
  assert.match(tekst, /WhatsApp: https:\/\/wa\.me\/31612345678\?text=Goedendag%20Jan%2C/);
  assert.match(tekst, /Opmerking: Graag na 19:00/);
  assert.match(tekst, /In beheer: https:\/\/belastinghulpzaanstad\.nl\/beheer\/aanvraag\/\d+/);
  assert.match(nep.html(m.data), /href="tel:\+31612345678"/);
});

test('zonder JavaScript: 303 naar /bedankt/', async () => {
  const r = await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000001', h_duur: '' }), Object.assign({ Accept: 'text/html' }, ip()));
  assert.equal(r.status, 303);
  assert.equal(r.headers.get('location'), '/bedankt/');
});

test('zeker spam (honeypot, link in de naam): zelfde antwoord, niets opgeslagen', async () => {
  const voor = aantal();
  let r = await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000002', _gotcha: 'http://spam' }), ip());
  assert.deepEqual(await r.json(), { ok: true, volgende: '/bedankt/' });
  r = await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000006', naam: 'Goedkoop http://spam.example' }), ip());
  assert.deepEqual(await r.json(), { ok: true, volgende: '/bedankt/' });
  assert.equal(aantal(), voor);
});

test('misschien spam (te snel, veel links): wel bewaard, met [Controleer] in de melding', async () => {
  await t.wachtrijLeeg();
  const voor = t.smtp.berichten.length;
  let r = await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000003', h_duur: '1.2' }), ip());
  assert.deepEqual(await r.json(), { ok: true, volgende: '/bedankt/' });
  r = await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000004', opmerking: 'http://a.example http://b.example' }), ip());
  assert.deepEqual(await r.json(), { ok: true, volgende: '/bedankt/' });
  const v = (tel) => t.db.prepare('SELECT verdacht FROM aanvragen WHERE telefoon = ?').get(tel).verdacht;
  assert.equal(v('+31612000003'), 'binnen 2,5 seconde verstuurd');
  assert.equal(v('+31612000004'), 'meerdere links in de opmerking');
  const mails = await t.mails(voor + 2);
  const onderwerpen = mails.slice(voor).map((m) => nep.onderwerp(m.data));
  assert.ok(onderwerpen.every((o) => o.startsWith('[Controleer] Nieuwe aanvraag')), onderwerpen.join(' | '));
  assert.match(nep.tekst(mails[voor].data), /Let op, misschien spam/);
  /* een gewone aanvraag heeft geen markering */
  await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000007' }), ip());
  assert.equal(v('+31612000007'), null);
});

test('ongeldige invoer: 422 met een zin per veld', async () => {
  const r = await t.post('/api/aanvraag', terugbellen({ telefoon: '1234', naam: '', akkoord: '' }), ip());
  assert.equal(r.status, 422);
  const j = await r.json();
  assert.equal(j.ok, false);
  assert.match(j.fouten.telefoon, /klopt niet/);
  assert.equal(j.fouten.naam, 'Vul uw naam in.');
  assert.match(j.fouten.akkoord, /Vink het vakje aan/);
  const zonderJs = await t.post('/api/aanvraag', terugbellen({ telefoon: '1234' }), Object.assign({ Accept: 'text/html', Referer: 'https://belastinghulpzaanstad.nl/contact/' }, ip()));
  assert.equal(zonderJs.status, 422);
  const html = await zonderJs.text();
  assert.match(html, /Dit telefoonnummer klopt niet/);
  assert.match(html, /href="\/contact\/"/);
  assert.match(html, /noindex/);
});

test('onbekende toestemmingsversie of verkeerd formuliersoort: geweigerd', async () => {
  let r = await t.post('/api/aanvraag', terugbellen({ toestemming_versie: 'terugbellen-1999-01' }), ip());
  assert.equal(r.status, 422);
  r = await t.post('/api/aanvraag', terugbellen({ formulier: 'rekentool' }), ip());
  assert.equal(r.status, 422);
});

test('van een andere site: 403', async () => {
  const r = await t.post('/api/aanvraag', terugbellen(), Object.assign({ Origin: 'https://kwaad.example' }, ip()));
  assert.equal(r.status, 403);
});

test('geen formulier maar JSON: 415', async () => {
  const r = await fetch(t.basis + '/api/aanvraag', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: '{}' });
  assert.equal(r.status, 415);
});

test('twee keer op de knop: één aanvraag', async () => {
  const voor = aantal();
  const kop = ip();
  await t.post('/api/aanvraag', terugbellen({ telefoon: '06 12 00 00 05' }), kop);
  await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000005' }), kop);
  assert.equal(aantal(), voor + 1);
  t.verder(3 * 60e3);
  await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000005' }), kop);
  assert.equal(aantal(), voor + 2);
});

test('limiet per IP-adres: de zesde binnen een uur krijgt 429', async () => {
  const kop = ip();
  for (let i = 0; i < 5; i++) {
    const r = await t.post('/api/aanvraag', terugbellen({ telefoon: '061300000' + i }), kop);
    assert.equal(r.status, 200);
  }
  const r = await t.post('/api/aanvraag', terugbellen({ telefoon: '0613000009' }), kop);
  assert.equal(r.status, 429);
  assert.match((await r.json()).fout, /06 19 71 18 48/);
  t.verder(61 * 60e3);
  assert.equal((await t.post('/api/aanvraag', terugbellen({ telefoon: '0613000019' }), kop)).status, 200);
});

test('bron: flyer, partner, bedrijfsprofiel', async () => {
  t.db.prepare("INSERT INTO partners (naam, type, rechtsvorm, ref_code, aangemaakt, gewijzigd) VALUES ('Jansen Makelaardij', 'makelaar', 'bv', 'jansen', 'x', 'x')").run();
  await t.post('/api/aanvraag', terugbellen({ telefoon: '0614000001', h_utm_source: 'flyer', h_utm_medium: 'print', h_utm_campaign: 'rosmolenwijk', h_utm_content: 'senioren' }), ip());
  await t.post('/api/aanvraag', terugbellen({ telefoon: '0614000002', h_ref: 'Jansen' }), ip());
  await t.post('/api/aanvraag', terugbellen({ telefoon: '0614000003', h_utm_source: 'google', h_utm_medium: 'organic', h_utm_campaign: 'bedrijfsprofiel' }), ip());
  const rij = (tel) => t.db.prepare('SELECT bron, bron_detail, partner_id, utm_content FROM aanvragen WHERE telefoon = ?').get(tel);
  assert.deepEqual({ ...rij('+31614000001') }, { bron: 'flyer', bron_detail: 'rosmolenwijk', partner_id: null, utm_content: 'senioren' });
  const p = rij('+31614000002');
  assert.equal(p.bron, 'partner');
  assert.equal(p.bron_detail, 'Jansen Makelaardij');
  assert.ok(p.partner_id);
  assert.equal(rij('+31614000003').bron, 'bedrijfsprofiel');
});

test('rekentool: invoer en uitkomst gaan mee, ook in de melding', async () => {
  await t.wachtrijLeeg();
  const voor = t.smtp.berichten.length;
  const berekening = JSON.stringify({ invoer: [['Hypotheek', '340000'], ['Rente', '3,7']], uitkomst: [['Per maand', '€ 339 – 357']] });
  const r = await t.post('/api/aanvraag', terugbellen({
    formulier: 'rekentool', toestemming_versie: 'rekentool-2026-10', telefoon: '0614000010', rekentool: 'voorlopige-teruggave', berekening
  }), ip());
  assert.equal(r.status, 200);
  const a = t.db.prepare('SELECT rekentool, berekening, toestemming_tekst FROM aanvragen WHERE telefoon = ?').get('+31614000010');
  assert.equal(a.rekentool, 'voorlopige-teruggave');
  assert.deepEqual(JSON.parse(a.berekening).uitkomst, [['Per maand', '€ 339 – 357']]);
  assert.match(a.toestemming_tekst, /deze berekening/);
  const mails = await t.mails(voor + 1);
  assert.match(nep.tekst(mails[mails.length - 1].data), /Per maand: € 339 – 357/);
});

test('contactbericht: e-mail en bericht verplicht', async () => {
  const basis = { formulier: 'bericht', toestemming_versie: 'bericht-2026-10', telefoon: '0614000020' };
  let r = await t.post('/api/aanvraag', terugbellen(basis), ip());
  assert.equal(r.status, 422);
  const j = await r.json();
  assert.ok(j.fouten.email && j.fouten.opmerking);
  r = await t.post('/api/aanvraag', terugbellen(Object.assign({ email: 'a@b.nl', opmerking: 'Mijn vraag' }, basis)), ip());
  assert.equal(r.status, 200);
});

test('gezondheid: publiek alleen ok, vanaf de server meer', async () => {
  let r = await fetch(t.basis + '/api/gezond', { headers: { 'X-Real-IP': '203.0.113.9' } });
  assert.deepEqual(await r.json(), { ok: true });
  r = await fetch(t.basis + '/api/gezond');
  const j = await r.json();
  assert.equal(j.ok, true);
  assert.equal(j.mail, 'ingesteld');
  assert.ok('wachtrij' in j);
});

test('onbekend pad onder /api/: 404 als JSON', async () => {
  const r = await fetch(t.basis + '/api/bestaat-niet');
  assert.equal(r.status, 404);
});
