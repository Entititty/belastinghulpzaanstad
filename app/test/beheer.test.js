'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, terugbellen, ORIGIN } = require('./hulp');
const S = require('../lib/sessie');
const { leesZip } = require('../lib/zip');

const WW = 'een heel lang wachtwoord';
let t, geheim, cookie, csrf;

function haal(pad, kop) {
  return fetch(t.basis + pad, { redirect: 'manual', headers: Object.assign({ Cookie: cookie || '' }, kop || {}) });
}
function stuur(pad, velden, kop) {
  return t.post(pad, Object.assign({ csrf }, velden), Object.assign({ Cookie: cookie, Accept: 'text/html' }, kop || {}));
}
async function login(code) {
  return t.post('/beheer/inloggen', { naam: 'stan', wachtwoord: WW, code }, { Accept: 'text/html', 'X-Real-IP': '203.0.113.50' });
}

test.before(async () => {
  t = await startApp();
  geheim = S.maakGebruiker(t.db, t.nu, 'stan', WW);
  await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000001', naam: 'Jan de Vries', opmerking: 'Graag na 19:00' }), { 'X-Real-IP': '198.51.100.1' });
  /* Een naam met HTML erin weigert het formulier als spam; zet hem er direct in
   * om te zien dat /beheer hem als tekst toont. */
  const nu = t.nu().toISOString();
  t.db.prepare(`INSERT INTO aanvragen (aangemaakt, kanaal, formulier, naam, telefoon, telefoon_soort, email, dienst, bron, grondslag, status, gewijzigd)
    VALUES (?, 'formulier', 'terugbellen', '<b>Piet</b> Jansen', '+31612000002', 'mobiel', 'piet@voorbeeld.nl', 'box3', 'direct', 'toestemming', 'nieuw', ?)`).run(nu, nu);
});
test.after(async () => { await t.stop(); });

test('zonder sessie: naar het inlogscherm, en een POST wordt geweigerd', async () => {
  let r = await haal('/beheer/aanvragen');
  assert.equal(r.status, 303);
  assert.equal(r.headers.get('location'), '/beheer/inloggen');
  r = await t.post('/beheer/aanvraag/1/status', { status: 'klant' }, { Accept: 'text/html' });
  assert.equal(r.status, 403);
  r = await haal('/beheer/inloggen');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(r.headers.get('x-robots-tag'), 'noindex, nofollow');
});

test('inloggen: een foute code niet, de goede wel, en dezelfde code geen tweede keer', async () => {
  let r = await login('000000');
  assert.equal(r.status, 401);
  assert.match(await r.text(), /Inloggen mislukt/);
  const code = S.totp(geheim, t.nu().getTime());
  r = await login(code);
  assert.equal(r.status, 303);
  const set = r.headers.get('set-cookie');
  assert.match(set, /^__Host-bhz=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=\d+$/);
  cookie = set.split(';')[0];
  /* dezelfde code nog eens: geweigerd (iemand die meekeek, komt er niet in) */
  r = await login(code);
  assert.equal(r.status, 401);
  const lijst = await (await haal('/beheer/aanvragen')).text();
  csrf = /name="csrf" value="([^"]+)"/.exec(lijst)[1];
  assert.ok(csrf.length > 20);
});

test('de lijst: namen als tekst, nooit als HTML', async () => {
  const r = await haal('/beheer/aanvragen');
  const s = await r.text();
  assert.match(s, /Jan de Vries/);
  assert.match(s, /&lt;b&gt;Piet&lt;\/b&gt; Jansen/);
  assert.ok(!s.includes('<b>Piet</b>'));
  assert.match(s, /href="tel:\+31612000001"/);
  /* filter op dienst */
  const box3 = await (await haal('/beheer/aanvragen?dienst=box3&status=alle')).text();
  assert.ok(box3.includes('Piet') && !box3.includes('Jan de Vries'));
  /* zoeken op nummer in een andere schrijfwijze */
  const zoek = await (await haal('/beheer/aanvragen?status=alle&q=' + encodeURIComponent('06-12 00 00 01'))).text();
  assert.ok(zoek.includes('Jan de Vries') && !zoek.includes('Piet'));
});

test('status, notitie en omzet; zonder CSRF-token niets', async () => {
  const id = t.db.prepare("SELECT id FROM aanvragen WHERE telefoon = '+31612000001'").get().id;
  let r = await t.post('/beheer/aanvraag/' + id + '/status', { status: 'klant' }, { Cookie: cookie, Accept: 'text/html' });
  assert.equal(r.status, 403, 'zonder csrf');
  r = await stuur('/beheer/aanvraag/' + id + '/status', { status: 'klant' }, { Origin: 'https://kwaad.example' });
  assert.equal(r.status, 403, 'van een andere site');
  r = await stuur('/beheer/aanvraag/' + id + '/status', { status: 'gebeld' });
  assert.equal(r.status, 303);
  r = await stuur('/beheer/aanvraag/' + id + '/status', { status: 'klant' });
  let a = t.db.prepare('SELECT * FROM aanvragen WHERE id = ?').get(id);
  assert.equal(a.status, 'klant');
  assert.equal(a.klant_sinds, t.nu().toISOString());
  const notities = t.db.prepare('SELECT tekst FROM notities WHERE aanvraag_id = ? ORDER BY id').all(id).map((n) => n.tekst);
  assert.deepEqual(notities, ['Status: Nieuw → Gebeld', 'Status: Gebeld → Klant']);
  await stuur('/beheer/aanvraag/' + id + '/notitie', { tekst: 'Afspraak dinsdag 19:30' });
  r = await stuur('/beheer/aanvraag/' + id + '/omzet', { omzet: '1.234,50' });
  assert.equal(r.status, 303);
  a = t.db.prepare('SELECT omzet_centen FROM aanvragen WHERE id = ?').get(id);
  assert.equal(a.omzet_centen, 123450);
  r = await stuur('/beheer/aanvraag/' + id + '/omzet', { omzet: 'veel' });
  assert.equal(r.headers.get('location'), '/beheer/aanvraag/' + id + '?fout=omzet');
  const detail = await (await haal('/beheer/aanvraag/' + id + '?fout=omzet')).text();
  assert.match(detail, /Dat bedrag begrijp ik niet/);
  assert.match(detail, /Afspraak dinsdag 19:30/);
  assert.match(detail, /aria-pressed="true">Klant/);
  assert.match(detail, /https:\/\/wa\.me\/31612000001\?text=Goedendag%20Jan/);
});

test('export: CSV en Excel met de juiste kolommen', async () => {
  let r = await haal('/beheer/aanvragen.csv?status=alle');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-disposition'), /attachment; filename="aanvragen-\d{4}-\d{2}-\d{2}\.csv"/);
  const bytes = Buffer.from(await r.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 3)], [0xef, 0xbb, 0xbf], 'BOM voorop, voor Excel');
  const s = bytes.toString('utf8').slice(1);
  assert.ok(s.startsWith('Nr;Binnen;Status;Naam;Telefoon;E-mail;Dienst'), s.slice(0, 60));
  assert.match(s, /Jan de Vries;06 12 00 00 01/);
  r = await haal('/beheer/aanvragen.xlsx?status=alle');
  const z = leesZip(Buffer.from(await r.arrayBuffer()));
  const blad = z['xl/worksheets/sheet1.xml'].toString();
  assert.match(blad, /Jan de Vries/);
  assert.match(blad, /<c r="W\d+" s="2"><v>1234\.5<\/v><\/c>/, 'omzet als bedrag');
  assert.ok(t.db.prepare("SELECT 1 FROM logboek WHERE actie = 'export'").get());
});

test('handmatig toevoegen: wie belde', async () => {
  let r = await stuur('/beheer/nieuw', { naam: 'Bel Vrouw', telefoon: 'onzin', kanaal: 'telefoon', dienst: 'aangifte-senioren', hoe: 'via-via' });
  assert.equal(r.status, 422);
  assert.match(await r.text(), /Dit telefoonnummer klopt niet/);
  r = await stuur('/beheer/nieuw', { naam: 'Bel Vrouw', telefoon: '075 123 4567', kanaal: 'telefoon', dienst: 'aangifte-senioren', hoe: 'via-via' });
  assert.equal(r.status, 303);
  const a = t.db.prepare("SELECT * FROM aanvragen WHERE naam = 'Bel Vrouw'").get();
  assert.equal(a.kanaal, 'telefoon');
  assert.equal(a.bron, 'via-via');
  assert.equal(a.grondslag, 'zelf contact opgenomen');
  assert.equal(a.telefoon_soort, 'vast');
});

test('privacy: alles van één persoon exporteren en verwijderen', async () => {
  /* dezelfde persoon staat ook op de herinneringslijst */
  t.db.prepare("INSERT INTO herinneringen (email, status, aangemaakt, toestemming_versie, toestemming_tekst) VALUES ('piet@voorbeeld.nl', 'bevestigd', ?, 'herinnering-2026-10', 't')").run(t.nu().toISOString());
  const pagina = await (await haal('/beheer/persoon?q=piet@voorbeeld.nl')).text();
  assert.match(pagina, /1 aanvraag\/aanvragen en 1 inschrijving/);
  const r = await haal('/beheer/persoon.json?q=piet@voorbeeld.nl');
  const j = await r.json();
  assert.equal(j.aanvragen.length, 1);
  assert.equal(j.herinneringslijst.length, 1);
  assert.ok(Array.isArray(j.aanvragen[0].notities));
  const weg = await stuur('/beheer/persoon/verwijderen', { q: 'piet@voorbeeld.nl' });
  assert.equal(weg.status, 303);
  assert.equal(t.db.prepare("SELECT COUNT(*) n FROM aanvragen WHERE email = 'piet@voorbeeld.nl'").get().n, 0);
  assert.equal(t.db.prepare("SELECT COUNT(*) n FROM herinneringen WHERE email = 'piet@voorbeeld.nl'").get().n, 0);
  const log = t.db.prepare("SELECT details FROM logboek WHERE actie = 'privacy-verwijderd'").get().details;
  assert.equal(log, '1 aanvragen, 1 herinneringen');
  assert.ok(!t.db.prepare('SELECT group_concat(details) AS d FROM logboek').get().d.includes('piet'), 'geen adres in het logboek');
});

test('herinnering: voorbeeld en goedkeuren', async () => {
  const pagina = await (await haal('/beheer/herinnering')).text();
  assert.match(pagina, /Nog niet goedgekeurd/);
  assert.match(pagina, /De aangifte over 2026 gaat open/);
  const vb = await haal('/beheer/herinnering/2027/voorbeeld');
  assert.match(vb.headers.get('content-security-policy'), /sandbox/);
  assert.match(await vb.text(), /€59, met uw partner samen €89/);
  const r = await stuur('/beheer/herinnering/2027/goedkeuren', {});
  assert.equal(r.status, 303);
  assert.equal(t.app.herinnering.goedgekeurd(t.config.herinnering.rondes[0]), true);
});

test('status en proefmail', async () => {
  const voor = t.smtp.berichten.length;
  const s = await (await haal('/beheer/status')).text();
  assert.match(s, /ingesteld \(SMTP 127\.0\.0\.1/);
  await stuur('/beheer/status/testmail', {});
  const mails = await t.mails(voor + 1);
  assert.ok(mails.slice(voor).some((m) => /Proefmail uit \/beheer/.test(require('./nep-smtp').onderwerp(m.data))));
});

test('stijl en script zonder sessie, en onbekend = 404', async () => {
  const css = await fetch(t.basis + '/beheer/stijl.css');
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type'), /text\/css/);
  const r = await haal('/beheer/bestaat-niet');
  assert.equal(r.status, 404);
});

test('uitloggen: sessie weg, cookie leeg', async () => {
  const r = await stuur('/beheer/uitloggen', {});
  assert.equal(r.status, 303);
  assert.match(r.headers.get('set-cookie'), /^__Host-bhz=; .*Max-Age=0/);
  const na = await haal('/beheer/aanvragen');
  assert.equal(na.status, 303, 'oude cookie werkt niet meer');
});

test('rem: na 5 foute pogingen 15 minuten dicht', async () => {
  const kop = { Accept: 'text/html', 'X-Real-IP': '203.0.113.77' };
  for (let i = 0; i < 5; i++) await t.post('/beheer/inloggen', { naam: 'stan', wachtwoord: 'fout', code: '123456' }, kop);
  const r = await t.post('/beheer/inloggen', { naam: 'stan', wachtwoord: WW, code: S.totp(geheim, t.nu().getTime() + 30000) }, kop);
  assert.equal(r.status, 429);
  assert.match(await r.text(), /Te veel pogingen/);
  void ORIGIN;
});
