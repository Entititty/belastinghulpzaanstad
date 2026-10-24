'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./hulp');
const { opruimen } = require('../lib/taken');
const nep = require('./nep-smtp');

let ipTeller = 0;
const ip = () => ({ 'X-Real-IP': '198.51.100.' + (++ipTeller) });
const aanmelding = (email) => ({ email, toestemming_versie: 'herinnering-2026-10', _gotcha: '', h_duur: '8', h_pagina: '/herinnering/' });
const tokenUit = (tekst, soort) => {
  const m = new RegExp('/herinnering/' + soort + '/\\?t=([0-9]+\\.[0-9a-f]{32})').exec(tekst);
  return m && m[1];
};

test('aanmelden, bevestigen met de knop, afmelden = weg', async () => {
  const t = await startApp();
  try {
    let r = await t.post('/api/herinnering', aanmelding('Piet@KPNmail.nl'), ip());
    assert.deepEqual(await r.json(), { ok: true });
    let rij = t.db.prepare('SELECT * FROM herinneringen').get();
    assert.equal(rij.email, 'piet@kpnmail.nl');
    assert.equal(rij.status, 'wacht');
    assert.equal(rij.toestemming_tekst, t.config.toestemming['herinnering-2026-10']);
    assert.equal(rij.pagina, '/herinnering/');

    const [mail] = await t.mails(1);
    assert.equal(mail.aan, 'piet@kpnmail.nl');
    assert.equal(nep.onderwerp(mail.data), 'Bevestig uw herinnering voor de belastingaangifte');
    const token = tokenUit(nep.tekst(mail.data), 'bevestigen');
    assert.ok(token, 'bevestiglink in de mail');

    /* een fout token doet niets */
    r = await t.post('/api/herinnering/bevestig', { t: token.slice(0, -1) + (token.endsWith('a') ? 'b' : 'a') });
    assert.equal(r.status, 400);
    r = await t.post('/api/herinnering/bevestig', { t: token });
    assert.deepEqual(await r.json(), { ok: true });
    rij = t.db.prepare('SELECT * FROM herinneringen').get();
    assert.equal(rij.status, 'bevestigd');
    assert.equal(rij.bevestigd, t.nu().toISOString());

    /* nog een keer aanmelden binnen een dag: geen nieuwe mail */
    await t.post('/api/herinnering', aanmelding('piet@kpnmail.nl'), ip());
    await t.mails(2);
    assert.equal(t.smtp.berichten.length, 1);

    /* na een dag: "u staat al op de lijst", met een afmeldlink */
    t.verder(25 * 3600e3);
    await t.post('/api/herinnering', aanmelding('piet@kpnmail.nl'), ip());
    const mails = await t.mails(2);
    assert.equal(nep.onderwerp(mails[1].data), 'U staat al op de lijst voor de herinnering');
    const afmeld = tokenUit(nep.tekst(mails[1].data), 'afmelden');
    assert.ok(afmeld);

    r = await t.post('/api/herinnering/afmelden', { t: afmeld });
    assert.deepEqual(await r.json(), { ok: true });
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM herinneringen').get().n, 0);
    assert.ok(t.db.prepare("SELECT * FROM logboek WHERE actie = 'herinnering afgemeld'").get());
    /* nog eens afmelden: ook gewoon ok */
    r = await t.post('/api/herinnering/afmelden', { t: afmeld });
    assert.equal(r.status, 200);
  } finally {
    await t.stop();
  }
});

test('ongeldig adres, onbekende versie, honeypot', async () => {
  const t = await startApp();
  try {
    let r = await t.post('/api/herinnering', aanmelding('piet@'), ip());
    assert.equal(r.status, 422);
    r = await t.post('/api/herinnering', Object.assign(aanmelding('a@b.nl'), { toestemming_versie: 'terugbellen-2026-10' }), ip());
    assert.equal(r.status, 400);
    r = await t.post('/api/herinnering', Object.assign(aanmelding('a@b.nl'), { _gotcha: 'x' }), ip());
    assert.equal(r.status, 200);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM herinneringen').get().n, 0);
  } finally {
    await t.stop();
  }
});

test('niet bevestigd: na 7 dagen weg', async () => {
  const t = await startApp();
  try {
    await t.post('/api/herinnering', aanmelding('a@b.nl'), ip());
    t.verder(6 * 864e5);
    opruimen(t.ctx);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM herinneringen').get().n, 1);
    t.verder(2 * 864e5);
    opruimen(t.ctx);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM herinneringen').get().n, 0);
  } finally {
    await t.stop();
  }
});

test('afmelden met één klik vanuit Gmail (RFC 8058)', async () => {
  const t = await startApp();
  try {
    t.db.prepare("INSERT INTO herinneringen (email, status, aangemaakt, bevestigd, toestemming_versie, toestemming_tekst) VALUES ('x@y.nl', 'bevestigd', '2026-11-01T10:00:00.000Z', '2026-11-01T10:05:00.000Z', 'herinnering-2026-10', 'tekst')").run();
    const rij = t.db.prepare('SELECT * FROM herinneringen').get();
    const token = t.app.herinnering.token('afmelden', rij);
    /* Gmail stuurt geen Origin mee */
    const r = await fetch(t.basis + '/api/herinnering/afmelden?t=' + token, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'List-Unsubscribe=One-Click'
    });
    assert.equal(r.status, 200);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM herinneringen').get().n, 0);
    const g = await fetch(t.basis + '/api/herinnering/afmelden?t=' + token, { redirect: 'manual' });
    assert.equal(g.status, 303);
    assert.equal(g.headers.get('location'), '/herinnering/afmelden/?t=' + token);
  } finally {
    await t.stop();
  }
});

test('jaarlijkse ronde: alleen na goedkeuring, maximum per dag, één keer per jaar', async () => {
  const t = await startApp({
    start: '2027-02-10T12:00:00Z',
    config: (c) => { c.herinnering.max_per_dag = 2; }
  });
  try {
    const voeg = t.db.prepare("INSERT INTO herinneringen (email, status, aangemaakt, bevestigd, toestemming_versie, toestemming_tekst) VALUES (?, ?, '2026-11-01T10:00:00.000Z', ?, 'herinnering-2026-10', 'tekst')");
    voeg.run('a@voorbeeld.nl', 'bevestigd', '2026-11-01T10:05:00.000Z');
    voeg.run('b@voorbeeld.nl', 'bevestigd', '2026-11-02T10:05:00.000Z');
    voeg.run('c@voorbeeld.nl', 'bevestigd', '2026-11-03T10:05:00.000Z');
    voeg.run('d@voorbeeld.nl', 'wacht', null);
    const h = t.app.herinnering;

    /* 15 dagen vooraf: niets */
    h.ronde();
    assert.equal((await t.mails(0)).length, 0);
    /* een week vooraf, niet goedgekeurd: seintje aan Stan, één keer */
    t.zetTijd('2027-02-18T12:00:00Z');
    h.ronde();
    h.ronde();
    let mails = await t.mails(1);
    assert.equal(mails.length, 1);
    assert.equal(mails[0].aan, 'stan@voorbeeld.nl');
    assert.match(nep.onderwerp(mails[0].data), /Over een week gaat de herinnering 2027 uit/);

    /* startdatum, nog steeds niet goedgekeurd: weer een seintje, geen mail naar de lijst */
    t.zetTijd('2027-02-25T09:30:00Z');
    h.ronde();
    mails = await t.mails(2);
    assert.equal(mails.length, 2);
    assert.match(nep.onderwerp(mails[1].data), /wacht op uw goedkeuring/);

    /* goedgekeurd: twee vandaag (maximum), de derde morgen; wie niet bevestigde niets */
    h.keurGoed(2027);
    h.ronde();
    mails = await t.mails(4);
    assert.deepEqual(mails.slice(2).map((m) => m.aan).sort(), ['a@voorbeeld.nl', 'b@voorbeeld.nl']);
    const m = mails[2];
    assert.equal(nep.onderwerp(m.data), 'De aangifte over 2026 gaat open');
    const kop = nep.koppen(m.data);
    assert.match(kop['list-unsubscribe'], /^<https:\/\/belastinghulpzaanstad\.nl\/api\/herinnering\/afmelden\?t=\d+\.[0-9a-f]{32}>$/);
    assert.equal(kop['list-unsubscribe-post'], 'List-Unsubscribe=One-Click');
    const tekst = nep.tekst(m.data);
    assert.match(tekst, /De prijs is vast: €59, met uw partner samen €89\./);
    assert.match(tekst, /utm_source=herinnering&utm_medium=email&utm_campaign=aangifte-2026#terugbellen/);
    assert.match(tekst, /\/herinnering\/afmelden\/\?t=/);
    h.ronde();
    await t.mails(5);
    assert.equal(t.smtp.berichten.length, 4, 'maximum per dag');

    t.zetTijd('2027-02-26T10:00:00Z');
    h.ronde();
    mails = await t.mails(5);
    assert.equal(mails[4].aan, 'c@voorbeeld.nl');
    /* alles verstuurd: één keer een seintje dat het klaar is, daarna niets meer */
    h.ronde();
    h.ronde();
    mails = await t.mails(6);
    assert.equal(mails.length, 6);
    assert.match(nep.onderwerp(mails[5].data), /is verstuurd/);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM herinneringen WHERE laatst_verstuurd = 2027').get().n, 3);
  } finally {
    await t.stop();
  }
});

test('goedkeuring vervalt als de tekst verandert', async () => {
  const t = await startApp({ start: '2027-02-25T10:00:00Z' });
  try {
    t.app.herinnering.keurGoed(2027);
    const r = t.config.herinnering.rondes[0];
    assert.equal(t.app.herinnering.goedgekeurd(r), true);
    r.alineas = r.alineas.concat(['Een extra zin.']);
    assert.equal(t.app.herinnering.goedgekeurd(r), false);
  } finally {
    await t.stop();
  }
});
