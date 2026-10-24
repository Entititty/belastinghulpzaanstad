'use strict';
/*
 * hulp.js — de app starten voor een test: eigen tijdelijke database, een
 * nep-mailserver en een klok die de test zelf verzet.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { maakApp } = require('../server');
const { laadConfig } = require('../lib/config');
const { startNepSmtp } = require('./nep-smtp');

const ROOT = path.resolve(__dirname, '..', '..');
const ORIGIN = 'https://belastinghulpzaanstad.nl';

async function startApp(opties) {
  const o = opties || {};
  const smtp = await startNepSmtp({ weiger: o.weiger });
  const map = fs.mkdtempSync(path.join(os.tmpdir(), 'bhz-test-'));
  let nu = new Date(o.start || '2026-11-02T19:00:00Z');
  const klok = () => new Date(nu.getTime());
  const logs = [];
  const config = laadConfig(ROOT);
  if (o.config) o.config(config);
  const env = Object.assign({
    BHZ_DB: path.join(map, 'test.db'),
    BHZ_BASIS_URL: ORIGIN,
    BHZ_GEHEIM: 'test-geheim-'.repeat(4),
    BHZ_BACKUP_MAP: path.join(map, 'backup'),
    BHZ_TELLINGEN_MAP: path.join(map, 'tellingen'),
    SMTP_HOST: '127.0.0.1',
    SMTP_POORT: String(smtp.poort),
    SMTP_BEVEILIGING: 'geen',
    SMTP_GEBRUIKER: 'test',
    SMTP_WACHTWOORD: 'geheim',
    MAIL_VAN: 'info@belastinghulpzaanstad.nl',
    MAIL_MELDINGEN_AAN: 'stan@voorbeeld.nl'
  }, o.env || {});
  const app = maakApp({ root: ROOT, env, klok, config, log: (n, t) => logs.push('[' + n + '] ' + t) });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const basis = 'http://127.0.0.1:' + app.server.address().port;

  const t = {
    app, smtp, logs, basis, map, config, db: app.ctx.db, ctx: app.ctx,
    zetTijd(d) { nu = new Date(d); },
    verder(ms) { nu = new Date(nu.getTime() + ms); },
    nu: klok,
    post(pad, velden, kop) {
      return fetch(basis + pad, {
        method: 'POST',
        redirect: 'manual',
        headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', Origin: ORIGIN }, kop || {}),
        body: new URLSearchParams(velden).toString()
      });
    },
    /* wacht tot er n mails binnen zijn (de wachtrij werkt na setImmediate) */
    async mails(n) {
      for (let i = 0; i < 100 && smtp.berichten.length < n; i++) {
        await app.ctx.mail.verwerk();
        await new Promise((r) => setTimeout(r, 20));
      }
      return smtp.berichten;
    },
    /* wacht tot alle mail uit de wachtrij verstuurd is */
    async wachtrijLeeg() {
      for (let i = 0; i < 100; i++) {
        await app.ctx.mail.verwerk();
        if (app.ctx.db.prepare('SELECT COUNT(*) AS n FROM uitgaand WHERE gestopt IS NULL').get().n === 0) return;
        await new Promise((r) => setTimeout(r, 20));
      }
    },
    async stop() {
      await app.sluit();
      await smtp.sluit();
      fs.rmSync(map, { recursive: true, force: true });
    }
  };
  return t;
}

/* Een geldig terugbelformulier; overschrijf wat je wilt testen */
function terugbellen(extra) {
  return Object.assign({
    formulier: 'terugbellen',
    toestemming_versie: 'terugbellen-2026-10',
    naam: 'Jan de Vries',
    telefoon: '06 12 34 56 78',
    dienst: 'voorlopige-teruggave',
    voorkeurstijd: 'weekend-avond',
    akkoord: 'on',
    _gotcha: '',
    h_duur: '12',
    h_pagina: '/'
  }, extra || {});
}

module.exports = { startApp, terugbellen, ROOT, ORIGIN };
