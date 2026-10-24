#!/usr/bin/env node
'use strict';
/*
 * server.js — de app achter /api/ en /beheer/.
 *
 * Op de server: draait als systemd-dienst "belastinghulp-app" onder de
 * gebruiker bhz-app, luistert alleen op 127.0.0.1:8790, en nginx stuurt
 * /api/ en /beheer/ hierheen. Zie server-setup/APP.md.
 *
 * Lokaal:  node app/server.js --dev
 *   Serveert dan ook de pagina's, op http://localhost:8790, met een database
 *   in intern/dev/. Mail gaat alleen weg als SMTP_* in de omgeving staat;
 *   anders blijft hij in de wachtrij staan.
 *
 * Na een uitrol (git reset --hard verandert .git/ORIG_HEAD) stopt de app
 * zichzelf netjes, en start systemd hem opnieuw met de nieuwe code.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const dbm = require('./lib/db');
const h = require('./lib/http');
const { laadConfig, laadEnv } = require('./lib/config');
const { maakMailer } = require('./lib/mail');
const { maakAanvraag } = require('./lib/aanvraag');
const { maakHerinnering } = require('./lib/herinnering');
const { maakPlanner, opruimen } = require('./lib/taken');
const { maakStatisch } = require('./lib/statisch');
const { maakBeheer } = require('./lib/beheer');
const { maakPush } = require('./lib/push');
const { dagoverzicht, dagoverzichtTijd, backup, klikkenInlezen } = require('./lib/dagelijks');

const ROOT = path.resolve(__dirname, '..');

function standaardLog(niveau, tekst) {
  (niveau === 'fout' ? console.error : console.log)('[' + niveau + '] ' + tekst);
}

/* De commit die nu draait, voor /api/gezond vanaf de server zelf */
function commit(root) {
  try {
    const head = fs.readFileSync(path.join(root, '.git', 'HEAD'), 'utf8').trim();
    if (!head.startsWith('ref: ')) return head.slice(0, 8);
    const ref = head.slice(5);
    const los = path.join(root, '.git', ref);
    if (fs.existsSync(los)) return fs.readFileSync(los, 'utf8').trim().slice(0, 8);
    const packed = fs.readFileSync(path.join(root, '.git', 'packed-refs'), 'utf8');
    const m = packed.split('\n').find((r) => r.endsWith(' ' + ref));
    return m ? m.slice(0, 8) : '?';
  } catch (e) {
    return '?';
  }
}

function maakApp(o) {
  const opties = o || {};
  const root = opties.root || ROOT;
  const dev = !!opties.dev;
  const poort = opties.poort || 8790;
  const config = opties.config || laadConfig(root);
  const env = laadEnv(opties.env || process.env, root, dev, poort);
  const klok = opties.klok || (() => new Date());
  const log = opties.log || standaardLog;
  const db = dbm.open(env.BHZ_DB);
  const basisUrl = env.BHZ_BASIS_URL;
  const origins = [new URL(basisUrl).origin];
  if (dev) origins.push('http://localhost:' + poort, 'http://127.0.0.1:' + poort);

  const ctx = { root, dev, config, env, klok, log, db, basisUrl, origins };
  ctx.mail = maakMailer({ db, klok, env, log, verstuur: opties.verstuur });
  ctx.push = maakPush(env, log, basisUrl);
  ctx.commit = () => commit(root);
  const aanvraag = maakAanvraag(ctx);
  const herinnering = maakHerinnering(ctx);
  ctx.herinnering = herinnering;
  ctx.beheer = maakBeheer(ctx);
  require('./lib/overzicht').registreer(ctx);
  require('./lib/partners').registreer(ctx);
  const statisch = dev ? maakStatisch(root, log) : null;

  function gezond(req, res) {
    if (!h.lokaalVerzoek(req)) return h.json(res, 200, { ok: true });
    let dbOk = true;
    try { db.prepare('SELECT 1').get(); } catch (e) { dbOk = false; }
    return h.json(res, 200, { ok: dbOk, commit: commit(root), mail: ctx.mail.ingesteld() ? 'ingesteld' : 'NIET ingesteld', wachtrij: ctx.mail.wachtrijStand() });
  }

  const routes = {
    'GET /api/gezond': gezond,
    'POST /api/aanvraag': aanvraag,
    'POST /api/herinnering': herinnering.aanmelden,
    'POST /api/herinnering/bevestig': herinnering.bevestig,
    'POST /api/herinnering/afmelden': herinnering.afmelden,
    'GET /api/herinnering/afmelden': herinnering.afmeldenGet
  };
  ctx.routes = routes;

  const server = http.createServer(async (req, res) => {
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch (e) { res.writeHead(400); return res.end(); }
    try {
      const route = routes[req.method + ' ' + url.pathname];
      if (route) return await route(req, res, url);
      if (ctx.beheer && (url.pathname === '/beheer' || url.pathname.startsWith('/beheer/'))) return await ctx.beheer(req, res, url);
      if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/beheer')) return h.json(res, 404, { ok: false, fout: 'niet gevonden' });
      if (statisch) return statisch(req, res, url);
      res.writeHead(404); return res.end();
    } catch (e) {
      if (res.headersSent) { res.destroy(); return; }
      if (e instanceof h.HttpFout) return h.json(res, e.status, { ok: false, fout: e.status === 413 ? 'Uw bericht is te lang.' : 'Dit verzoek klopt niet.' });
      log('fout', req.method + ' ' + url.pathname + ': ' + (e && e.stack ? e.stack : e));
      return h.json(res, 500, { ok: false, fout: 'Er ging iets mis. Bel of app ons op 06 19 71 18 48, dan helpen wij u direct.' });
    }
  });
  server.requestTimeout = 30e3;
  server.headersTimeout = 15e3;

  const planner = maakPlanner(ctx, [
    { naam: 'wachtrij', elkeMs: 60e3, doe: () => ctx.mail.verwerk() },
    { naam: 'herinnering', elkeMs: 60e3, doe: () => herinnering.ronde() },
    { naam: 'opruimen', om: config.planning.opruimen, doe: () => opruimen(ctx) },
    { naam: 'backup', om: config.planning.backup, doe: () => backup(ctx) },
    { naam: 'klikken', om: config.planning.klikken_inlezen, doe: () => klikkenInlezen(ctx) },
    { naam: 'dagoverzicht', om: dagoverzichtTijd(config), doe: () => dagoverzicht(ctx) }
  ]);
  ctx.planner = planner;

  function sluit() {
    planner.stop();
    return new Promise((resolve) => {
      server.close(() => { try { db.close(); } catch (e) { /* al dicht */ } resolve(); });
      if (server.closeIdleConnections) server.closeIdleConnections();
    });
  }

  return { ctx, server, planner, herinnering, sluit };
}

/* Stop netjes als git reset --hard een nieuwe versie heeft neergezet */
function bewaakUitrol(root, stop, log) {
  const f = path.join(root, '.git', 'ORIG_HEAD');
  const stand = () => { try { return fs.statSync(f).mtimeMs; } catch (e) { return 0; } };
  const begin = stand();
  const t = setInterval(() => {
    if (stand() === begin) return;
    clearInterval(t);
    log('info', 'nieuwe uitrol gezien; de app herstart met de nieuwe code');
    stop();
  }, 60e3);
  t.unref();
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const waarde = (naam) => { const i = args.indexOf(naam); return i !== -1 ? args[i + 1] : undefined; };
  const dev = args.includes('--dev');
  const poort = Number(waarde('--poort') || process.env.BHZ_POORT || 8790);
  const app = maakApp({ dev, poort });
  let stopt = false;
  const stop = () => {
    if (stopt) return;
    stopt = true;
    app.sluit().then(() => process.exit(0));
    setTimeout(() => process.exit(0), 10e3).unref();
  };
  app.server.listen(poort, '127.0.0.1', () => {
    standaardLog('info', 'app luistert op 127.0.0.1:' + poort + (dev ? ' (lokaal: http://localhost:' + poort + '/)' : '') +
      '; mail ' + (app.ctx.mail.ingesteld() ? 'ingesteld' : 'NIET ingesteld (zie server-setup/APP.md)'));
  });
  app.planner.start();
  if (!dev) bewaakUitrol(ROOT, stop, standaardLog);
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

module.exports = { maakApp };
