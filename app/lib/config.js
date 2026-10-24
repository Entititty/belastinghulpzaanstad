'use strict';
/*
 * config.js — instellingen inlezen en controleren.
 *
 * Publiek: data/aanvraag.json (formulieren, termijnen, tijden) en
 * data/bedrijf.json (naam, prijzen). Geheim: de omgeving, die systemd uit
 * /etc/belastinghulp/app.env haalt. Een fout in de instellingen stopt de app
 * bij het starten, met een duidelijke melding, in plaats van halverwege een
 * aanvraag.
 */
const fs = require('fs');
const path = require('path');
const { vanNl } = require('./tijd');

function lees(f) { return JSON.parse(fs.readFileSync(f, 'utf8')); }

function controleer(c) {
  const fout = (t) => { throw new Error('data/aanvraag.json: ' + t); };
  const codes = (lijst, wat) => {
    if (!Array.isArray(lijst) || !lijst.length) fout(wat + ' ontbreekt');
    const gezien = new Set();
    for (const x of lijst) {
      if (!/^[a-z0-9-]+$/.test(x.code || '') || !x.label) fout(wat + ': ongeldige regel ' + JSON.stringify(x));
      if (gezien.has(x.code)) fout(wat + ': dubbele code ' + x.code);
      gezien.add(x.code);
    }
  };
  codes(c.diensten, 'diensten');
  codes(c.voorkeurstijden, 'voorkeurstijden');
  if (!c.diensten.some((d) => d.code === 'onbekend')) fout('diensten mist "onbekend"');
  for (const [p, d] of Object.entries(c.dienst_per_pagina || {})) {
    if (!c.diensten.some((x) => x.code === d)) fout('dienst_per_pagina ' + p + ': onbekende dienst ' + d);
  }
  for (const [versie, tekst] of Object.entries(c.toestemming || {})) {
    if (!/^(terugbellen|rekentool|bericht|herinnering)-\d{4}-\d{2}$/.test(versie)) fout('toestemmingsversie ' + versie + ' heeft niet de vorm soort-JJJJ-MM');
    if (typeof tekst !== 'string' || tekst.length < 20) fout('toestemmingstekst ' + versie + ' is leeg');
  }
  const b = c.bewaren || {};
  for (const k of ['aanvraag_maanden', 'herinnering_onbevestigd_dagen', 'backup_dagen', 'sessie_dagen', 'mislukte_mail_dagen']) {
    if (!Number.isInteger(b[k]) || b[k] < 1) fout('bewaren.' + k + ' moet een positief geheel getal zijn');
  }
  for (const k of ['dagoverzicht_doordeweeks', 'dagoverzicht_weekend', 'opruimen', 'backup', 'klikken_inlezen']) {
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test((c.planning || {})[k] || '')) fout('planning.' + k + ' moet UU:MM zijn');
  }
  for (const r of (c.herinnering || {}).rondes || []) {
    vanNl(r.verstuur_vanaf);
    if (!r.onderwerp || !Array.isArray(r.alineas) || !r.alineas.length) fout('herinnering ' + r.jaar + ': onderwerp of alinea\'s ontbreken');
  }
}

function laadConfig(root) {
  const c = lees(path.join(root, 'data', 'aanvraag.json'));
  controleer(c);
  c.bedrijf = lees(path.join(root, 'data', 'bedrijf.json'));
  return c;
}

/* De omgeving, met standaardwaarden. In --dev komt alles in intern/dev/
 * (staat in .gitignore) en is een geheim niet verplicht. */
function laadEnv(bron, root, dev, poort) {
  const e = Object.assign({}, bron);
  e.BHZ_BASIS_URL = (e.BHZ_BASIS_URL || (dev ? 'http://localhost:' + poort : 'https://belastinghulpzaanstad.nl')).replace(/\/$/, '');
  e.BHZ_DB = e.BHZ_DB || (dev ? path.join(root, 'intern', 'dev', 'leads.db') : '/var/lib/belastinghulp/leads.db');
  e.BHZ_BACKUP_MAP = e.BHZ_BACKUP_MAP || (dev ? path.join(root, 'intern', 'dev', 'backup') : '/var/backups/belastinghulp');
  e.BHZ_TELLINGEN_MAP = e.BHZ_TELLINGEN_MAP || (dev ? path.join(root, 'data', 'tellingen') : '/var/log/belastinghulp/tellingen');
  if (!e.BHZ_GEHEIM) {
    if (!dev) throw new Error('BHZ_GEHEIM ontbreekt in /etc/belastinghulp/app.env (draai server-setup/app-installeren.sh opnieuw)');
    e.BHZ_GEHEIM = 'alleen-voor-lokaal-testen-niet-op-de-server-gebruiken';
  }
  if (!dev && e.BHZ_GEHEIM.length < 32) throw new Error('BHZ_GEHEIM is te kort (minstens 32 tekens)');
  return e;
}

module.exports = { laadConfig, laadEnv, controleer };
