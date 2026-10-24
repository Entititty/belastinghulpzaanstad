'use strict';
/*
 * db.js — de database: één SQLite-bestand buiten de webroot.
 *
 * Waarom SQLite en geen databaseserver: één bestand, geen extra proces, en
 * sinds Node 22 zit het in Node zelf (node:sqlite). Er hoeft dus niets
 * gebouwd of geïnstalleerd te worden op de VPS.
 *
 * secure_delete staat aan: een verwijderde rij wordt met nullen overschreven
 * in plaats van alleen vrijgegeven. Wie om verwijdering vraagt, is dan ook
 * echt weg uit het bestand (de back-ups van de afgelopen 14 dagen nog niet;
 * dat staat in het privacybeleid).
 *
 * Schemawijzigingen: voeg een stap toe aan MIGRATIES. user_version houdt bij
 * welke stappen al gedraaid hebben. Nooit een bestaande stap wijzigen.
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const MIGRATIES = [
  /* 1: eerste versie */
  `
  CREATE TABLE partners (
    id INTEGER PRIMARY KEY,
    naam TEXT NOT NULL,
    type TEXT NOT NULL,
    rechtsvorm TEXT NOT NULL,
    contactpersoon TEXT,
    telefoon TEXT,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'benaderd',
    ref_code TEXT NOT NULL UNIQUE,
    landingspagina TEXT,
    notities TEXT,
    aangemaakt TEXT NOT NULL,
    gewijzigd TEXT NOT NULL
  );

  CREATE TABLE aanvragen (
    id INTEGER PRIMARY KEY,
    aangemaakt TEXT NOT NULL,
    kanaal TEXT NOT NULL,
    formulier TEXT,
    naam TEXT NOT NULL,
    telefoon TEXT,
    telefoon_soort TEXT,
    email TEXT,
    dienst TEXT NOT NULL,
    voorkeurstijd TEXT,
    opmerking TEXT,
    rekentool TEXT,
    berekening TEXT,
    pagina TEXT,
    vorige_pagina TEXT,
    landingspagina TEXT,
    verwijzer TEXT,
    utm_source TEXT,
    utm_medium TEXT,
    utm_campaign TEXT,
    utm_content TEXT,
    ref TEXT,
    partner_id INTEGER REFERENCES partners(id) ON DELETE SET NULL,
    bron TEXT NOT NULL,
    bron_detail TEXT,
    apparaat TEXT,
    grondslag TEXT NOT NULL,
    toestemming_versie TEXT,
    toestemming_tekst TEXT,
    toestemming_tijd TEXT,
    status TEXT NOT NULL DEFAULT 'nieuw',
    status_tijd TEXT,
    omzet_centen INTEGER,
    klant_sinds TEXT,
    gewijzigd TEXT NOT NULL
  );
  CREATE INDEX aanvragen_status ON aanvragen(status);
  CREATE INDEX aanvragen_aangemaakt ON aanvragen(aangemaakt);
  CREATE INDEX aanvragen_telefoon ON aanvragen(telefoon);
  CREATE INDEX aanvragen_email ON aanvragen(email);
  CREATE INDEX aanvragen_partner ON aanvragen(partner_id);

  CREATE TABLE notities (
    id INTEGER PRIMARY KEY,
    aanvraag_id INTEGER NOT NULL REFERENCES aanvragen(id) ON DELETE CASCADE,
    tijd TEXT NOT NULL,
    tekst TEXT NOT NULL
  );
  CREATE INDEX notities_aanvraag ON notities(aanvraag_id);

  CREATE TABLE herinneringen (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    aangemaakt TEXT NOT NULL,
    bevestigd TEXT,
    toestemming_versie TEXT NOT NULL,
    toestemming_tekst TEXT NOT NULL,
    pagina TEXT,
    laatste_mail TEXT,
    laatst_verstuurd INTEGER
  );

  CREATE TABLE klikken (
    dag TEXT NOT NULL,
    e TEXT NOT NULL,
    p TEXT NOT NULL,
    k TEXT NOT NULL DEFAULT '',
    b TEXT NOT NULL DEFAULT '',
    c TEXT NOT NULL DEFAULT '',
    n INTEGER NOT NULL,
    PRIMARY KEY (dag, e, p, k, b, c)
  );

  CREATE TABLE gebruikers (
    id INTEGER PRIMARY KEY,
    naam TEXT NOT NULL UNIQUE,
    wachtwoord TEXT NOT NULL,
    totp_geheim TEXT NOT NULL,
    laatste_code TEXT,
    aangemaakt TEXT NOT NULL
  );

  CREATE TABLE sessies (
    token_hash TEXT PRIMARY KEY,
    gebruiker_id INTEGER NOT NULL REFERENCES gebruikers(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    aangemaakt TEXT NOT NULL,
    verloopt TEXT NOT NULL
  );

  CREATE TABLE uitgaand (
    id INTEGER PRIMARY KEY,
    soort TEXT NOT NULL,
    aan TEXT NOT NULL,
    onderwerp TEXT NOT NULL,
    tekst TEXT NOT NULL,
    html TEXT,
    headers TEXT,
    aanvraag_id INTEGER REFERENCES aanvragen(id) ON DELETE CASCADE,
    herinnering_id INTEGER REFERENCES herinneringen(id) ON DELETE CASCADE,
    pogingen INTEGER NOT NULL DEFAULT 0,
    volgende_poging TEXT NOT NULL,
    fout TEXT,
    gestopt TEXT,
    aangemaakt TEXT NOT NULL
  );
  CREATE INDEX uitgaand_volgende ON uitgaand(volgende_poging);

  CREATE TABLE taken (
    naam TEXT PRIMARY KEY,
    laatste TEXT NOT NULL
  );

  CREATE TABLE instellingen (
    sleutel TEXT PRIMARY KEY,
    waarde TEXT NOT NULL
  );

  CREATE TABLE logboek (
    id INTEGER PRIMARY KEY,
    tijd TEXT NOT NULL,
    actie TEXT NOT NULL,
    details TEXT
  );
  `
];

function open(bestand) {
  if (bestand !== ':memory:') fs.mkdirSync(path.dirname(bestand), { recursive: true });
  const db = new DatabaseSync(bestand);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA busy_timeout = 5000');
  db.exec('PRAGMA secure_delete = ON');
  migreer(db);
  return db;
}

function migreer(db) {
  const versie = db.prepare('PRAGMA user_version').get().user_version;
  for (let i = versie; i < MIGRATIES.length; i++) {
    transactie(db, () => {
      db.exec(MIGRATIES[i]);
      db.exec('PRAGMA user_version = ' + (i + 1));
    });
  }
}

function transactie(db, fn) {
  db.exec('BEGIN');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

/* node:sqlite kent geen undefined; maak er null van */
function rij(o) {
  const r = {};
  for (const k of Object.keys(o)) r[k] = o[k] === undefined ? null : o[k];
  return r;
}

/* Een regel in het logboek. NOOIT persoonsgegevens in details: alleen
 * nummers, aantallen en soorten. */
function log(db, klok, actie, details) {
  db.prepare('INSERT INTO logboek (tijd, actie, details) VALUES (?, ?, ?)')
    .run(klok().toISOString(), actie, details == null ? null : String(details));
}

function instelling(db, sleutel) {
  const r = db.prepare('SELECT waarde FROM instellingen WHERE sleutel = ?').get(sleutel);
  return r ? r.waarde : null;
}
function zetInstelling(db, sleutel, waarde) {
  if (waarde === null) db.prepare('DELETE FROM instellingen WHERE sleutel = ?').run(sleutel);
  else db.prepare('INSERT INTO instellingen (sleutel, waarde) VALUES (?, ?) ON CONFLICT(sleutel) DO UPDATE SET waarde = excluded.waarde').run(sleutel, String(waarde));
}

module.exports = { open, transactie, rij, log, instelling, zetInstelling, MIGRATIES };
