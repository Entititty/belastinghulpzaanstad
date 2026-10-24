#!/usr/bin/env node
'use strict';
/*
 * beheer-gebruiker.js — een beheerder aanmaken, of wachtwoord en app opnieuw
 * instellen (bijvoorbeeld bij een nieuwe telefoon). Alle sessies van die
 * gebruiker vervallen dan.
 *
 * Op de server:
 *   sudo -u bhz-app node /var/www/belastinghulpzaanstad.nl/html/app/beheer-gebruiker.js stan
 *
 * 1. Typ twee keer een wachtwoord (minstens 12 tekens; u ziet niets verschijnen).
 * 2. Scan de QR-code met een authenticator-app (Google Authenticator,
 *    Microsoft Authenticator). Lukt scannen niet, typ dan de sleutel over.
 * 3. Typ ter controle de 6 cijfers die de app toont.
 */
const readline = require('readline');
const path = require('path');
const { omgeving } = require('./lib/envbestand');
const { laadEnv } = require('./lib/config');
const dbm = require('./lib/db');
const S = require('./lib/sessie');
const qr = require('./lib/qr');

function vraag(tekst, verborgen) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (verborgen) {
      /* niets laten zien van wat er getypt wordt, wel de vraag zelf */
      rl._writeToOutput = (s) => { if (s.indexOf(tekst) !== -1) process.stdout.write(tekst); };
    }
    rl.question(tekst, (antwoord) => {
      rl.close();
      if (verborgen) process.stdout.write('\n');
      resolve(antwoord);
    });
  });
}

async function main() {
  const naam = (process.argv[2] || 'stan').trim();
  const env = laadEnv(omgeving(), path.resolve(__dirname, '..'), process.argv.includes('--dev'), 8790);
  const db = dbm.open(env.BHZ_DB);
  const klok = () => new Date();

  console.log('Beheerder "' + naam + '" ' + (db.prepare('SELECT 1 FROM gebruikers WHERE naam = ?').get(naam) ? 'opnieuw instellen' : 'aanmaken') + '.');
  const w1 = await vraag('Nieuw wachtwoord (minstens 12 tekens): ', true);
  if (w1.length < 12) { console.error('Te kort: minstens 12 tekens. Er is niets veranderd.'); process.exit(1); }
  const w2 = await vraag('Hetzelfde wachtwoord nog een keer: ', true);
  if (w1 !== w2) { console.error('De twee wachtwoorden zijn niet gelijk. Er is niets veranderd.'); process.exit(1); }

  const geheim = S.maakGebruiker(db, klok, naam, w1);
  const uri = S.otpauthUri(naam, geheim);
  console.log('\nOpen een authenticator-app (bijvoorbeeld Google Authenticator of Microsoft Authenticator),');
  console.log('kies "account toevoegen" en "QR-code scannen", en scan deze code:\n');
  console.log(qr.terminal(qr.maak(uri, 'M')));
  console.log('\nLukt scannen niet? Kies dan "sleutel invoeren" en typ:');
  console.log('  Account: Belastinghulp Zaanstad (' + naam + ')');
  console.log('  Sleutel: ' + geheim.match(/.{1,4}/g).join(' '));
  console.log('  Soort:   op tijd gebaseerd\n');

  for (let poging = 1; poging <= 3; poging++) {
    const code = await vraag('Typ ter controle de 6 cijfers die de app nu toont: ');
    if (S.totpStap(geheim, code, Date.now()) >= 0) {
      console.log('\nGelukt. Log in op ' + env.BHZ_BASIS_URL + '/beheer/ met "' + naam + '", uw wachtwoord en de code uit de app.');
      db.close();
      return;
    }
    console.log('Die code klopt niet. Kijk of de tijd op uw telefoon automatisch staat, en probeer het nog eens.');
  }
  console.log('\nDe gebruiker is wel aangemaakt, maar de controle lukte niet. Draai dit commando opnieuw om de app opnieuw te koppelen.');
  db.close();
  process.exit(1);
}

main().catch((e) => { console.error('FOUT: ' + e.message); process.exit(1); });
