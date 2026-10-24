#!/usr/bin/env node
'use strict';
/*
 * testmail.js — stuurt één proefmail, rechtstreeks (niet via de wachtrij),
 * en zegt in gewone taal wat er mis is als het niet lukt.
 *
 * Op de server, na het invullen van /etc/belastinghulp/app.env:
 *   sudo -u bhz-app node /var/www/belastinghulpzaanstad.nl/html/app/testmail.js info@belastinghulpzaanstad.nl
 */
const { omgeving } = require('./lib/envbestand');
const { bouw, vervoer } = require('./lib/mail');
const smtp = require('./lib/smtp');
const brevo = require('./lib/brevo');

async function main() {
  const aan = process.argv[2];
  if (!aan || aan.indexOf('@') < 1) {
    console.error('Gebruik: node app/testmail.js uw@adres.nl');
    process.exit(2);
  }
  const env = omgeving();
  const via = vervoer(env);
  if (!via) {
    console.error('NIET INGESTELD: vul in /etc/belastinghulp/app.env MAIL_VAN en SMTP_HOST/SMTP_GEBRUIKER/SMTP_WACHTWOORD in');
    console.error('(of MAIL_VIA=brevo-api met BREVO_API_SLEUTEL). Zie server-setup/APP.md.');
    process.exit(1);
  }
  const onderwerp = 'Proefmail van belastinghulpzaanstad.nl';
  const tekst = 'Deze proefmail komt van de app op de server (' + new Date().toISOString() + ').\nKomt hij aan, dan werken de meldingen.';
  console.log('Versturen via ' + (via.soort === 'api' ? 'de Brevo-API' : 'SMTP ' + via.inst.host + ':' + via.inst.poort) + ' naar ' + aan + ' ...');
  try {
    if (via.soort === 'api') await brevo.verstuur(env, { aan, onderwerp, tekst });
    else await smtp.verstuur(via.inst, { van: env.MAIL_VAN, aan, data: bouw({ van: env.MAIL_VAN, vanNaam: env.MAIL_VAN_NAAM, aan, onderwerp, tekst }) });
    console.log('GELUKT. Kijk in de mailbox van ' + aan + ' (ook bij de ongewenste mail).');
  } catch (e) {
    console.error('MISLUKT: ' + e.message);
    const m = e.message;
    if (/ECONNREFUSED|ETIMEDOUT|kan niet verbinden|geen antwoord/i.test(m)) {
      console.error('-> De server komt er niet door. DigitalOcean blokkeert vaak de mailpoorten. Probeer SMTP_POORT=2525,');
      console.error('   of zet MAIL_VIA=brevo-api met BREVO_API_SLEUTEL (gaat via HTTPS). Zie APP.md, stap 3.');
    } else if (/\b535\b|authent|401|403/i.test(m)) {
      console.error('-> Inloggen lukt niet. SMTP_GEBRUIKER is de "login" uit Brevo (SMTP & API > SMTP),');
      console.error('   SMTP_WACHTWOORD is een SMTP-sleutel (niet uw Brevo-wachtwoord en niet een API-sleutel).');
    } else if (/sender|afzender|not valid|domain/i.test(m)) {
      console.error('-> Brevo kent de afzender nog niet. Controleer in Brevo dat het domein belastinghulpzaanstad.nl geverifieerd is.');
    }
    process.exit(1);
  }
}

main();
