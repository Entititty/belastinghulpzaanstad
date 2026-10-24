'use strict';
/*
 * envbestand.js — /etc/belastinghulp/app.env inlezen voor de losse
 * commando's (testmail, beheer-gebruiker). De dienst zelf krijgt het bestand
 * via systemd (EnvironmentFile); een commando in de terminal niet.
 *
 * Opmaak zoals systemd die leest: SLEUTEL=waarde, # voor commentaar,
 * eventueel met aanhalingstekens om de waarde.
 */
const fs = require('fs');

const STANDAARD = '/etc/belastinghulp/app.env';

function leesEnvBestand(bestand) {
  const f = bestand || process.env.BHZ_ENV_BESTAND || STANDAARD;
  const o = {};
  let tekst;
  try { tekst = fs.readFileSync(f, 'utf8'); } catch (e) { return null; }
  for (const regel of tekst.split(/\r?\n/)) {
    const m = /^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(regel);
    if (!m || regel.trim().startsWith('#')) continue;
    let w = m[2];
    if ((w.startsWith('"') && w.endsWith('"')) || (w.startsWith("'") && w.endsWith("'"))) w = w.slice(1, -1);
    o[m[1]] = w;
  }
  return o;
}

/* process.env aangevuld met het bestand; wat al in de omgeving staat, wint */
function omgeving() {
  return Object.assign({}, leesEnvBestand() || {}, process.env);
}

module.exports = { leesEnvBestand, omgeving, STANDAARD };
