'use strict';
/*
 * brevo.js — mail versturen via de HTTP-API van Brevo.
 *
 * Dit is de aanbevolen route (MAIL_VIA=brevo-api in app.env), om twee redenen:
 *
 * 1. Geen volgen per persoon. Brevo zet in elke mail een volgpixel en leidt
 *    links via een eigen klikteller, ook bij SMTP. Alleen via de API kunnen we
 *    per ontvanger zeggen dat er geen toestemming is (contactPixelTrackingConsent:
 *    false). Brevo telt opens en kliks dan alleen anoniem, in totalen. Daarvoor
 *    moet in Brevo de instelling voor toestemming per contact aanstaan; zonder
 *    die instelling negeert Brevo het veld (zie server-setup/APP.md, stap 4e).
 *    Mensen op de herinneringslijst gaven toestemming voor de herinnering, niet
 *    om gevolgd te worden.
 * 2. Gewone HTTPS (poort 443), die DigitalOcean nooit blokkeert.
 *
 * Alleen via IPv4: api.brevo.com heeft ook IPv6-adressen, en in Brevo staat
 * alleen het IPv4-adres van de server bij Authorized IPs.
 *
 * Fouten krijgen een SMTP-achtige code, zodat de wachtrij in mail.js ze op
 * dezelfde manier behandelt: 0 = geen verbinding of verkeerde sleutel (de rest
 * van de ronde overslaan), 451 = tijdelijk, 550 = dit bericht lukt nooit.
 */
const http = require('http');
const https = require('https');

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* POST met een JSON-body, alleen over IPv4; geeft { status, tekst } */
function post(adres, body, koppen, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(adres);
    const verzoek = (u.protocol === 'http:' ? http : https).request({
      hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, method: 'POST', family: 4,
      headers: Object.assign({ 'Content-Length': Buffer.byteLength(body) }, koppen), timeout: timeoutMs
    }, (res) => {
      let tekst = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { if (tekst.length < 2000) tekst += d; });
      res.on('end', () => resolve({ status: res.statusCode, tekst }));
    });
    verzoek.on('timeout', () => verzoek.destroy(new Error('geen antwoord binnen ' + timeoutMs + ' ms')));
    verzoek.on('error', reject);
    verzoek.end(body);
  });
}

async function verstuur(env, m) {
  const body = {
    sender: { name: env.MAIL_VAN_NAAM || 'Belastinghulp Zaanstad', email: env.MAIL_VAN },
    /* geen toestemming voor volgen: Brevo telt opens en kliks dan alleen anoniem */
    to: [{ email: m.aan, contactPixelTrackingConsent: false }],
    subject: m.onderwerp,
    textContent: m.tekst,
    htmlContent: m.html || '<pre style="font-family:Arial,Helvetica,sans-serif;white-space:pre-wrap">' + esc(m.tekst) + '</pre>'
  };
  if (m.headers) body.headers = m.headers;
  let r;
  try {
    r = await post(env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email', JSON.stringify(body),
      { 'api-key': env.BREVO_API_SLEUTEL, 'Content-Type': 'application/json', Accept: 'application/json' }, 20000);
  } catch (e) {
    const f = new Error('Brevo-API onbereikbaar: ' + e.message);
    f.code = 0;
    throw f;
  }
  if (r.status === 200 || r.status === 201 || r.status === 202) return;
  const f = new Error('Brevo-API ' + r.status + ': ' + r.tekst.slice(0, 200));
  f.code = r.status === 401 || r.status === 403 ? 0 : (r.status === 400 ? 550 : 451);
  throw f;
}

module.exports = { verstuur };
