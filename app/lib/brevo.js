'use strict';
/*
 * brevo.js — mail versturen via de HTTP-API van Brevo in plaats van SMTP.
 *
 * Waarom: DigitalOcean blokkeert op nieuwe accounts de uitgaande mailpoorten
 * 25, 465 en 587. Brevo neemt SMTP ook aan op poort 2525, en dat is de
 * standaard in app.env. Is ook die dicht, dan is dit het vangnet: de API gaat
 * over gewone HTTPS (poort 443). Aanzetten met MAIL_VIA=brevo-api en
 * BREVO_API_SLEUTEL in app.env.
 *
 * Fouten krijgen een SMTP-achtige code, zodat de wachtrij in mail.js ze op
 * dezelfde manier behandelt: 0 = geen verbinding of verkeerde sleutel (de rest
 * van de ronde overslaan), 451 = tijdelijk, 550 = dit bericht lukt nooit.
 */

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function verstuur(env, m) {
  const body = {
    sender: { name: env.MAIL_VAN_NAAM || 'Belastinghulp Zaanstad', email: env.MAIL_VAN },
    to: [{ email: m.aan }],
    subject: m.onderwerp,
    textContent: m.tekst,
    htmlContent: m.html || '<pre style="font-family:Arial,Helvetica,sans-serif;white-space:pre-wrap">' + esc(m.tekst) + '</pre>'
  };
  if (m.headers) body.headers = m.headers;
  let r;
  try {
    r = await fetch(env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': env.BREVO_API_SLEUTEL, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(20000)
    });
  } catch (e) {
    const f = new Error('Brevo-API onbereikbaar: ' + e.message);
    f.code = 0;
    throw f;
  }
  if (r.status === 200 || r.status === 201 || r.status === 202) return;
  const tekst = (await r.text().catch(() => '')).slice(0, 200);
  const f = new Error('Brevo-API ' + r.status + ': ' + tekst);
  f.code = r.status === 401 || r.status === 403 ? 0 : (r.status === 400 ? 550 : 451);
  throw f;
}

module.exports = { verstuur };
