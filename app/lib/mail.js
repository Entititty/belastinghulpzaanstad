'use strict';
/*
 * mail.js — de wachtrij voor uitgaande mail, en het opbouwen van een bericht.
 *
 * Elke mail gaat eerst de wachtrij in (tabel "uitgaand") en wordt dan
 * meteen verstuurd. Lukt dat niet, omdat Brevo even plat ligt of de
 * instellingen nog ontbreken, dan blijft hij staan en probeert de app het
 * opnieuw: na 1, 5, 15 en daarna elke 60 minuten, tot 48 uur na het
 * aanmaken. Zo raakt een melding over een aanvraag niet kwijt.
 *
 * Verstuurd = weg uit de wachtrij. De inhoud (naam, telefoonnummer) blijft
 * dus niet in een tweede tabel achter.
 */
const crypto = require('crypto');
const smtp = require('./smtp');
const brevo = require('./brevo');

const WACHT_MINUTEN = [1, 5, 15, 60];
const OPGEVEN_NA_MS = 48 * 3600e3;

function ascii(s) { return /^[\x20-\x7e]*$/.test(s); }

/* RFC 2047: een kop met niet-ASCII als =?UTF-8?B?...?=, in stukken van
 * maximaal 45 bytes zodat elk gecodeerd woord onder de 75 tekens blijft. */
function kopWoord(s) {
  if (ascii(s)) return s;
  const delen = [];
  let huidig = '';
  for (const teken of s) {
    if (Buffer.byteLength(huidig + teken, 'utf8') > 45) { delen.push(huidig); huidig = teken; } else huidig += teken;
  }
  if (huidig) delen.push(huidig);
  return delen.map((d) => '=?UTF-8?B?' + Buffer.from(d, 'utf8').toString('base64') + '?=').join('\r\n ');
}

function adres(naam, email) {
  if (!naam) return email;
  const n = ascii(naam) ? '"' + naam.replace(/["\\]/g, '\\$&') + '"' : kopWoord(naam);
  return n + ' <' + email + '>';
}

function base64Regels(s) {
  return Buffer.from(s, 'utf8').toString('base64').replace(/.{76}(?=.)/g, '$&\r\n');
}

const DAG = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MAAND = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function datumKop(d) {
  const t = (n) => String(n).padStart(2, '0');
  return DAG[d.getUTCDay()] + ', ' + d.getUTCDate() + ' ' + MAAND[d.getUTCMonth()] + ' ' + d.getUTCFullYear() + ' ' +
    t(d.getUTCHours()) + ':' + t(d.getUTCMinutes()) + ':' + t(d.getUTCSeconds()) + ' +0000';
}

/*
 * Het complete bericht als tekst met CRLF. Platte tekst altijd; HTML erbij als
 * multipart/alternative. headers: extra koppen, bijvoorbeeld List-Unsubscribe.
 */
function bouw(o) {
  const domein = o.van.split('@')[1] || 'localhost';
  const koppen = [
    'From: ' + adres(o.vanNaam, o.van),
    'To: ' + o.aan,
    'Subject: ' + kopWoord(o.onderwerp),
    'Date: ' + datumKop(o.datum || new Date()),
    'Message-ID: <' + Date.now().toString(36) + '.' + crypto.randomBytes(8).toString('hex') + '@' + domein + '>',
    'MIME-Version: 1.0'
  ];
  for (const [k, v] of Object.entries(o.headers || {})) koppen.push(k + ': ' + v);
  let romp;
  if (o.html) {
    const grens = '=_bhz_' + crypto.randomBytes(12).toString('hex');
    koppen.push('Content-Type: multipart/alternative; boundary="' + grens + '"');
    romp = '--' + grens + '\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n' +
      base64Regels(o.tekst) + '\r\n--' + grens + '\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n' +
      base64Regels(o.html) + '\r\n--' + grens + '--\r\n';
  } else {
    koppen.push('Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64');
    romp = base64Regels(o.tekst) + '\r\n';
  }
  return koppen.join('\r\n') + '\r\n\r\n' + romp;
}

function smtpInstellingen(env) {
  if (!env.SMTP_HOST || !env.MAIL_VAN) return null;
  return {
    host: env.SMTP_HOST,
    poort: Number(env.SMTP_POORT || 2525),
    gebruiker: env.SMTP_GEBRUIKER || '',
    wachtwoord: env.SMTP_WACHTWOORD || '',
    beveiliging: env.SMTP_BEVEILIGING || undefined
  };
}

/* Hoe de mail de deur uit gaat: de Brevo-API (aanbevolen: alleen daar kan
 * Brevo het volgen per persoon uitzetten, zie brevo.js) of SMTP. null = nog
 * niet ingesteld; de mail blijft dan wachten. */
function vervoer(env) {
  if (env.MAIL_VIA === 'brevo-api') return env.BREVO_API_SLEUTEL && env.MAIL_VAN ? { soort: 'api' } : null;
  const inst = smtpInstellingen(env);
  return inst ? { soort: 'smtp', inst } : null;
}

/* Een foutmelding van een mailserver kan het adres van de ontvanger bevatten.
 * Dat hoort niet in de logs of in de database. */
function zonderAdressen(s) {
  return String(s || '').replace(/[^\s<>"'(),;:]+@[^\s<>"'(),;:]+/g, '[adres]').slice(0, 300);
}

/*
 * ctx: { db, klok, env, log, verstuur? }   verstuur vervangt smtp.verstuur in tests
 */
function maakMailer(ctx) {
  const { db } = ctx;
  let lopend = null;
  let opnieuw = false;

  function inWachtrij(m) {
    const nu = ctx.klok().toISOString();
    const r = db.prepare(`INSERT INTO uitgaand (soort, aan, onderwerp, tekst, html, headers, aanvraag_id, herinnering_id, volgende_poging, aangemaakt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(m.soort, m.aan, m.onderwerp, m.tekst, m.html || null,
      m.headers ? JSON.stringify(m.headers) : null, m.aanvraag_id || null, m.herinnering_id || null, nu, nu);
    setImmediate(() => { verwerk().catch((e) => ctx.log('fout', 'wachtrij: ' + zonderAdressen(e.message))); });
    return Number(r.lastInsertRowid);
  }

  /* Eén ronde tegelijk. Wie tijdens een ronde aanroept, krijgt dezelfde
   * belofte terug en er volgt nog een ronde, zodat een mail die net in de
   * wachtrij kwam niet blijft liggen. */
  function verwerk() {
    if (lopend) { opnieuw = true; return lopend; }
    lopend = (async () => {
      try {
        do {
          opnieuw = false;
          await ronde();
        } while (opnieuw);
      } finally {
        lopend = null;
      }
    })();
    return lopend;
  }

  async function ronde() {
    const via = vervoer(ctx.env);
    if (!via) return;
    const verstuur = ctx.verstuur || smtp.verstuur;
    const gehad = new Set();
    for (;;) {
      const nu = ctx.klok();
      const m = db.prepare('SELECT * FROM uitgaand WHERE gestopt IS NULL AND volgende_poging <= ? ORDER BY id LIMIT 20')
        .all(nu.toISOString()).find((x) => !gehad.has(x.id));
      if (!m) return;
      gehad.add(m.id);
      try {
        const headers = m.headers ? JSON.parse(m.headers) : null;
        if (via.soort === 'api') {
          await brevo.verstuur(ctx.env, { aan: m.aan, onderwerp: m.onderwerp, tekst: m.tekst, html: m.html, headers });
        } else {
          const data = bouw({
            van: ctx.env.MAIL_VAN, vanNaam: ctx.env.MAIL_VAN_NAAM || 'Belastinghulp Zaanstad', aan: m.aan,
            onderwerp: m.onderwerp, tekst: m.tekst, html: m.html, headers, datum: nu
          });
          await verstuur(via.inst, { van: ctx.env.MAIL_VAN, aan: m.aan, data });
        }
        db.prepare('DELETE FROM uitgaand WHERE id = ?').run(m.id);
        ctx.log('info', 'mail verzonden: ' + m.soort + ' #' + m.id);
      } catch (e) {
        const pogingen = m.pogingen + 1;
        const wacht = WACHT_MINUTEN[Math.min(pogingen, WACHT_MINUTEN.length) - 1];
        const volgende = new Date(nu.getTime() + wacht * 6e4).toISOString();
        /* SMTP-code, of 0 bij een verbindingsfout (ECONNREFUSED en dergelijke) */
        const code = typeof e.code === 'number' ? e.code : 0;
        /* 550/551/553: dit adres bestaat niet of wordt geweigerd; opnieuw proberen helpt niet */
        const blijvend = code === 550 || code === 551 || code === 553;
        const opgeven = blijvend || nu.getTime() - new Date(m.aangemaakt).getTime() > OPGEVEN_NA_MS;
        db.prepare('UPDATE uitgaand SET pogingen = ?, volgende_poging = ?, fout = ?, gestopt = ? WHERE id = ?')
          .run(pogingen, volgende, zonderAdressen(e.message), opgeven ? nu.toISOString() : null, m.id);
        ctx.log('fout', 'mail niet verzonden: ' + m.soort + ' #' + m.id + ' (poging ' + pogingen + (opgeven ? ', opgegeven' : '') + '): ' + zonderAdressen(e.message));
        /* Geen verbinding of een tijdelijke fout: de rest heeft nu ook geen kans */
        if (!code || (code >= 400 && code < 500)) return;
      }
    }
  }

  function wachtrijStand() {
    const r = db.prepare('SELECT COUNT(*) AS wacht, SUM(CASE WHEN gestopt IS NOT NULL THEN 1 ELSE 0 END) AS gestopt FROM uitgaand').get();
    return { wacht: r.wacht - (r.gestopt || 0), gestopt: r.gestopt || 0 };
  }

  return { inWachtrij, verwerk, wachtrijStand, ingesteld: () => !!vervoer(ctx.env) };
}

module.exports = { maakMailer, bouw, kopWoord, zonderAdressen, vervoer, smtpInstellingen };
