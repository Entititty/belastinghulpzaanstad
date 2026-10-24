'use strict';
/*
 * smtp.js — een kleine SMTP-client, zonder pakketten.
 *
 * Genoeg voor één verzenddienst (Brevo): verbinden, versleutelen (TLS op 465
 * of STARTTLS op 587), inloggen met AUTH PLAIN of LOGIN, één bericht afleveren.
 * Per bericht een nieuwe verbinding; bij een handvol mails per dag is een
 * open verbinding houden alleen maar iets dat stuk kan gaan.
 *
 * Een onversleutelde verbinding mag alleen naar deze machine zelf: die is er
 * voor de tests (app/test/nep-smtp.js). Naar buiten gaat het altijd via TLS,
 * met controle van het certificaat.
 */
const net = require('net');
const tls = require('tls');

class SmtpFout extends Error {
  constructor(bericht, code) { super(bericht); this.code = code || 0; }
}

function sessie(socket, timeoutMs) {
  let buffer = '';
  let regels = [];
  const klaar = [];
  let wachtend = null;
  let kapot = null;
  let huidig = null;

  function data(stuk) {
    buffer += stuk.toString('utf8');
    let i;
    while ((i = buffer.indexOf('\r\n')) !== -1) {
      const regel = buffer.slice(0, i);
      buffer = buffer.slice(i + 2);
      regels.push(regel);
      if (/^\d{3}(?: |$)/.test(regel)) {
        const antwoord = { code: Number(regel.slice(0, 3)), regels: regels };
        regels = [];
        if (wachtend) { const w = wachtend; wachtend = null; w.resolve(antwoord); } else klaar.push(antwoord);
      }
    }
  }
  function stuk(e) {
    kapot = e || new SmtpFout('verbinding verbroken');
    if (wachtend) { const w = wachtend; wachtend = null; w.reject(kapot); }
  }
  function koppel(s) {
    if (huidig) { huidig.removeListener('data', data); huidig.removeListener('error', stuk); huidig.removeListener('close', sluitStuk); }
    huidig = s;
    s.on('data', data);
    s.on('error', stuk);
    s.on('close', sluitStuk);
    s.setTimeout(timeoutMs, () => s.destroy(new SmtpFout('geen antwoord binnen ' + timeoutMs + ' ms')));
  }
  function sluitStuk() { stuk(new SmtpFout('verbinding gesloten')); }

  function lees() {
    if (klaar.length) return Promise.resolve(klaar.shift());
    if (kapot) return Promise.reject(kapot);
    return new Promise((resolve, reject) => { wachtend = { resolve, reject }; });
  }
  async function opdracht(regel, verwacht, verberg) {
    if (regel !== null) huidig.write(regel + '\r\n');
    const a = await lees();
    const ok = Array.isArray(verwacht) ? verwacht.includes(a.code) : a.code === verwacht;
    if (!ok) {
      const wat = verberg ? '(inloggegevens)' : (regel || '(begroeting)').split(' ')[0];
      throw new SmtpFout('SMTP ' + wat + ': ' + a.regels.join(' | '), a.code);
    }
    return a;
  }
  koppel(socket);
  return { opdracht, koppel, socket: () => huidig };
}

/* Wacht op het event "klaar" van socket s, met een eigen timer */
function wachtOp(s, klaarEvent, timeoutMs, melding) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => s.destroy(new SmtpFout(melding)), timeoutMs);
    function fout(e) { clearTimeout(timer); reject(e); }
    s.once('error', fout);
    s.once(klaarEvent, () => { clearTimeout(timer); s.removeListener('error', fout); resolve(s); });
  });
}

function verbind(host, poort, versleuteld, timeoutMs) {
  const s = versleuteld
    ? tls.connect({ host, port: poort, servername: host })
    : net.connect({ host, port: poort });
  return wachtOp(s, versleuteld ? 'secureConnect' : 'connect', timeoutMs, 'kan niet verbinden met ' + host + ':' + poort);
}

function opwaarderen(socket, host, timeoutMs) {
  return wachtOp(tls.connect({ socket, servername: host }), 'secureConnect', timeoutMs, 'STARTTLS duurde te lang');
}

function lokaal(host) { return host === '127.0.0.1' || host === 'localhost' || host === '::1'; }

/* Regels die met een punt beginnen krijgen er een extra (RFC 5321, 4.5.2) */
function puntjes(data) {
  return data.replace(/\r\n\./g, '\r\n..').replace(/^\./, '..');
}

/*
 * instellingen: { host, poort, gebruiker, wachtwoord, beveiliging: 'tls'|'starttls'|'geen', heloNaam, timeoutMs }
 * bericht:      { van, aan, data }   data is het complete bericht met CRLF
 */
async function verstuur(inst, bericht) {
  const timeoutMs = inst.timeoutMs || 20000;
  const beveiliging = inst.beveiliging || (Number(inst.poort) === 465 ? 'tls' : 'starttls');
  if (beveiliging === 'geen' && !lokaal(inst.host)) throw new SmtpFout('onversleuteld versturen mag alleen naar deze machine zelf');
  const helo = inst.heloNaam || 'belastinghulpzaanstad.nl';

  const socket = await verbind(inst.host, Number(inst.poort), beveiliging === 'tls', timeoutMs);
  const s = sessie(socket, timeoutMs);
  try {
    await s.opdracht(null, 220);
    let ehlo = await s.opdracht('EHLO ' + helo, 250);
    if (beveiliging === 'starttls') {
      if (!ehlo.regels.some((r) => /STARTTLS/i.test(r))) throw new SmtpFout('server biedt geen STARTTLS aan');
      await s.opdracht('STARTTLS', 220);
      s.koppel(await opwaarderen(s.socket(), inst.host, timeoutMs));
      ehlo = await s.opdracht('EHLO ' + helo, 250);
    }
    if (inst.gebruiker) {
      const auth = ehlo.regels.find((r) => /^250[ -]AUTH/i.test(r)) || '';
      if (/\bPLAIN\b/i.test(auth) || !/\bLOGIN\b/i.test(auth)) {
        const token = Buffer.from('\0' + inst.gebruiker + '\0' + inst.wachtwoord, 'utf8').toString('base64');
        await s.opdracht('AUTH PLAIN ' + token, 235, true);
      } else {
        await s.opdracht('AUTH LOGIN', 334);
        await s.opdracht(Buffer.from(inst.gebruiker, 'utf8').toString('base64'), 334, true);
        await s.opdracht(Buffer.from(inst.wachtwoord, 'utf8').toString('base64'), 235, true);
      }
    }
    await s.opdracht('MAIL FROM:<' + bericht.van + '>', 250);
    await s.opdracht('RCPT TO:<' + bericht.aan + '>', [250, 251]);
    await s.opdracht('DATA', 354);
    const data = puntjes(bericht.data.replace(/\r?\n/g, '\r\n'));
    await s.opdracht(data + (data.slice(-2) === '\r\n' ? '' : '\r\n') + '.', 250);
    try { await s.opdracht('QUIT', 221); } catch (e) { /* afgeleverd is afgeleverd */ }
  } finally {
    s.socket().destroy();
  }
}

module.exports = { verstuur, SmtpFout };
