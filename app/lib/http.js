'use strict';
/*
 * http.js — kleine hulpjes rond verzoek en antwoord.
 */

class HttpFout extends Error {
  constructor(status, bericht) { super(bericht || String(status)); this.status = status; }
}

/* De body als tekst, met een maximum. Te groot: 413. */
function leesBody(req, max) {
  return new Promise((resolve, reject) => {
    let lengte = 0;
    const stukken = [];
    req.on('data', (s) => {
      lengte += s.length;
      if (lengte > max) { reject(new HttpFout(413, 'te groot')); req.destroy(); return; }
      stukken.push(s);
    });
    req.on('end', () => resolve(Buffer.concat(stukken).toString('utf8')));
    req.on('error', reject);
  });
}

/* application/x-www-form-urlencoded naar een object; per veld de eerste waarde */
function formulier(tekst) {
  const o = Object.create(null);
  for (const [k, v] of new URLSearchParams(tekst)) if (!(k in o)) o[k] = v;
  return o;
}

async function leesFormulier(req, max) {
  const soort = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (soort !== 'application/x-www-form-urlencoded') throw new HttpFout(415, 'verwacht een formulier');
  return formulier(await leesBody(req, max));
}

const GEEN_CACHE = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

function json(res, status, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }, GEEN_CACHE, extra || {}));
  res.end(body);
}

function html(res, status, body, extra) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }, GEEN_CACHE, extra || {}));
  res.end(body);
}

function doorsturen(res, url, status, extra) {
  res.writeHead(status || 303, Object.assign({ Location: url, 'Content-Length': 0 }, GEEN_CACHE, extra || {}));
  res.end();
}

function wilJson(req) { return /application\/json/i.test(String(req.headers.accept || '')); }

/* Het IP-adres van de bezoeker. Achter nginx staat het in X-Real-IP; die kop
 * geloven we alleen als het verzoek van deze machine zelf komt. */
function ipVan(req) {
  const direct = req.socket.remoteAddress || '';
  const lokaal = direct === '127.0.0.1' || direct === '::1' || direct === '::ffff:127.0.0.1';
  if (lokaal && req.headers['x-real-ip']) return String(req.headers['x-real-ip']);
  return direct;
}

function lokaalVerzoek(req) {
  const direct = req.socket.remoteAddress || '';
  return (direct === '127.0.0.1' || direct === '::1' || direct === '::ffff:127.0.0.1') && !req.headers['x-real-ip'];
}

/* Een POST van een andere site weigeren. Geen Origin-kop (oude browsers,
 * curl op de server) laten we door; de rest moet van onze eigen site komen. */
function vanEigenSite(req, toegestaan) {
  const o = req.headers.origin;
  if (!o || o === 'null') return !o;
  return toegestaan.includes(o);
}

/* Alle cookies van het domein komen mee, ook die van andere scripts. Eentje met
 * een kapotte %-code ("100%") slaan we over; anders zou /beheer niet meer openen. */
function cookies(req) {
  const o = Object.create(null);
  for (const deel of String(req.headers.cookie || '').split(';')) {
    const i = deel.indexOf('=');
    if (i <= 0) continue;
    let w = deel.slice(i + 1).trim();
    try { w = decodeURIComponent(w); } catch (e) { continue; }
    o[deel.slice(0, i).trim()] = w;
  }
  return o;
}

module.exports = { HttpFout, leesBody, leesFormulier, formulier, json, html, doorsturen, wilJson, ipVan, lokaalVerzoek, vanEigenSite, cookies, GEEN_CACHE };
