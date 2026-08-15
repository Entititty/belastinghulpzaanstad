#!/usr/bin/env node
/*
 * gsc-export.js
 * Haalt Search Console-data op en schrijft één CSV per dag naar data/gsc/.
 * Search Console bewaart maar 16 maanden; dit archief bewaart alles.
 *
 * Geen npm-pakketten nodig. De JWT wordt met node:crypto ondertekend.
 *
 * Gebruik:
 *   node scripts/gsc-export.js                 # vult aan tot vandaag
 *   node scripts/gsc-export.js --days 90       # laatste 90 dagen
 *   node scripts/gsc-export.js --from 2026-05-01 --to 2026-05-31
 *   node scripts/gsc-export.js --force         # bestaande dagen overschrijven
 *
 * Sleutel: zet GSC_KEY_FILE, of gebruik het pad hieronder.
 * De sleutel staat BUITEN de repo. Zet hem daar nooit in:
 * de webroot is de repo-root, dus alles in git komt publiek online.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const ROOT = path.resolve(__dirname, '..');
const UIT = path.join(ROOT, 'data', 'gsc');

const KEY_FILE = process.env.GSC_KEY_FILE ||
  path.join(os.homedir(), '.secrets', 'gsc-service-account.json');
const SITE = process.env.GSC_SITE || 'sc-domain:belastinghulpzaanstad.nl';

const SCOPE = 'https://www.googleapis.com/auth/webmasters.readonly';
const ROW_LIMIT = 25000;          // maximum van de API
const VERS_DAGEN = 3;             // laatste dagen altijd opnieuw ophalen: data komt na
const LAG_DAGEN = 2;              // Search Console loopt ~2 dagen achter

/* ---------- argumenten ---------- */
function arg(naam, standaard) {
  const i = process.argv.indexOf('--' + naam);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : standaard;
}
const FORCE = process.argv.indexOf('--force') !== -1;

function dagStr(d) { return d.toISOString().slice(0, 10); }
function plusDagen(d, n) { const x = new Date(d); x.setUTCDate(x.getUTCDate() + n); return x; }

/* ---------- authenticatie ---------- */
function base64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function accessToken(key) {
  const nu = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(JSON.stringify({
    iss: key.client_email,
    scope: SCOPE,
    aud: key.token_uri,
    iat: nu,
    exp: nu + 3600
  }));
  const sig = base64url(
    crypto.createSign('RSA-SHA256').update(header + '.' + claims).sign(key.private_key)
  );
  const jwt = header + '.' + claims + '.' + sig;

  const res = await fetch(key.token_uri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    })
  });
  const body = await res.json();
  if (!res.ok) throw new Error('token halen mislukt (' + res.status + '): ' + JSON.stringify(body));
  return body.access_token;
}

/* ---------- API ---------- */
async function queryDag(token, datum) {
  const url = 'https://searchconsole.googleapis.com/webmasters/v3/sites/' +
    encodeURIComponent(SITE) + '/searchAnalytics/query';

  const rijen = [];
  let startRow = 0;

  for (;;) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        startDate: datum,
        endDate: datum,
        dimensions: ['query', 'page'],
        type: 'web',
        rowLimit: ROW_LIMIT,
        startRow: startRow
      })
    });
    const body = await res.json();
    if (!res.ok) {
      const m = (body.error && body.error.message) || JSON.stringify(body);
      throw new Error('API-fout (' + res.status + ') op ' + datum + ': ' + m);
    }
    const batch = body.rows || [];
    rijen.push.apply(rijen, batch);
    if (batch.length < ROW_LIMIT) break;
    startRow += ROW_LIMIT;
  }
  return rijen;
}

/* ---------- dagtotalen ----------
 * Belangrijk: zodra je de dimensie "query" opvraagt, laat Search Console
 * zeldzame (geanonimiseerde) zoekopdrachten weg. De som over die rijen is
 * dus altijd lager dan de echte totalen. Voor de KPI's halen we daarom
 * apart de totalen per dag op, zonder query-dimensie.
 */
async function queryTotalen(token, van, tot) {
  const url = 'https://searchconsole.googleapis.com/webmasters/v3/sites/' +
    encodeURIComponent(SITE) + '/searchAnalytics/query';
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      startDate: van, endDate: tot,
      dimensions: ['date'], type: 'web', rowLimit: ROW_LIMIT
    })
  });
  const body = await res.json();
  if (!res.ok) {
    const m = (body.error && body.error.message) || JSON.stringify(body);
    throw new Error('API-fout bij totalen (' + res.status + '): ' + m);
  }
  return body.rows || [];
}

function schrijfTotalen(nieuweRijen) {
  const bestand = path.join(UIT, 'totals.csv');
  const perDag = new Map();
  if (fs.existsSync(bestand)) {
    const regels = fs.readFileSync(bestand, 'utf8').trim().split(/\r?\n/).slice(1);
    for (const r of regels) { const c = r.split(','); if (c[0]) perDag.set(c[0], r); }
  }
  for (const r of nieuweRijen) {
    const d = r.keys[0];
    perDag.set(d, [d, r.clicks, r.impressions, (r.ctr || 0).toFixed(6), (r.position || 0).toFixed(2)].join(','));
  }
  const uit = Array.from(perDag.keys()).sort().map(function (d) { return perDag.get(d); });
  fs.mkdirSync(UIT, { recursive: true });
  fs.writeFileSync(bestand, 'date,clicks,impressions,ctr,position\n' + uit.join('\n') + '\n', 'utf8');
  return uit.length;
}

/* ---------- csv ---------- */
function cel(v) {
  const s = String(v === undefined || v === null ? '' : v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function schrijfDag(datum, rijen) {
  const kop = 'date,query,page,clicks,impressions,ctr,position';
  const regels = rijen.map(function (r) {
    return [datum, r.keys[0], r.keys[1], r.clicks, r.impressions,
      (r.ctr || 0).toFixed(6), (r.position || 0).toFixed(2)].map(cel).join(',');
  });
  fs.mkdirSync(UIT, { recursive: true });
  fs.writeFileSync(path.join(UIT, datum + '.csv'), kop + '\n' + regels.join('\n') + (regels.length ? '\n' : ''), 'utf8');
  return regels.length;
}

/* ---------- hoofdprogramma ---------- */
(async function () {
  if (!fs.existsSync(KEY_FILE)) {
    console.error('Sleutelbestand niet gevonden: ' + KEY_FILE);
    console.error('Zet GSC_KEY_FILE naar het juiste pad.');
    process.exit(1);
  }
  const key = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));

  const laatsteBruikbaar = plusDagen(new Date(), -LAG_DAGEN);
  let van, tot;

  if (arg('from')) {
    van = new Date(arg('from') + 'T00:00:00Z');
    tot = new Date(arg('to', dagStr(laatsteBruikbaar)) + 'T00:00:00Z');
  } else if (arg('days')) {
    tot = laatsteBruikbaar;
    van = plusDagen(tot, -(parseInt(arg('days'), 10) - 1));
  } else {
    // Verder waar het archief ophoudt; anders 90 dagen terug.
    fs.mkdirSync(UIT, { recursive: true });
    const bestaand = fs.readdirSync(UIT).filter(function (f) { return /^\d{4}-\d{2}-\d{2}\.csv$/.test(f); }).sort();
    tot = laatsteBruikbaar;
    van = bestaand.length
      ? plusDagen(new Date(bestaand[bestaand.length - 1].slice(0, 10) + 'T00:00:00Z'), -(VERS_DAGEN - 1))
      : plusDagen(tot, -89);
  }

  // Search Console bewaart 16 maanden.
  const grens = plusDagen(new Date(), -480);
  if (van < grens) van = grens;

  console.log('site   : ' + SITE);
  console.log('sleutel: ' + KEY_FILE);
  console.log('periode: ' + dagStr(van) + ' t/m ' + dagStr(tot));

  const token = await accessToken(key);

  let dagen = 0, rijenTotaal = 0, overgeslagen = 0;
  for (let d = new Date(van); d <= tot; d = plusDagen(d, 1)) {
    const datum = dagStr(d);
    const doelBestand = path.join(UIT, datum + '.csv');
    const versDrempel = dagStr(plusDagen(laatsteBruikbaar, -(VERS_DAGEN - 1)));
    if (!FORCE && fs.existsSync(doelBestand) && datum < versDrempel) { overgeslagen++; continue; }

    let rijen;
    try { rijen = await queryDag(token, datum); }
    catch (e) { console.error('  ' + datum + ': ' + e.message); continue; }

    const n = schrijfDag(datum, rijen);
    dagen++; rijenTotaal += n;
    console.log('  ' + datum + '  ' + String(n).padStart(5) + ' rijen');
  }

  // Echte dagtotalen, zonder query-dimensie, dus zonder anonimisatieverlies.
  try {
    const tot2 = await queryTotalen(token, dagStr(van), dagStr(tot));
    const n = schrijfTotalen(tot2);
    console.log('\ntotalen: ' + tot2.length + ' dagen bijgewerkt, ' + n + ' in archief -> data/gsc/totals.csv');
  } catch (e) {
    console.error('\nTotalen ophalen mislukt: ' + e.message);
  }

  console.log('klaar: ' + dagen + ' dagen weggeschreven, ' + rijenTotaal +
    ' rijen, ' + overgeslagen + ' al aanwezig -> data/gsc/');
})().catch(function (e) {
  console.error('\nMislukt: ' + e.message);
  process.exit(1);
});
