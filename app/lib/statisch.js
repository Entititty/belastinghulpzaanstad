'use strict';
/*
 * statisch.js — alleen voor lokaal testen (node app/server.js --dev).
 *
 * Op de server serveert nginx de pagina's en komt hier alleen /api/ en
 * /beheer/ binnen. Lokaal doet de app beide, zodat je de formulieren met de
 * echte pagina's kunt proberen op één adres. Ongeveer zoals nginx: mappen
 * krijgen index.html, onbekend geeft /404/ met status 404, en de mappen die
 * nginx afschermt, zijn hier ook dicht.
 */
const fs = require('fs');
const path = require('path');

const SOORT = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.avif': 'image/avif', '.woff2': 'font/woff2', '.woff': 'font/woff',
  '.ico': 'image/x-icon', '.xml': 'application/xml; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
  '.vcf': 'text/vcard; charset=utf-8', '.pdf': 'application/pdf'
};
const DICHT = /(^|\/)\.|^\/(app|scripts|server-setup|docs|intern|reports|data\/gsc|data\/tellingen)(\/|$)/;

function maakStatisch(root, log) {
  function stuur(res, status, bestand) {
    res.writeHead(status, { 'Content-Type': SOORT[path.extname(bestand).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    fs.createReadStream(bestand).pipe(res);
  }
  function nietGevonden(res) {
    const f = path.join(root, '404', 'index.html');
    if (fs.existsSync(f)) return stuur(res, 404, f);
    res.writeHead(404); res.end('niet gevonden');
  }
  return function statisch(req, res, url) {
    /* het meetpunt van js/tellingen.js: lokaal alleen tonen */
    if (url.pathname === '/t') {
      log('info', 'meting: ' + url.search);
      res.writeHead(204); return res.end();
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    let p;
    try { p = decodeURIComponent(url.pathname); } catch (e) { return nietGevonden(res); }
    if (DICHT.test(p)) return nietGevonden(res);
    let f = path.join(root, p);
    if (f !== root && !f.startsWith(root + path.sep)) return nietGevonden(res);
    let st = null;
    try { st = fs.statSync(f); } catch (e) { st = null; }
    if (st && st.isDirectory()) {
      if (!p.endsWith('/')) { res.writeHead(301, { Location: p + '/' + url.search }); return res.end(); }
      f = path.join(f, 'index.html');
      try { st = fs.statSync(f); } catch (e) { st = null; }
    }
    if (!st || !st.isFile()) return nietGevonden(res);
    return stuur(res, 200, f);
  };
}

module.exports = { maakStatisch };
