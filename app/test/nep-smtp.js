'use strict';
/*
 * nep-smtp.js — een mailserver voor de tests en voor lokaal proberen.
 * Neemt alles aan en bewaart de berichten in het geheugen.
 *
 * Los te starten:  node app/test/nep-smtp.js 2525
 * en dan de app met SMTP_HOST=127.0.0.1 SMTP_POORT=2525 SMTP_BEVEILIGING=geen.
 * Elk bericht wordt dan als tekst in de terminal getoond.
 */
const net = require('net');

function startNepSmtp(opties) {
  const o = opties || {};
  const berichten = [];
  const verbindingen = new Set();
  const server = net.createServer((s) => {
    verbindingen.add(s);
    s.on('close', () => verbindingen.delete(s));
    s.setEncoding('utf8');
    let buffer = '';
    let inData = false;
    let huidig = {};
    s.write('220 nep-smtp klaar\r\n');
    s.on('data', (d) => {
      buffer += d;
      for (;;) {
        if (inData) {
          const i = buffer.indexOf('\r\n.\r\n');
          if (i === -1) return;
          huidig.data = buffer.slice(0, i).replace(/\r\n\.\./g, '\r\n.').replace(/^\.\./, '.');
          buffer = buffer.slice(i + 5);
          berichten.push(huidig);
          if (o.toon) console.log('\n===== mail aan ' + huidig.aan + ' =====\n' + leesbaar(huidig.data));
          huidig = {};
          inData = false;
          s.write('250 ok\r\n');
          continue;
        }
        const i = buffer.indexOf('\r\n');
        if (i === -1) return;
        const regel = buffer.slice(0, i);
        buffer = buffer.slice(i + 2);
        const cmd = regel.toUpperCase();
        if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) s.write('250-nep\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n');
        else if (cmd.startsWith('AUTH PLAIN')) { huidig.auth = Buffer.from(regel.slice(11), 'base64').toString('utf8'); s.write('235 ok\r\n'); }
        else if (cmd.startsWith('MAIL FROM:')) { huidig.van = regel.slice(10).replace(/[<>]/g, ''); s.write('250 ok\r\n'); }
        else if (cmd.startsWith('RCPT TO:')) {
          huidig.aan = regel.slice(8).replace(/[<>]/g, '');
          if (o.weiger && o.weiger.includes(huidig.aan)) s.write('550 5.1.1 <' + huidig.aan + '>: onbekende ontvanger\r\n');
          else s.write('250 ok\r\n');
        } else if (cmd === 'DATA') { inData = true; s.write('354 ga je gang\r\n'); }
        else if (cmd === 'QUIT') { s.write('221 dag\r\n'); s.end(); }
        else if (cmd === 'RSET' || cmd === 'NOOP') s.write('250 ok\r\n');
        else s.write('500 onbekend\r\n');
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(o.poort || 0, '127.0.0.1', () => resolve({
      poort: server.address().port,
      berichten,
      sluit: () => new Promise((r) => { for (const s of verbindingen) s.destroy(); server.close(() => r()); })
    }));
  });
}

/* ---- hulpjes om een bericht te lezen ---- */
function koppen(data) {
  const kop = data.split('\r\n\r\n')[0].replace(/\r\n[ \t]+/g, ' ');
  const o = {};
  for (const r of kop.split('\r\n')) {
    const i = r.indexOf(':');
    if (i > 0) o[r.slice(0, i).toLowerCase()] = r.slice(i + 1).trim();
  }
  return o;
}
function decodeerWoord(s) {
  return s.replace(/=\?UTF-8\?B\?([^?]+)\?=\s*/gi, (h, b) => Buffer.from(b, 'base64').toString('utf8')).trim();
}
function deel(data, soort) {
  const re = new RegExp('Content-Type: ' + soort.replace('/', '\\/') + '[^\\r]*\\r\\nContent-Transfer-Encoding: base64\\r\\n\\r\\n([A-Za-z0-9+/=\\r\\n]+)');
  const m = re.exec(data);
  return m ? Buffer.from(m[1].replace(/\r\n/g, ''), 'base64').toString('utf8') : '';
}
function onderwerp(data) { return decodeerWoord(koppen(data).subject || ''); }
function tekst(data) { return deel(data, 'text/plain'); }
function html(data) { return deel(data, 'text/html'); }
function leesbaar(data) { return 'Onderwerp: ' + onderwerp(data) + '\n\n' + tekst(data); }

if (require.main === module) {
  const poort = Number(process.argv[2] || 2525);
  startNepSmtp({ poort, toon: true }).then((s) => console.log('nep-smtp luistert op 127.0.0.1:' + s.poort));
}

module.exports = { startNepSmtp, koppen, onderwerp, tekst, html };
