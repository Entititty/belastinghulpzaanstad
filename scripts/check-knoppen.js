#!/usr/bin/env node
/*
 * check-knoppen.js
 * Bewaakt dat de site overal dezelfde twee knoppen gebruikt.
 * Faalt (exit 1) bij een afwijking.
 *
 * WAAROM
 * In oktober 2026 stonden er 193 verschillende knopteksten op de site
 * ("WhatsApp ons", "Afspraak maken →", "Neem contact op", "Claim uw €20
 * korting"...). Nu is er één primaire knop, "Bel of app" (links bellen,
 * rechts WhatsApp, elk één tik), en één secundaire, "Bel mij terug". Al het
 * andere is een gewone tekstlink. Een nieuwe pagina die uit een oude kopie
 * komt, neemt de oude knoppen weer mee; dit script vangt dat.
 *
 * WAT HET CONTROLEERT (pagina's met een meta-refresh tellen niet mee)
 * - geen oude knopklassen meer: btn, btn-*, tarief-btn, nav-cta, wa-float,
 *   mid-cta-phone, mid-cta-wa, en geen groene knop met een inline style
 * - elke "Bel of app" (.boa) heeft een belhelft (tel:+31619711848) en een
 *   WhatsApp-helft (wa.me/31619711848)
 * - "Bel mij terug" (.bmt) heet zo, of "Call me back" in het Engels
 * - verzendknoppen van formulieren: "Bel mij terug" of "Bericht versturen";
 *   voor de herinneringslijst "Stuur mij een herinnering", en op de pagina's
 *   achter de link in de mail "Ja, bevestig mijn aanmelding" en "Afmelden"
 * - andere <button>s alleen voor FAQ, menu, printen en de cookievoorkeur
 *
 * GEBRUIK
 *   node scripts/check-knoppen.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const OUD = /\bclass="[^"]*\b(btn|btn-[a-z]+|tarief-btn|nav-cta|wa-float|mid-cta-phone|mid-cta-wa)\b[^"]*"/;
const BMT = ['Bel mij terug', 'Call me back'];
const VERZEND = ['Bel mij terug', 'Bericht versturen', 'Stuur mij een herinnering', 'Ja, bevestig mijn aanmelding', 'Afmelden'];
const KNOP_OK = /\bclass="[^"]*\b(faq-question|mobile-toggle|cl-print)\b|onclick="window\.bhzResetConsent/;

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['.git', 'node_modules', 'docs', 'reports', 'intern'].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}
const tekst = (s) => s.replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/g, ' ').replace(/\s+/g, ' ').trim();

const fouten = [];
let paginas = 0, paren = 0;
for (const f of walk(ROOT, [])) {
  const ruw = fs.readFileSync(f, 'utf8');
  if (/<meta http-equiv="refresh"/.test(ruw)) continue;
  const rel = path.relative(ROOT, f).split(path.sep).join('/');
  const s = ruw.replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/g, '').replace(/<style[\s\S]*?<\/style>/g, '');
  paginas++;
  const fout = (m) => fouten.push(rel + ': ' + m);

  for (const m of s.matchAll(/<(a|button)\b([^>]*)>([\s\S]*?)<\/\1>/g)) {
    const [, tag, attrs, inhoud] = m;
    const t = tekst(inhoud);
    if (OUD.test(attrs)) fout('oude knop "' + t.slice(0, 40) + '"');
    if (tag === 'a' && /background:\s*#188741/.test(attrs) && !/\bclass="[^"]*\bboa-app\b/.test(attrs)) fout('groene knop met inline style "' + t.slice(0, 40) + '"');
    if (/\bclass="[^"]*\bbmt\b/.test(attrs) && !BMT.includes(t)) fout('tweede knop heet "' + t + '", niet "Bel mij terug"');
    if (tag === 'button') {
      if (/type="submit"/.test(attrs)) { if (!VERZEND.includes(t)) fout('verzendknop heet "' + t + '"'); }
      else if (!KNOP_OK.test(attrs)) fout('onbekende knop "' + t.slice(0, 40) + '"');
    }
  }
  const boa = (s.match(/<span class="boa"/g) || []).length;
  const bel = [...s.matchAll(/<a href="([^"]*)" class="boa-bel"/g)];
  const app = [...s.matchAll(/<a href="([^"]*)" class="boa-app"/g)];
  if (bel.length !== boa || app.length !== boa) fout(boa + 'x "Bel of app", maar ' + bel.length + ' belhelft(en) en ' + app.length + ' WhatsApp-helft(en)');
  bel.forEach((m) => { if (m[1] !== 'tel:+31619711848') fout('belhelft gaat naar ' + m[1]); });
  app.forEach((m) => { if (m[1].indexOf('https://wa.me/31619711848') !== 0) fout('WhatsApp-helft gaat naar ' + m[1]); });
  if (!boa) fout('geen "Bel of app" op de pagina');
  paren += boa;
}

console.log('check-knoppen: ' + paginas + ' pagina\'s, ' + paren + 'x "Bel of app"');
if (fouten.length) {
  console.error('FAIL: ' + fouten.length + ' afwijking(en):');
  fouten.slice(0, 40).forEach((e) => console.error('  - ' + e));
  process.exit(1);
}
console.log('OK: overal dezelfde twee knoppen.');
