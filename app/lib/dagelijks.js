'use strict';
/*
 * dagelijks.js — de vaste taken van elke dag.
 *
 * - dagoverzicht: de open aanvragen per mail, vlak voor het belvenster
 *   (doordeweeks 17:30, in het weekend 08:30; zie data/aanvraag.json). Ook bij
 *   nul open aanvragen, als teken van leven: komt hij niet, dan is er iets mis.
 * - back-up: elke nacht een kopie van de database (VACUUM INTO), 14 dagen
 *   bewaard. Een verwijderde aanvraag is dus na uiterlijk 14 dagen ook uit de
 *   back-ups weg; zo staat het in het privacybeleid.
 * - klikken inlezen: de dagbestanden van de klikmeting (nginx, /t) tellen per
 *   dag, pagina, knop, bron en campagne, voor het overzicht in /beheer.
 *   Herhaalbaar: een dag wordt elke keer opnieuw geteld, nooit opgeteld.
 */
const fs = require('fs');
const path = require('path');
const dbm = require('./db');
const berichten = require('./berichten');
const { nl, minDagen } = require('./tijd');

function dagoverzicht(ctx) {
  const { db, config: cfg } = ctx;
  if (!ctx.env.MAIL_MELDINGEN_AAN) return null;
  const open = db.prepare(`SELECT * FROM aanvragen WHERE status IN ('nieuw','gebeld','afspraak')
    ORDER BY CASE status WHEN 'nieuw' THEN 0 WHEN 'gebeld' THEN 1 ELSE 2 END, aangemaakt`).all();
  if (!open.length && !cfg.planning.dagoverzicht_ook_als_leeg) return null;
  const nu = ctx.klok();
  const waarschuwingen = [];
  if (!ctx.mail.ingesteld()) waarschuwingen.push('De mail is niet ingesteld; meldingen blijven liggen.');
  const stand = ctx.mail.wachtrijStand();
  if (stand.gestopt) waarschuwingen.push(stand.gestopt + ' mail(s) konden niet worden verstuurd. Kijk in /beheer/status.');
  const laatsteBackup = dbm.instelling(db, 'backup-laatste');
  if (!laatsteBackup || nu.getTime() - new Date(laatsteBackup).getTime() > 2 * 864e5) {
    waarschuwingen.push('Er is ' + (laatsteBackup ? 'al meer dan twee dagen' : 'nog') + ' geen back-up gemaakt. Kijk in /beheer/status.');
  }
  const extra = {
    nieuwSindsGisteren: db.prepare('SELECT COUNT(*) AS n FROM aanvragen WHERE aangemaakt >= ?').get(minDagen(nu, 1).toISOString()).n,
    lijst: db.prepare("SELECT COUNT(*) AS n FROM herinneringen WHERE status = 'bevestigd'").get().n,
    waarschuwingen
  };
  const m = berichten.dagoverzicht(open, extra, cfg, ctx.basisUrl);
  ctx.mail.inWachtrij({ soort: 'dagoverzicht', aan: ctx.env.MAIL_MELDINGEN_AAN, onderwerp: m.onderwerp, tekst: m.tekst, html: m.html });
  ctx.log('info', 'dagoverzicht: ' + open.length + ' open');
  return m;
}

/* "17:30" door de week, "08:30" in het weekend */
function dagoverzichtTijd(cfg) {
  return (t) => (t.weekdag === 0 || t.weekdag === 6 ? cfg.planning.dagoverzicht_weekend : cfg.planning.dagoverzicht_doordeweeks);
}

function backup(ctx) {
  const { db, config: cfg } = ctx;
  const map = ctx.env.BHZ_BACKUP_MAP;
  fs.mkdirSync(map, { recursive: true });
  const naam = 'leads-' + nl(ctx.klok()).datum + '.db';
  const doel = path.join(map, naam);
  if (fs.existsSync(doel)) fs.unlinkSync(doel);
  db.exec("VACUUM INTO '" + doel.replace(/'/g, "''") + "'");
  try { fs.chmodSync(doel, 0o600); } catch (e) { /* Windows */ }
  const grens = nl(minDagen(ctx.klok(), cfg.bewaren.backup_dagen)).datum;
  let weg = 0;
  for (const f of fs.readdirSync(map)) {
    const m = /^leads-(\d{4}-\d{2}-\d{2})\.db$/.exec(f);
    if (m && m[1] < grens) { fs.unlinkSync(path.join(map, f)); weg++; }
  }
  dbm.zetInstelling(db, 'backup-laatste', ctx.klok().toISOString());
  ctx.log('info', 'back-up ' + naam + ' gemaakt; ' + weg + ' oude weg');
  return { naam, weg };
}

/* ---------------- klikmeting inlezen ---------------- */
const EVENTS = ['whatsapp', 'tel', 'mail', 'form_submit', 'form_abandon', 'bezoek', 'rekentool'];
const RE_UUR = /^\d{4}-\d{2}-\d{2}T\d{2}:00$/;
const RE_PAD = /^\/[a-z0-9/._-]{0,80}$/;
const RE_CODE = /^[a-z0-9-]{1,40}$/;

function pad(p) {
  let d = String(p || '');
  try { d = decodeURIComponent(d); } catch (e) { return 'overig'; }
  d = d.toLowerCase();
  return RE_PAD.test(d) ? d : 'overig';
}
function code(x) { return !x ? '' : (RE_CODE.test(x) ? x : 'overig'); }

function klikkenInlezen(ctx) {
  const { db } = ctx;
  const map = ctx.env.BHZ_TELLINGEN_MAP;
  let bestanden;
  try { bestanden = fs.readdirSync(map).filter((n) => /^\d{4}-\d{2}-\d{2}\.ndjson$/.test(n)).sort(); } catch (e) { return { dagen: 0 }; }
  /* de laatste ingelezen dag kan toen nog niet af zijn geweest: die opnieuw, en alles daarna */
  const vanaf = dbm.instelling(db, 'klikken-laatst') || '0000-00-00';
  let dagen = 0, regels = 0, fout = 0, laatste = vanaf;
  for (const naam of bestanden) {
    const dag = naam.slice(0, 10);
    if (dag < vanaf) continue;
    const telling = new Map();
    let tekst;
    try { tekst = fs.readFileSync(path.join(map, naam), 'utf8'); } catch (e) { continue; }
    for (const r of tekst.split('\n')) {
      if (!r.trim()) continue;
      let x;
      try { x = JSON.parse(r); } catch (e) { fout++; continue; }
      if (!RE_UUR.test(x.t || '') || !EVENTS.includes(x.e)) { fout++; continue; }
      const sleutel = [x.e, pad(x.p), code(x.k), code(x.b), code(x.c)].join('\u0001');
      telling.set(sleutel, (telling.get(sleutel) || 0) + 1);
      regels++;
    }
    dbm.transactie(db, () => {
      db.prepare('DELETE FROM klikken WHERE dag = ?').run(dag);
      const zet = db.prepare('INSERT INTO klikken (dag, e, p, k, b, c, n) VALUES (?, ?, ?, ?, ?, ?, ?)');
      for (const [s, n] of telling) zet.run(dag, ...s.split('\u0001'), n);
    });
    dagen++;
    if (dag > laatste) laatste = dag;
  }
  if (laatste !== vanaf) dbm.zetInstelling(db, 'klikken-laatst', laatste);
  ctx.log('info', 'klikken ingelezen: ' + dagen + ' dag(en), ' + regels + ' regels' + (fout ? ', ' + fout + ' overgeslagen' : ''));
  return { dagen, regels, fout };
}

module.exports = { dagoverzicht, dagoverzichtTijd, backup, klikkenInlezen };
