'use strict';
/*
 * taken.js — wat de app uit zichzelf doet, zonder cron.
 *
 * Twee soorten taken:
 * - "elke": elke zoveel milliseconden (de mailwachtrij, de herinneringsronde)
 * - "om":   één keer per dag, op een Nederlandse kloktijd (opruimen, back-up,
 *           dagoverzicht). Welke dag al gedaan is, staat in de tabel "taken",
 *           zodat een herstart niets dubbel doet.
 *
 * Een "om"-taak loopt alleen binnen twee uur na zijn tijd. Start de app om
 * 22:00 opnieuw, dan komt het dagoverzicht van 17:30 dus niet alsnog.
 */
const dbm = require('./db');
const { nl, minMaanden, minDagen } = require('./tijd');

function maakPlanner(ctx, taken) {
  const laatste = new Map();
  let bezig = false;
  let timer = null;

  function minuten(hhmm) { const [u, m] = hhmm.split(':').map(Number); return u * 60 + m; }

  async function tik() {
    if (bezig) return;
    bezig = true;
    try {
      const nu = ctx.klok();
      const t = nl(nu);
      for (const taak of taken) {
        try {
          if (taak.elkeMs) {
            if (nu.getTime() - (laatste.get(taak.naam) || 0) < taak.elkeMs) continue;
            laatste.set(taak.naam, nu.getTime());
            await taak.doe();
            continue;
          }
          const om = typeof taak.om === 'function' ? taak.om(t) : taak.om;
          if (!om) continue;
          const verschil = minuten(t.tijd) - minuten(om);
          if (verschil < 0 || verschil > (taak.vensterMin || 120)) continue;
          const r = ctx.db.prepare('SELECT laatste FROM taken WHERE naam = ?').get(taak.naam);
          if (r && r.laatste === t.datum) continue;
          ctx.db.prepare('INSERT INTO taken (naam, laatste) VALUES (?, ?) ON CONFLICT(naam) DO UPDATE SET laatste = excluded.laatste')
            .run(taak.naam, t.datum);
          await taak.doe();
        } catch (e) {
          ctx.log('fout', 'taak ' + taak.naam + ': ' + e.message);
        }
      }
    } finally {
      bezig = false;
    }
  }

  return {
    tik,
    start(ms) {
      timer = setInterval(tik, ms || 30e3);
      if (timer.unref) timer.unref();
      setImmediate(tik);
    },
    stop() { if (timer) clearInterval(timer); }
  };
}

/*
 * Bewaartermijnen toepassen:
 * - aanvragen die geen klant werden: weg na 12 maanden (bewaren.aanvraag_maanden)
 * - klanten: weg 7 jaar na "klant sinds" (de fiscale bewaarplicht)
 * - herinneringen die niet bevestigd zijn: weg na 7 dagen
 * - verlopen sessies en mails die het opgaven
 * - mails die nooit weg konden, omdat de mail niet was ingesteld: ook die na
 *   twee dagen plus de termijn voor mislukte mails, want er staan namen en
 *   nummers in (het dagoverzicht hangt aan geen enkele aanvraag)
 * Notities en wachtende mails van een aanvraag gaan mee (ON DELETE CASCADE).
 */
function opruimen(ctx) {
  const { db, config: cfg } = ctx;
  const nu = ctx.klok();
  const b = cfg.bewaren;
  const a = db.prepare("DELETE FROM aanvragen WHERE status != 'klant' AND aangemaakt < ?")
    .run(minMaanden(nu, b.aanvraag_maanden).toISOString()).changes;
  const k = db.prepare("DELETE FROM aanvragen WHERE status = 'klant' AND COALESCE(klant_sinds, aangemaakt) < ?")
    .run(minMaanden(nu, 12 * (b.klant_jaren || 7)).toISOString()).changes;
  const h = db.prepare("DELETE FROM herinneringen WHERE status = 'wacht' AND aangemaakt < ?")
    .run(minDagen(nu, b.herinnering_onbevestigd_dagen).toISOString()).changes;
  const s = db.prepare('DELETE FROM sessies WHERE verloopt < ?').run(nu.toISOString()).changes;
  const m = db.prepare('DELETE FROM uitgaand WHERE (gestopt IS NOT NULL AND gestopt < ?) OR aangemaakt < ?')
    .run(minDagen(nu, b.mislukte_mail_dagen).toISOString(), minDagen(nu, b.mislukte_mail_dagen + 2).toISOString()).changes;
  if (a + k + h + m) {
    dbm.log(db, ctx.klok, 'opgeruimd', a + ' aanvragen, ' + k + ' oude klanten, ' + h + ' onbevestigde herinneringen, ' + m + ' mislukte mails');
  }
  /* het WAL-bestand leegmaken, zodat verwijderde rijen ook daar weg zijn */
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  ctx.log('info', 'opgeruimd: ' + a + ' aanvragen, ' + k + ' klanten, ' + h + ' herinneringen, ' + s + ' sessies, ' + m + ' mails');
  return { aanvragen: a, klanten: k, herinneringen: h, sessies: s, mails: m };
}

module.exports = { maakPlanner, opruimen };
