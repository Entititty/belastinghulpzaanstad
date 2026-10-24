'use strict';
/*
 * herinnering.js — de lijst "mail mij als de aangifte opengaat".
 *
 * Dubbele opt-in: na aanmelden staat iemand op "wacht" en krijgt een mail
 * met een link. Die link opent een pagina met een knop; pas die knop
 * bevestigt. Een link alleen is niet genoeg, omdat sommige mailscanners alle
 * links in een mail openen. Wie na 7 dagen niet heeft bevestigd, wordt
 * verwijderd (taak "opruimen").
 *
 * Afmelden is wel één klik: de pagina meldt meteen af, en de koppen
 * List-Unsubscribe en List-Unsubscribe-Post laten Gmail en Outlook het met
 * hun eigen knop doen. Afmelden = de rij weg, niet "uitgeschreven" markeren.
 *
 * De links bevatten geen opgeslagen geheim, maar een HMAC over het nummer en
 * het aanmeldmoment met het app-geheim uit app.env. Er staat dus niets in de
 * database waarmee iemand anders links kan maken.
 */
const crypto = require('crypto');
const v = require('./valideer');
const http = require('./http');
const dbm = require('./db');
const berichten = require('./berichten');
const { Limiet } = require('./limiet');
const { pagina } = require('./pagina');
const { vanNl, nl, minDagen } = require('./tijd');

const DAG_MS = 864e5;

function maakHerinnering(ctx) {
  const { db, config: cfg } = ctx;
  const perIp = new Limiet(cfg.spam.max_per_uur_per_ip, 3600e3);

  function hmac(doel, rij) {
    return crypto.createHmac('sha256', ctx.env.BHZ_GEHEIM).update(doel + ':' + rij.id + ':' + rij.aangemaakt).digest('hex').slice(0, 32);
  }
  function token(doel, rij) { return rij.id + '.' + hmac(doel, rij); }
  function zoek(doel, t) {
    const m = /^(\d{1,12})\.([0-9a-f]{32})$/.exec(String(t || ''));
    if (!m) return null;
    const rij = db.prepare('SELECT * FROM herinneringen WHERE id = ?').get(Number(m[1]));
    if (!rij) return null;
    const goed = Buffer.from(hmac(doel, rij));
    return crypto.timingSafeEqual(goed, Buffer.from(m[2])) ? rij : null;
  }
  const link = {
    bevestig: (rij) => ctx.basisUrl + '/herinnering/bevestigen/?t=' + token('bevestig', rij),
    afmelden: (rij) => ctx.basisUrl + '/herinnering/afmelden/?t=' + token('afmelden', rij),
    afmeldenApi: (rij) => ctx.basisUrl + '/api/herinnering/afmelden?t=' + token('afmelden', rij)
  };

  function stuur(soort, rij, m, headers) {
    ctx.mail.inWachtrij({ soort, aan: rij.email, onderwerp: m.onderwerp, tekst: m.tekst, html: m.html, headers, herinnering_id: rij.id });
  }

  /* ---------- POST /api/herinnering ---------- */
  async function aanmelden(req, res) {
    const metJson = http.wilJson(req);
    const gelukt = () => (metJson ? http.json(res, 200, { ok: true })
      : http.html(res, 200, pagina(ctx.root, 'Kijk in uw mail', [
        'Wij hebben u een mail gestuurd. Klik op de knop in die mail om uw aanmelding te bevestigen.',
        'Ziet u niets? Kijk dan ook even bij de ongewenste mail.'])));
    const fout = (status, tekst) => (metJson ? http.json(res, status, { ok: false, fout: tekst })
      : http.html(res, status, pagina(ctx.root, 'Dat lukte nog niet', [berichten.esc(tekst)], { terug: v.pad(req.headers.referer) || '/herinnering/' })));

    if (!http.vanEigenSite(req, ctx.origins)) return fout(403, 'Dit formulier kan alleen vanaf onze eigen site worden verstuurd.');
    const b = await http.leesFormulier(req, 8 * 1024);
    /* Alleen de honeypot. Een tijdval zou hier een snelle mens stil laten
     * verdwijnen; de bevestigingsmail (dubbele opt-in) en de limieten per IP
     * en per adres houden misbruik al tegen. */
    if (b._gotcha) {
      ctx.log('info', 'herinnering genegeerd: honeypot');
      return gelukt();
    }
    if (!perIp.mag(http.ipVan(req), ctx.klok().getTime())) return fout(429, 'Er zijn al een paar aanmeldingen vanaf dit adres verstuurd. Probeer het later nog eens.');
    const versie = String(b.toestemming_versie || '');
    if (versie.indexOf('herinnering-') !== 0 || !cfg.toestemming[versie]) return fout(400, 'Het formulier is niet compleet. Ververs de pagina en probeer het opnieuw.');
    const e = v.email(b.email);
    if (!e.waarde) return fout(422, 'Dit e-mailadres klopt niet. Kijkt u het nog even na?');

    const nu = ctx.klok();
    const nuIso = nu.toISOString();
    const net = (iso) => iso && nu.getTime() - new Date(iso).getTime() < DAG_MS;
    const bestaand = db.prepare('SELECT * FROM herinneringen WHERE email = ?').get(e.waarde);
    if (!bestaand) {
      const r = db.prepare(`INSERT INTO herinneringen (email, status, aangemaakt, toestemming_versie, toestemming_tekst, pagina, laatste_mail)
        VALUES (?, 'wacht', ?, ?, ?, ?, ?)`).run(e.waarde, nuIso, versie, cfg.toestemming[versie], v.pad(b.h_pagina) || v.pad(req.headers.referer) || null, nuIso);
      const rij = db.prepare('SELECT * FROM herinneringen WHERE id = ?').get(Number(r.lastInsertRowid));
      stuur('bevestig', rij, berichten.bevestigHerinnering(link.bevestig(rij), cfg));
      ctx.log('info', 'herinnering #' + rij.id + ': aangemeld, wacht op bevestiging');
    } else if (!net(bestaand.laatste_mail)) {
      /* Al bekend. Hoogstens één mail per dag, zodat niemand met andermans
       * adres een mailbom kan maken. Het antwoord is altijd hetzelfde: zo is
       * niet af te lezen of een adres al op de lijst staat. */
      db.prepare('UPDATE herinneringen SET laatste_mail = ? WHERE id = ?').run(nuIso, bestaand.id);
      if (bestaand.status === 'wacht') stuur('bevestig', bestaand, berichten.bevestigHerinnering(link.bevestig(bestaand), cfg));
      else stuur('al-aangemeld', bestaand, berichten.alAangemeld(link.afmelden(bestaand), cfg));
    }
    return gelukt();
  }

  /* ---------- POST /api/herinnering/bevestig ---------- */
  async function bevestig(req, res) {
    if (!http.vanEigenSite(req, ctx.origins)) return http.json(res, 403, { ok: false });
    const b = await http.leesFormulier(req, 4 * 1024);
    const rij = zoek('bevestig', b.t);
    if (!rij) return http.json(res, 400, { ok: false, fout: 'Deze link werkt niet (meer). Meld u opnieuw aan; dat kan op belastinghulpzaanstad.nl/herinnering/.' });
    if (rij.status === 'wacht') {
      db.prepare("UPDATE herinneringen SET status = 'bevestigd', bevestigd = ? WHERE id = ?").run(ctx.klok().toISOString(), rij.id);
      ctx.log('info', 'herinnering #' + rij.id + ': bevestigd');
    }
    return http.json(res, 200, { ok: true });
  }

  /* ---------- POST /api/herinnering/afmelden ----------
   * Ook het doel van List-Unsubscribe-Post (RFC 8058): Gmail stuurt dan een
   * POST naar de URL uit de kop, met het token in de querystring. */
  async function afmelden(req, res, url) {
    const b = await http.leesFormulier(req, 4 * 1024).catch(() => ({}));
    const rij = zoek('afmelden', b.t || url.searchParams.get('t'));
    if (rij) {
      db.prepare('DELETE FROM herinneringen WHERE id = ?').run(rij.id);
      dbm.log(db, ctx.klok, 'herinnering afgemeld', 'nummer ' + rij.id);
      ctx.log('info', 'herinnering #' + rij.id + ': afgemeld en verwijderd');
    }
    /* Altijd "gelukt": wie al afgemeld was, is nog steeds afgemeld. */
    return http.json(res, 200, { ok: true });
  }

  /* GET op de afmeldlink uit de kop: naar de pagina, die meldt dan af */
  function afmeldenGet(req, res, url) {
    return http.doorsturen(res, '/herinnering/afmelden/?t=' + encodeURIComponent(url.searchParams.get('t') || ''));
  }

  /* ---------- de jaarlijkse ronde ---------- */
  function tekstHash(r) { return crypto.createHash('sha256').update(JSON.stringify([r.onderwerp, r.alineas])).digest('hex'); }
  function goedgekeurd(r) { return dbm.instelling(db, 'herinnering-goedgekeurd-' + r.jaar) === tekstHash(r); }
  function keurGoed(jaar) {
    const r = cfg.herinnering.rondes.find((x) => x.jaar === Number(jaar));
    if (!r) throw new Error('geen ronde voor ' + jaar);
    dbm.zetInstelling(db, 'herinnering-goedgekeurd-' + r.jaar, tekstHash(r));
    dbm.log(db, ctx.klok, 'herinnering goedgekeurd', String(r.jaar));
  }
  /* Een voorbeeld zoals een abonnee hem krijgt, voor /beheer */
  function voorbeeld(jaar) {
    const r = cfg.herinnering.rondes.find((x) => x.jaar === Number(jaar));
    const nep = { id: 0, aangemaakt: ctx.klok().toISOString() };
    return berichten.herinneringRonde(r, cfg, ctx.basisUrl, ctx.basisUrl + '/herinnering/afmelden/?t=voorbeeld', nep.aangemaakt);
  }

  function signaalAanStan(sleutel, onderwerp, regels) {
    if (dbm.instelling(db, sleutel)) return;
    dbm.zetInstelling(db, sleutel, ctx.klok().toISOString());
    if (!ctx.env.MAIL_MELDINGEN_AAN) return;
    const m = berichten.signaal(onderwerp, regels);
    ctx.mail.inWachtrij({ soort: 'signaal', aan: ctx.env.MAIL_MELDINGEN_AAN, onderwerp: m.onderwerp, tekst: m.tekst });
  }

  function ronde() {
    const nu = ctx.klok();
    const vandaag = nl(nu).datum;
    for (const r of cfg.herinnering.rondes) {
      const vanaf = vanNl(r.verstuur_vanaf);
      const tot = new Date(vanaf.getTime() + (cfg.herinnering.venster_dagen || 14) * DAG_MS);
      if (nu >= tot) continue;
      const goed = goedgekeurd(r);
      const beheer = ctx.basisUrl + '/beheer/herinnering';
      if (!goed && nu >= minDagen(vanaf, 7) && nu < vanaf) {
        signaalAanStan('herinnering-vooraf-' + r.jaar, 'Over een week gaat de herinnering ' + r.jaar + ' uit', [
          'Op ' + r.verstuur_vanaf + ' gaat de herinnering "' + r.onderwerp + '" naar de lijst.',
          'Hij gaat pas uit als u de tekst heeft goedgekeurd. Controleer de datums op belastingdienst.nl en keur hem goed in:',
          beheer]);
      }
      if (nu < vanaf) continue;
      if (!goed) {
        signaalAanStan('herinnering-wacht-' + r.jaar + '-' + vandaag, 'De herinnering ' + r.jaar + ' wacht op uw goedkeuring', [
          'De herinnering "' + r.onderwerp + '" had vanaf ' + r.verstuur_vanaf + ' uit mogen gaan, maar de tekst is nog niet goedgekeurd.',
          'Keur hem goed in: ' + beheer]);
        continue;
      }
      const sleutel = 'herinnering-verzonden-' + r.jaar + '-' + vandaag;
      const al = Number(dbm.instelling(db, sleutel) || 0);
      const ruimte = cfg.herinnering.max_per_dag - al;
      if (ruimte <= 0) continue;
      const lijst = db.prepare(`SELECT * FROM herinneringen WHERE status = 'bevestigd' AND (laatst_verstuurd IS NULL OR laatst_verstuurd < ?)
        ORDER BY id LIMIT ?`).all(r.jaar, ruimte);
      if (!lijst.length) {
        const totaal = db.prepare('SELECT COUNT(*) AS n FROM herinneringen WHERE laatst_verstuurd = ?').get(r.jaar).n;
        if (totaal) signaalAanStan('herinnering-klaar-' + r.jaar, 'Herinnering ' + r.jaar + ' is verstuurd', [
          'De herinnering "' + r.onderwerp + '" is in de wachtrij gezet voor ' + totaal + ' adres(sen).']);
        continue;
      }
      dbm.transactie(db, () => {
        for (const rij of lijst) {
          const m = berichten.herinneringRonde(r, cfg, ctx.basisUrl, link.afmelden(rij), rij.bevestigd || rij.aangemaakt);
          stuur('herinnering', rij, m, {
            'List-Unsubscribe': '<' + link.afmeldenApi(rij) + '>',
            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
          });
          db.prepare('UPDATE herinneringen SET laatst_verstuurd = ? WHERE id = ?').run(r.jaar, rij.id);
        }
        dbm.zetInstelling(db, sleutel, al + lijst.length);
      });
      ctx.log('info', 'herinnering ' + r.jaar + ': ' + lijst.length + ' mail(s) in de wachtrij');
    }
  }

  return { aanmelden, bevestig, afmelden, afmeldenGet, ronde, keurGoed, goedgekeurd, voorbeeld, token, link };
}

module.exports = { maakHerinnering };
