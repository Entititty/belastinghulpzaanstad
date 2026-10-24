'use strict';
/*
 * aanvraag.js — POST /api/aanvraag: elk formulier op de site komt hier binnen.
 *
 * Volgorde: is het van onze eigen site, is het spam, niet te vaak, klopt de
 * invoer, is het geen dubbele klik. Dan opslaan met de toestemmingstekst en
 * de herkomst, en een melding in de mailwachtrij.
 *
 * Zeker spam (honeypot ingevuld, links in de naam) krijgt hetzelfde antwoord
 * als een echte aanvraag, maar wordt niet opgeslagen. Een bot ziet dus geen
 * verschil en past zich niet aan.
 *
 * Misschien spam (binnen 2,5 seconde verstuurd, meer dan één link in de
 * opmerking) wordt WEL opgeslagen, met een markering "verdacht", en de
 * melding krijgt [Controleer] in het onderwerp. Een snelle mens met
 * automatisch invullen mag nooit stilletjes verdwijnen: die ziet de
 * bedankpagina en wacht op een telefoontje.
 *
 * Met JavaScript stuurt formulier.js het formulier en krijgt JSON terug.
 * Zonder JavaScript doet de browser een gewone POST en volgt een 303 naar
 * /bedankt/, of een eenvoudige foutpagina.
 */
const v = require('./valideer');
const http = require('./http');
const { bepaalBron } = require('./bron');
const { meldingAanvraag, esc, label } = require('./berichten');
const { pagina } = require('./pagina');
const { Limiet } = require('./limiet');
const { minMinuten } = require('./tijd');
const { rij } = require('./db');

/* Het voorvoegsel van de toestemmingsversie hoort bij het soort formulier */
const FORMULIEREN = { terugbellen: 'terugbellen-', rekentool: 'rekentool-', bericht: 'bericht-' };
const APPARATEN = ['mobiel', 'tablet', 'computer'];

const FOUTTEKST = {
  formulier: { ongeldig: 'Het formulier is niet compleet. Ververs de pagina en probeer het opnieuw.' },
  naam: { leeg: 'Vul uw naam in.', 'te-lang': 'Uw naam is te lang.', ongeldig: 'Vul uw naam in.' },
  telefoon: { leeg: 'Vul uw telefoonnummer in.', ongeldig: 'Dit telefoonnummer klopt niet. Vul een Nederlands nummer in, bijvoorbeeld 06 12 34 56 78.' },
  email: { leeg: 'Vul uw e-mailadres in.', ongeldig: 'Dit e-mailadres klopt niet. Kijkt u het nog even na?' },
  opmerking: { leeg: 'Schrijf uw vraag in het berichtveld.', 'te-lang': 'Uw bericht is te lang. Maak het iets korter, of bel of app ons.' },
  akkoord: { leeg: 'Vink het vakje aan, dan mogen wij contact met u opnemen.' }
};
const TE_VAAK = 'Er zijn al een paar aanvragen vanaf dit adres verstuurd. Bel of app ons op 06 19 71 18 48, dan helpen wij u direct.';

function controleer(b, cfg) {
  const fouten = {};
  let spam = false;
  const formulier = String(b.formulier || '');
  const versie = String(b.toestemming_versie || '');
  if (!FORMULIEREN[formulier] || !cfg.toestemming[versie] || versie.indexOf(FORMULIEREN[formulier]) !== 0) fouten.formulier = 'ongeldig';

  const n = v.naam(b.naam);
  if (n.fout) fouten.naam = n.fout;
  if (n.spam) spam = true;
  const t = v.telefoon(b.telefoon);
  if (t.fout) fouten.telefoon = t.fout;
  const e = v.email(b.email);
  if (e.fout) fouten.email = e.fout;
  else if (e.leeg && formulier === 'bericht') fouten.email = 'leeg';
  const o = v.tekst(b.opmerking, formulier === 'bericht' ? 2000 : 1000);
  if (o.fout) fouten.opmerking = o.fout;
  else if (!o.waarde && formulier === 'bericht') fouten.opmerking = 'leeg';
  if (!b.akkoord) fouten.akkoord = 'leeg';

  const rekentool = cfg.rekentools[b.rekentool] ? b.rekentool : null;
  const berekening = rekentool ? v.berekening(b.berekening) : null;
  return {
    fouten,
    spam,
    data: {
      formulier,
      versie,
      naam: n.waarde,
      telefoon: t.waarde,
      telefoon_soort: t.soort,
      email: e.waarde || null,
      dienst: cfg.diensten.some((d) => d.code === b.dienst) ? b.dienst : 'onbekend',
      voorkeurstijd: cfg.voorkeurstijden.some((d) => d.code === b.voorkeurstijd) ? b.voorkeurstijd : 'maakt-niet-uit',
      opmerking: o.waarde || null,
      veelLinks: !!o.spam,
      rekentool,
      berekening: berekening ? JSON.stringify(berekening) : null,
      pagina: v.pad(b.h_pagina),
      vorige_pagina: v.pad(b.h_vorige) || null,
      landingspagina: v.pad(b.h_landing) || null,
      verwijzer: v.domein(b.h_verwijzer) || null,
      utm_source: v.campagne(b.h_utm_source) || null,
      utm_medium: v.campagne(b.h_utm_medium) || null,
      utm_campaign: v.campagne(b.h_utm_campaign) || null,
      utm_content: v.campagne(b.h_utm_content) || null,
      ref: v.refCode(b.h_ref) || null,
      apparaat: APPARATEN.includes(b.h_apparaat) ? b.h_apparaat : null
    }
  };
}

async function turnstileOk(token, ip, geheim) {
  if (!token || !geheim) return false;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: new URLSearchParams({ secret: geheim, response: String(token), remoteip: ip })
    });
    const j = await r.json();
    return j.success === true;
  } catch (e) {
    return false;
  }
}

/* Te snel verstuurd: h_duur is het aantal seconden tussen laden en versturen,
 * door formulier.js meegegeven. Ontbreekt het (geen JavaScript), dan geen oordeel. */
function teSnel(b, cfg) {
  if (b.h_duur === undefined || b.h_duur === '') return false;
  const d = Number(b.h_duur);
  return Number.isFinite(d) && d < cfg.spam.min_seconden;
}

function maakAanvraag(ctx) {
  const { db, config: cfg } = ctx;
  const perIp = new Limiet(cfg.spam.max_per_uur_per_ip, 3600e3);

  const invoegen = db.prepare(`INSERT INTO aanvragen (aangemaakt, kanaal, formulier, naam, telefoon, telefoon_soort, email, dienst,
    voorkeurstijd, opmerking, rekentool, berekening, pagina, vorige_pagina, landingspagina, verwijzer, utm_source, utm_medium,
    utm_campaign, utm_content, ref, partner_id, bron, bron_detail, apparaat, verdacht, grondslag, toestemming_versie, toestemming_tekst,
    toestemming_tijd, status, status_tijd, gewijzigd)
    VALUES (:aangemaakt, 'formulier', :formulier, :naam, :telefoon, :telefoon_soort, :email, :dienst, :voorkeurstijd, :opmerking,
    :rekentool, :berekening, :pagina, :vorige_pagina, :landingspagina, :verwijzer, :utm_source, :utm_medium, :utm_campaign,
    :utm_content, :ref, :partner_id, :bron, :bron_detail, :apparaat, :verdacht, 'toestemming', :versie, :toestemming_tekst, :aangemaakt,
    'nieuw', :aangemaakt, :aangemaakt)`);
  invoegen.setAllowUnknownNamedParameters(true);

  return async function aanvraag(req, res) {
    const metJson = http.wilJson(req);
    const gelukt = () => (metJson ? http.json(res, 200, { ok: true, volgende: '/bedankt/' }) : http.doorsturen(res, '/bedankt/'));
    const fout = (status, tekst, velden) => {
      if (metJson) return http.json(res, status, { ok: false, fout: tekst, fouten: velden || undefined });
      const regels = velden ? Object.values(velden).map(esc) : [esc(tekst)];
      return http.html(res, status, pagina(ctx.root, 'Dat lukte nog niet', regels.concat(['Ga terug en pas het aan, of bel of app ons; dan regelen wij het direct.']),
        { terug: v.pad(req.headers.referer) || '/contact/' }));
    };

    if (!http.vanEigenSite(req, ctx.origins)) return fout(403, 'Dit formulier kan alleen vanaf onze eigen site worden verstuurd.');
    const b = await http.leesFormulier(req, 16 * 1024);
    const ip = http.ipVan(req);

    if (b._gotcha) {
      ctx.log('info', 'aanvraag genegeerd: honeypot');
      return gelukt();
    }
    if (!perIp.mag(ip, ctx.klok().getTime())) return fout(429, TE_VAAK);
    if (cfg.turnstile && cfg.turnstile.aan && !(await turnstileOk(b['cf-turnstile-response'], ip, ctx.env.TURNSTILE_GEHEIM))) {
      return fout(400, 'De controle tegen spam is niet gelukt. Ververs de pagina en probeer het opnieuw.');
    }

    const { fouten, spam, data } = controleer(b, cfg);
    if (Object.keys(fouten).length) {
      const teksten = {};
      for (const [veld, code] of Object.entries(fouten)) teksten[veld] = (FOUTTEKST[veld] && FOUTTEKST[veld][code]) || FOUTTEKST.formulier.ongeldig;
      return fout(422, teksten[Object.keys(teksten)[0]], teksten);
    }
    if (spam) {
      ctx.log('info', 'aanvraag genegeerd: link in de naam');
      return gelukt();
    }
    const twijfel = [];
    if (teSnel(b, cfg)) twijfel.push('binnen ' + String(cfg.spam.min_seconden).replace('.', ',') + ' seconde verstuurd');
    if (data.veelLinks) twijfel.push('meerdere links in de opmerking');
    data.verdacht = twijfel.length ? twijfel.join('; ') : null;
    if (!data.pagina) data.pagina = v.pad(req.headers.referer) || null;

    const nu = ctx.klok();
    const dubbel = db.prepare('SELECT id FROM aanvragen WHERE telefoon = ? AND dienst = ? AND aangemaakt > ?')
      .get(data.telefoon, data.dienst, minMinuten(nu, cfg.spam.dubbel_minuten).toISOString());
    if (dubbel) {
      ctx.log('info', 'aanvraag #' + dubbel.id + ' twee keer verstuurd; de tweede genegeerd');
      return gelukt();
    }

    const partner = data.ref ? db.prepare('SELECT id, naam FROM partners WHERE ref_code = ?').get(data.ref) : null;
    const b2 = bepaalBron({
      ref: data.ref, partnerNaam: partner && partner.naam, utm_source: data.utm_source,
      utm_medium: data.utm_medium, utm_campaign: data.utm_campaign, verwijzer: data.verwijzer
    });
    const r = invoegen.run(rij(Object.assign({}, data, {
      aangemaakt: nu.toISOString(),
      partner_id: partner ? partner.id : null,
      bron: b2.bron,
      bron_detail: b2.detail || null,
      toestemming_tekst: cfg.toestemming[data.versie]
    })));
    const id = Number(r.lastInsertRowid);
    ctx.log('info', 'aanvraag #' + id + ': ' + data.formulier + ', ' + data.dienst + ', bron ' + b2.bron);

    const opgeslagen = db.prepare('SELECT * FROM aanvragen WHERE id = ?').get(id);
    if (ctx.env.MAIL_MELDINGEN_AAN) {
      const m = meldingAanvraag(opgeslagen, cfg, ctx.basisUrl);
      ctx.mail.inWachtrij({ soort: 'melding', aan: ctx.env.MAIL_MELDINGEN_AAN, onderwerp: m.onderwerp, tekst: m.tekst, html: m.html, aanvraag_id: id });
    } else {
      ctx.log('fout', 'MAIL_MELDINGEN_AAN ontbreekt in app.env: geen melding voor aanvraag #' + id);
    }
    if (ctx.push) ctx.push('Nieuwe aanvraag: ' + label(cfg.diensten, data.dienst), '/beheer/aanvraag/' + id);
    return gelukt();
  };
}

module.exports = { maakAanvraag, controleer, FOUTTEKST };
