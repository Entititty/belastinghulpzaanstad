'use strict';
/*
 * beheer.js — /beheer: de aanvragen opvolgen.
 *
 * Gemaakt voor de telefoon, 's avonds tussen het bellen door: grote knoppen
 * om te bellen of te appen, de status met één tik, een notitie erbij.
 *
 * Alles hier is HTML van de server; er is bijna geen JavaScript. Elke pagina
 * behalve het inlogscherm vraagt een geldige sessie, en elke POST een
 * CSRF-token en een Origin van de eigen site. De CSP staat alleen bestanden
 * van de eigen site toe, geen inline scripts of stijlen.
 *
 * Andere modules (overzicht, partners) voegen hun pagina's toe met
 * beheer.route(...) en gebruiken dezelfde opmaak met beheer.pagina(...).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('./http');
const v = require('./valideer');
const S = require('./sessie');
const dbm = require('./db');
const berichten = require('./berichten');
const { h, veilig } = require('./html');
const { NAMEN, HANDMATIG } = require('./bron');
const { csv, xlsx } = require('./export');
const { leesbaar, minDagen, nl } = require('./tijd');

const STATUSSEN = [['nieuw', 'Nieuw'], ['gebeld', 'Gebeld'], ['afspraak', 'Afspraak'], ['klant', 'Klant'], ['geen-interesse', 'Geen interesse']];
const STATUS_NAAM = Object.fromEntries(STATUSSEN);
const OPEN = ['nieuw', 'gebeld', 'afspraak'];
const KANALEN = [['telefoon', 'Telefoon'], ['whatsapp', 'WhatsApp'], ['email', 'E-mail'], ['anders', 'Anders']];
const KANAAL_NAAM = Object.fromEntries(KANALEN.concat([['formulier', 'Formulier op de site']]));
const MELDINGEN = {
  status: 'Status opgeslagen.', notitie: 'Notitie opgeslagen.', omzet: 'Omzet opgeslagen.', verwijderd: 'De aanvraag is verwijderd.',
  nieuw: 'Aanvraag toegevoegd.', goedgekeurd: 'De herinneringstekst is goedgekeurd. Hij gaat op de ingestelde datum uit.',
  testmail: 'Proefmail staat in de wachtrij. Kijk over een minuut in uw mailbox.', persoonweg: 'Alle gegevens van deze persoon zijn verwijderd.',
  uitgelogd: 'U bent uitgelogd.'
};
const FOUTEN = { omzet: 'Dat bedrag begrijp ik niet. Typ bijvoorbeeld 89 of 89,50.' };
const CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";
const KOPPEN = { 'Content-Security-Policy': CSP, 'X-Robots-Tag': 'noindex, nofollow' };

/* "89", "89,50", "1.234,50", "€ 89" naar centen; null als het niet klopt */
function centen(s) {
  const t = String(s || '').replace(/[€\s]/g, '');
  if (!t) return null;
  if (!/^\d{1,3}(\.\d{3})*(,\d{1,2})?$|^\d+(,\d{1,2})?$/.test(t)) return null;
  const [heel, dec] = t.replace(/\./g, '').split(',');
  return Number(heel) * 100 + (dec ? Number(dec.padEnd(2, '0')) : 0);
}
function euro(c) { return c === null || c === undefined ? '' : '€ ' + (c / 100).toLocaleString('nl-NL', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }

function maakBeheer(ctx) {
  const { db, config: cfg } = ctx;
  const rem = new S.Rem();
  const DUMMY = S.hashWachtwoord(crypto.randomBytes(16).toString('hex'));
  const BESTANDEN = path.join(__dirname, '..', 'beheer');
  const hash = (f) => crypto.createHash('sha1').update(fs.readFileSync(path.join(BESTANDEN, f))).digest('hex').slice(0, 8);
  const VERSIE = { css: hash('stijl.css'), js: hash('beheer.js') };
  const routes = [];
  const label = (lijst, code) => berichten.label(lijst, code);

  /* ---------------- opmaak ---------------- */
  const MENU = [['aanvragen', 'Aanvragen', '/beheer/aanvragen'], ['nieuw', '+ Nieuw', '/beheer/nieuw'], ['overzicht', 'Overzicht', '/beheer/overzicht'],
    ['herinnering', 'Herinnering', '/beheer/herinnering'], ['partners', 'Partners', '/beheer/partners'], ['persoon', 'Privacy', '/beheer/persoon'],
    ['status', 'Status', '/beheer/status']];

  function document(titel, lichaam) {
    return '<!doctype html><html lang="nl"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow">' +
      '<title>' + h`${titel}` + ' · Beheer</title>' +
      '<link rel="stylesheet" href="/beheer/stijl.css?v=' + VERSIE.css + '">' +
      '<script src="/beheer/beheer.js?v=' + VERSIE.js + '" defer></script></head><body>' + lichaam + '</body></html>';
  }

  function pagina(res, sessie, titel, actief, inhoud, o) {
    const opties = o || {};
    const melding = opties.melding ? h`<p class="melding${opties.fout ? ' fout' : ''}" role="${opties.fout ? 'alert' : 'status'}">${opties.melding}</p>` : '';
    /* alleen pagina's die er zijn: overzicht en partners komen uit hun eigen module */
    const bestaat = (href) => routes.some((r) => r.methode === 'GET' && r.patroon.test(href));
    const kop = h`<header class="kop"><a class="merk" href="/beheer/aanvragen">Beheer</a><nav class="menu" aria-label="Beheer">${MENU.filter((m) => bestaat(m[2])).map(([k, t, href]) =>
      h`<a href="${href}"${veilig(k === actief ? ' aria-current="page"' : '')}>${t}</a>`)}</nav>
      <form method="post" action="/beheer/uitloggen" class="uit"><input type="hidden" name="csrf" value="${sessie.csrf}"><button type="submit">Uitloggen</button></form></header>`;
    return http.html(res, opties.status || 200, document(titel, kop + h`<main class="inhoud">${melding}${inhoud}</main>`), KOPPEN);
  }

  function csrfVeld(sessie) { return h`<input type="hidden" name="csrf" value="${sessie.csrf}">`; }
  function terug(res, pad, melding) { return http.doorsturen(res, pad + (melding ? (pad.includes('?') ? '&' : '?') + 'm=' + melding : '')); }
  function melding(url) { return MELDINGEN[url.searchParams.get('m')] || null; }

  /* ---------------- inloggen ---------------- */
  function inlogScherm(res, status, fout, info) {
    return http.html(res, status, document('Inloggen', h`<main class="inhoud"><div class="inlog kaart">
      <h1>Beheer Belastinghulp Zaanstad</h1>
      ${fout ? h`<p class="melding fout" role="alert">${fout}</p>` : ''}${info ? h`<p class="melding" role="status">${info}</p>` : ''}
      <form method="post" action="/beheer/inloggen">
        <label for="naam">Gebruikersnaam</label><input type="text" id="naam" name="naam" autocomplete="username" required autocapitalize="none">
        <label for="wachtwoord">Wachtwoord</label><input type="password" id="wachtwoord" name="wachtwoord" autocomplete="current-password" required>
        <label for="code">Code uit de app (6 cijfers)</label><input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" required>
        <p><button type="submit">Inloggen</button></p>
      </form></div></main>`), KOPPEN);
  }

  async function inloggen(req, res) {
    const ip = http.ipVan(req);
    const nu = ctx.klok().getTime();
    const wacht = rem.wacht(ip, nu);
    if (wacht) return inlogScherm(res, 429, 'Te veel pogingen. Probeer het over ' + Math.ceil(wacht / 60) + ' minuten opnieuw.');
    if (!http.vanEigenSite(req, ctx.origins)) return inlogScherm(res, 403, 'Dit kan alleen vanaf de eigen site.');
    const b = await http.leesFormulier(req, 4096);
    const g = db.prepare('SELECT * FROM gebruikers WHERE naam = ?').get(String(b.naam || '').trim());
    let goed = false;
    if (g) {
      if (S.controleerWachtwoord(b.wachtwoord || '', g.wachtwoord)) {
        const stap = S.totpStap(g.totp_geheim, b.code, nu);
        if (stap >= 0 && stap > Number(g.laatste_code || -1)) {
          goed = true;
          db.prepare('UPDATE gebruikers SET laatste_code = ? WHERE id = ?').run(String(stap), g.id);
        }
      }
    } else {
      S.controleerWachtwoord(b.wachtwoord || '', DUMMY); /* even lang rekenen, ook als de naam niet bestaat */
    }
    if (!goed) {
      const alarm = rem.fout(ip, nu);
      ctx.log('info', 'inloggen mislukt');
      if (alarm && ctx.env.MAIL_MELDINGEN_AAN) {
        const m = berichten.signaal('Veel mislukte inlogpogingen op /beheer', [
          'In het afgelopen uur zijn er 20 of meer mislukte pogingen geweest om in te loggen op /beheer.',
          'Inloggen is daarom 15 minuten voor iedereen dicht. Was u dit niet zelf? Dan probeert iemand binnen te komen;',
          'met alleen een wachtwoord lukt dat niet, want er is ook een code uit uw app nodig.']);
        ctx.mail.inWachtrij({ soort: 'signaal', aan: ctx.env.MAIL_MELDINGEN_AAN, onderwerp: m.onderwerp, tekst: m.tekst });
      }
      return inlogScherm(res, 401, 'Inloggen mislukt. Controleer de naam, het wachtwoord en de code.');
    }
    rem.goed(ip);
    const s = S.maakSessie(db, ctx.klok, g.id, cfg.bewaren.sessie_dagen);
    dbm.log(db, ctx.klok, 'ingelogd', g.naam);
    return http.doorsturen(res, '/beheer/aanvragen', 303, { 'Set-Cookie': S.cookieKop(s.token, s.verloopt) });
  }

  /* ---------------- aanvragen ---------------- */
  function filters(url) {
    const q = url.searchParams;
    const status = q.get('status') || 'open';
    return {
      status: ['open', 'alle'].concat(STATUSSEN.map((x) => x[0])).includes(status) ? status : 'open',
      dienst: cfg.diensten.some((d) => d.code === q.get('dienst')) ? q.get('dienst') : '',
      bron: /^[a-z-]{1,20}$/.test(q.get('bron') || '') ? q.get('bron') : '',
      periode: ['7', '30', '90', '365'].includes(q.get('periode')) ? q.get('periode') : '',
      zoek: String(q.get('q') || '').trim().slice(0, 80)
    };
  }

  function zoekAanvragen(f, limiet) {
    const waar = [];
    const p = [];
    if (f.status === 'open') waar.push("a.status IN ('nieuw','gebeld','afspraak')");
    else if (f.status !== 'alle') { waar.push('a.status = ?'); p.push(f.status); }
    if (f.dienst) { waar.push('a.dienst = ?'); p.push(f.dienst); }
    if (f.bron) { waar.push('a.bron = ?'); p.push(f.bron); }
    if (f.periode) { waar.push('a.aangemaakt >= ?'); p.push(minDagen(ctx.klok(), Number(f.periode)).toISOString()); }
    if (f.zoek) {
      const t = v.telefoon(f.zoek);
      if (t.waarde) { waar.push('a.telefoon = ?'); p.push(t.waarde); }
      else { waar.push('(a.naam LIKE ? OR a.email LIKE ?)'); p.push('%' + f.zoek + '%', '%' + f.zoek.toLowerCase() + '%'); }
    }
    return db.prepare('SELECT a.*, p.naam AS partner_naam FROM aanvragen a LEFT JOIN partners p ON p.id = a.partner_id' +
      (waar.length ? ' WHERE ' + waar.join(' AND ') : '') + ' ORDER BY a.aangemaakt DESC LIMIT ' + Number(limiet || 500)).all(...p);
  }

  function bronTekst(a) { return (NAMEN[a.bron] || a.bron) + (a.bron_detail ? ': ' + a.bron_detail : ''); }
  function tijdKort(code) { return label(cfg.voorkeurstijden, code).replace(/\s*\d.*$/, '').replace(/,/g, '').trim(); }

  function lijstPagina(req, res, url, sessie) {
    const f = filters(url);
    const rijen = zoekAanvragen(f);
    const opties = (lijst, gekozen, leeg) => [h`<option value="">${leeg}</option>`].concat(lijst.map(([c, t]) => h`<option value="${c}"${veilig(c === gekozen ? ' selected' : '')}>${t}</option>`));
    const bronnen = db.prepare('SELECT DISTINCT bron FROM aanvragen ORDER BY bron').all().map((r) => [r.bron, NAMEN[r.bron] || r.bron]);
    const zoekdeel = new URLSearchParams({ status: f.status, dienst: f.dienst, bron: f.bron, periode: f.periode, q: f.zoek }).toString();
    const inhoud = h`<h1>Aanvragen</h1>
      <form method="get" action="/beheer/aanvragen" class="kaart filters" data-direct>
        <div><label for="f-status">Status</label><select id="f-status" name="status">${[['open', 'Open (nieuw, gebeld, afspraak)'], ['alle', 'Alle']].concat(STATUSSEN)
          .map(([c, t]) => h`<option value="${c}"${veilig(c === f.status ? ' selected' : '')}>${t}</option>`)}</select></div>
        <div><label for="f-dienst">Dienst</label><select id="f-dienst" name="dienst">${opties(cfg.diensten.map((d) => [d.code, d.label]), f.dienst, 'Alle diensten')}</select></div>
        <div><label for="f-bron">Bron</label><select id="f-bron" name="bron">${opties(bronnen, f.bron, 'Alle bronnen')}</select></div>
        <div><label for="f-periode">Periode</label><select id="f-periode" name="periode">${opties([['7', 'Laatste 7 dagen'], ['30', 'Laatste 30 dagen'], ['90', 'Laatste 90 dagen'], ['365', 'Laatste jaar']], f.periode, 'Altijd')}</select></div>
        <div><label for="f-q">Zoek naam, nummer of e-mail</label><input type="search" id="f-q" name="q" value="${f.zoek}"></div>
        <div><button type="submit">Toon</button></div>
      </form>
      <p class="rij"><span>${rijen.length} ${rijen.length === 1 ? 'aanvraag' : 'aanvragen'}</span>
        <a class="knop licht" href="/beheer/aanvragen.xlsx?${zoekdeel}">Excel</a><a class="knop licht" href="/beheer/aanvragen.csv?${zoekdeel}">CSV</a></p>
      ${rijen.length ? h`<ul class="lijst">${rijen.map((a) => h`<li><a href="/beheer/aanvraag/${a.id}">
        <span class="badge ${a.status}">${STATUS_NAAM[a.status] || a.status}</span>${a.verdacht ? h`<span class="badge verdacht">Controleer</span>` : ''}
        <span class="naam">${a.naam}</span>
        <div class="sub">${label(cfg.diensten, a.dienst)}${a.voorkeurstijd && a.voorkeurstijd !== 'maakt-niet-uit' ? ' · ' + tijdKort(a.voorkeurstijd) : ''} · ${bronTekst(a)}</div>
        <div class="sub">${v.telefoonWeergave(a.telefoon) || a.email || ''} · ${leesbaar(a.aangemaakt)}</div></a>
        ${a.telefoon ? h`<a class="bel" href="tel:${a.telefoon}">Bel</a>` : ''}</li>`)}</ul>` : h`<p class="kaart">Geen aanvragen met deze keuze.</p>`}`;
    return pagina(res, sessie, 'Aanvragen', 'aanvragen', inhoud, { melding: melding(url) });
  }

  /* ---------------- export ---------------- */
  const KOLOMMEN = [
    ['Nr', 6, 'getal', (a) => a.id], ['Binnen', 17, 0, (a) => tijdNl(a.aangemaakt)], ['Status', 12, 0, (a) => STATUS_NAAM[a.status] || a.status],
    ['Naam', 22, 0, (a) => a.naam], ['Telefoon', 16, 0, (a) => v.telefoonWeergave(a.telefoon)], ['E-mail', 26, 0, (a) => a.email],
    ['Dienst', 22, 0, (a) => label(cfg.diensten, a.dienst)], ['Voorkeur', 22, 0, (a) => label(cfg.voorkeurstijden, a.voorkeurstijd)],
    ['Opmerking', 40, 0, (a) => a.opmerking], ['Kanaal', 12, 0, (a) => KANAAL_NAAM[a.kanaal] || a.kanaal], ['Bron', 16, 0, (a) => NAMEN[a.bron] || a.bron],
    ['Bron detail', 22, 0, (a) => a.bron_detail], ['Pagina', 26, 0, (a) => a.pagina], ['Landingspagina', 26, 0, (a) => a.landingspagina],
    ['Verwijzer', 18, 0, (a) => a.verwijzer], ['utm_source', 12, 0, (a) => a.utm_source], ['utm_medium', 12, 0, (a) => a.utm_medium],
    ['utm_campaign', 18, 0, (a) => a.utm_campaign], ['utm_content', 16, 0, (a) => a.utm_content], ['Partner', 22, 0, (a) => a.partner_naam || a.ref],
    ['Apparaat', 10, 0, (a) => a.apparaat], ['Rekentool', 18, 0, (a) => a.rekentool ? cfg.rekentools[a.rekentool] || a.rekentool : null],
    ['Omzet', 11, 'euro', (a) => (a.omzet_centen === null ? null : a.omzet_centen / 100)], ['Klant sinds', 17, 0, (a) => tijdNl(a.klant_sinds)],
    ['Controleer', 22, 0, (a) => a.verdacht]
  ];
  function tijdNl(iso) { if (!iso) return null; const t = nl(new Date(iso)); return t.datum + ' ' + t.tijd; }
  function tabel(rijen) {
    return { naam: 'Aanvragen', kolommen: KOLOMMEN.map(([kop, breedte, soort]) => ({ kop, breedte, soort: soort || undefined })), rijen: rijen.map((a) => KOLOMMEN.map((k) => k[3](a))) };
  }
  function bestand(res, naam, soort, data) {
    res.writeHead(200, Object.assign({ 'Content-Type': soort, 'Content-Disposition': 'attachment; filename="' + naam + '"', 'Content-Length': Buffer.byteLength(data) }, http.GEEN_CACHE, KOPPEN));
    res.end(data);
  }
  function exporteer(res, url, formaat) {
    const rijen = zoekAanvragen(filters(url), 100000);
    const naam = 'aanvragen-' + nl(ctx.klok()).datum;
    dbm.log(db, ctx.klok, 'export', formaat + ', ' + rijen.length + ' rijen');
    if (formaat === 'csv') return bestand(res, naam + '.csv', 'text/csv; charset=utf-8', csv(tabel(rijen)));
    return bestand(res, naam + '.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', xlsx(tabel(rijen), ctx.klok()));
  }

  /* ---------------- één aanvraag ---------------- */
  function haal(id) {
    return db.prepare('SELECT a.*, p.naam AS partner_naam FROM aanvragen a LEFT JOIN partners p ON p.id = a.partner_id WHERE a.id = ?').get(Number(id));
  }

  function detailPagina(req, res, url, sessie, id) {
    const a = haal(id);
    if (!a) return nietGevonden(res, sessie);
    const notities = db.prepare('SELECT * FROM notities WHERE aanvraag_id = ? ORDER BY tijd DESC, id DESC').all(a.id);
    const reken = a.berekening ? JSON.parse(a.berekening) : null;
    const voornaam = String(a.naam).split(' ')[0];
    const groet = 'Goedendag ' + voornaam + ', u vroeg om teruggebeld te worden. Wanneer komt het u uit? Groet, Stan (Belastinghulp Zaanstad)';
    const kanWa = a.telefoon && (a.telefoon_soort === 'mobiel' || a.telefoon_soort === 'buitenland' || !a.telefoon_soort);
    const gegevens = [
      ['Telefoon', v.telefoonWeergave(a.telefoon) + (a.telefoon_soort === 'vast' ? ' (vast)' : a.telefoon_soort === 'buitenland' ? ' (buitenland)' : '')],
      ['E-mail', a.email], ['Waarover', label(cfg.diensten, a.dienst)], ['Voorkeur', label(cfg.voorkeurstijden, a.voorkeurstijd)],
      ['Opmerking', a.opmerking], ['Binnen', leesbaar(a.aangemaakt) + ' via ' + (KANAAL_NAAM[a.kanaal] || a.kanaal)],
      ['Klant sinds', a.klant_sinds ? leesbaar(a.klant_sinds) : null], ['Omzet', a.omzet_centen !== null ? euro(a.omzet_centen) : null]
    ].filter((r) => r[1]);
    const herkomst = [
      ['Bron', bronTekst(a)], ['Partner', a.partner_naam || a.ref], ['Pagina', a.pagina], ['Vorige pagina', a.vorige_pagina],
      ['Landingspagina', a.landingspagina], ['Verwijzer', a.verwijzer],
      ['Campagne', [a.utm_source, a.utm_medium, a.utm_campaign, a.utm_content].filter(Boolean).join(' / ')], ['Apparaat', a.apparaat]
    ].filter((r) => r[1]);
    const dl = (rijen) => h`<dl class="gegevens">${rijen.map(([k, w]) => h`<dt>${k}</dt><dd>${w}</dd>`)}</dl>`;
    const inhoud = h`<p><a href="/beheer/aanvragen">&larr; Alle aanvragen</a></p>
      <h1><span class="badge ${a.status}">${STATUS_NAAM[a.status]}</span>${a.naam}</h1>
      ${a.verdacht ? h`<p class="melding fout">Misschien spam: ${a.verdacht}. Kijk even of het echt lijkt voordat u belt.</p>` : ''}
      <div class="bel-rij">${a.telefoon ? h`<a class="knop" href="tel:${a.telefoon}">Bel ${v.telefoonWeergave(a.telefoon)}</a>` : ''}
        ${kanWa ? h`<a class="knop wa" href="${berichten.waLink(a.telefoon, groet)}" rel="noopener">WhatsApp</a>` : ''}
        ${a.email ? h`<a class="knop licht" href="mailto:${a.email}">Mail</a>` : ''}</div>
      <form method="post" action="/beheer/aanvraag/${a.id}/status" class="kaart">${csrfVeld(sessie)}
        <h2>Status</h2><div class="status-knoppen">${STATUSSEN.map(([c, t]) => h`<button type="submit" name="status" value="${c}" aria-pressed="${c === a.status ? 'true' : 'false'}">${t}</button>`)}</div>
      </form>
      ${a.status === 'klant' ? h`<form method="post" action="/beheer/aanvraag/${a.id}/omzet" class="kaart">${csrfVeld(sessie)}
        <label for="omzet">Omzet in euro's</label><div class="rij"><input type="text" id="omzet" name="omzet" inputmode="decimal" value="${a.omzet_centen !== null ? (a.omzet_centen / 100).toFixed(2).replace('.', ',') : ''}"><button type="submit">Opslaan</button></div>
      </form>` : ''}
      <section class="kaart"><h2>Notities</h2>
        ${notities.length ? h`<ul class="notities">${notities.map((n) => h`<li><time>${leesbaar(n.tijd)}</time>${n.tekst}</li>`)}</ul>` : ''}
        <form method="post" action="/beheer/aanvraag/${a.id}/notitie">${csrfVeld(sessie)}
          <label for="notitie">Nieuwe notitie</label><textarea id="notitie" name="tekst" required maxlength="4000"></textarea>
          <p><button type="submit">Notitie opslaan</button></p></form></section>
      <section class="kaart"><h2>Gegevens</h2>${dl(gegevens)}</section>
      ${reken ? h`<section class="kaart"><h2>Rekentool: ${cfg.rekentools[a.rekentool] || a.rekentool || ''}</h2>
        ${reken.tekst ? h`<p>${reken.tekst}</p>` : dl((reken.invoer || []).concat(reken.uitkomst || []))}</section>` : ''}
      <section class="kaart"><h2>Herkomst</h2>${dl(herkomst)}</section>
      <section class="kaart"><h2>Toestemming</h2>${a.grondslag === 'toestemming'
        ? dl([['Versie', a.toestemming_versie], ['Tekst', a.toestemming_tekst], ['Gegeven', leesbaar(a.toestemming_tijd)]])
        : h`<p>${a.grondslag}.</p>`}</section>
      <section class="kaart"><h2>Privacy</h2><div class="rij">
        <a class="knop licht" href="/beheer/persoon?q=${encodeURIComponent(a.telefoon || a.email || '')}">Alle gegevens van deze persoon</a>
        <form method="post" action="/beheer/aanvraag/${a.id}/verwijderen" data-bevestig="Deze aanvraag met alle notities verwijderen? Dat kan niet ongedaan worden.">${csrfVeld(sessie)}<button type="submit" class="gevaar">Verwijderen</button></form>
      </div></section>`;
    const fout = FOUTEN[url.searchParams.get('fout')];
    return pagina(res, sessie, a.naam, 'aanvragen', inhoud, fout ? { melding: fout, fout: true, status: 422 } : { melding: melding(url) });
  }

  function zetStatus(res, sessie, id, b) {
    const a = haal(id);
    if (!a) return nietGevonden(res, sessie);
    const status = String(b.status || '');
    if (!STATUS_NAAM[status]) return terug(res, '/beheer/aanvraag/' + a.id);
    if (status !== a.status) {
      const nu = ctx.klok().toISOString();
      dbm.transactie(db, () => {
        db.prepare(`UPDATE aanvragen SET status = ?, status_tijd = ?, gewijzigd = ?,
          klant_sinds = CASE WHEN ? = 'klant' AND klant_sinds IS NULL THEN ? ELSE klant_sinds END WHERE id = ?`).run(status, nu, nu, status, nu, a.id);
        db.prepare('INSERT INTO notities (aanvraag_id, tijd, tekst) VALUES (?, ?, ?)').run(a.id, nu, 'Status: ' + STATUS_NAAM[a.status] + ' → ' + STATUS_NAAM[status]);
      });
    }
    return terug(res, '/beheer/aanvraag/' + a.id, 'status');
  }

  function voegNotitieToe(res, sessie, id, b) {
    const a = haal(id);
    if (!a) return nietGevonden(res, sessie);
    const t = v.tekst(b.tekst, 4000);
    if (t.waarde) {
      const nu = ctx.klok().toISOString();
      db.prepare('INSERT INTO notities (aanvraag_id, tijd, tekst) VALUES (?, ?, ?)').run(a.id, nu, t.waarde);
      db.prepare('UPDATE aanvragen SET gewijzigd = ? WHERE id = ?').run(nu, a.id);
    }
    return terug(res, '/beheer/aanvraag/' + a.id, 'notitie');
  }

  function zetOmzet(res, sessie, id, b) {
    const a = haal(id);
    if (!a) return nietGevonden(res, sessie);
    const c = centen(b.omzet);
    if (c === null && String(b.omzet || '').trim()) return http.doorsturen(res, '/beheer/aanvraag/' + a.id + '?fout=omzet');
    db.prepare('UPDATE aanvragen SET omzet_centen = ?, gewijzigd = ? WHERE id = ?').run(c, ctx.klok().toISOString(), a.id);
    return terug(res, '/beheer/aanvraag/' + a.id, 'omzet');
  }

  function verwijder(res, sessie, id) {
    const a = haal(id);
    if (!a) return nietGevonden(res, sessie);
    db.prepare('DELETE FROM aanvragen WHERE id = ?').run(a.id);
    dbm.log(db, ctx.klok, 'aanvraag verwijderd', 'nummer ' + a.id);
    return terug(res, '/beheer/aanvragen', 'verwijderd');
  }

  /* ---------------- handmatig toevoegen ---------------- */
  function nieuwFormulier(res, sessie, waarden, fouten) {
    const w = waarden || {};
    const f = fouten || {};
    const partners = db.prepare("SELECT id, naam FROM partners WHERE status != 'gestopt' ORDER BY naam").all();
    const kies = (naam, lijst, gekozen) => lijst.map(([c, t]) => h`<option value="${c}"${veilig(String(c) === String(gekozen || '') ? ' selected' : '')}>${t}</option>`);
    const fout = (veld) => (f[veld] ? h`<p class="melding fout">${f[veld]}</p>` : '');
    const inhoud = h`<h1>Aanvraag toevoegen</h1>
      <p>Voor wie belde, appte of mailde. De bewaartermijn van ${cfg.bewaren.aanvraag_maanden} maanden geldt ook hier.</p>
      <form method="post" action="/beheer/nieuw" class="kaart">${csrfVeld(sessie)}
        <label for="n-naam">Naam</label><input type="text" id="n-naam" name="naam" required maxlength="80" value="${w.naam || ''}">${fout('naam')}
        <label for="n-tel">Telefoonnummer</label><input type="tel" id="n-tel" name="telefoon" maxlength="32" value="${w.telefoon || ''}">${fout('telefoon')}
        <label for="n-email">E-mailadres</label><input type="email" id="n-email" name="email" maxlength="254" value="${w.email || ''}">${fout('email')}
        <label for="n-kanaal">Hoe nam deze persoon contact op?</label><select id="n-kanaal" name="kanaal">${kies('kanaal', KANALEN, w.kanaal)}</select>
        <label for="n-dienst">Waarover</label><select id="n-dienst" name="dienst">${kies('dienst', cfg.diensten.map((d) => [d.code, d.label]), w.dienst)}</select>
        <label for="n-hoe">Hoe kent deze persoon ons?</label><select id="n-hoe" name="hoe">${kies('hoe', HANDMATIG.map((c) => [c, NAMEN[c] || c]), w.hoe)}</select>
        ${partners.length ? h`<label for="n-partner">Doorverwezen door (partner)</label><select id="n-partner" name="partner"><option value="">Geen</option>${kies('partner', partners.map((p) => [p.id, p.naam]), w.partner)}</select>` : ''}
        <label for="n-opm">Opmerking</label><textarea id="n-opm" name="opmerking" maxlength="2000">${w.opmerking || ''}</textarea>
        <p><button type="submit">Toevoegen</button></p>
      </form>`;
    return pagina(res, sessie, 'Aanvraag toevoegen', 'nieuw', inhoud, Object.keys(f).length ? { melding: 'Controleer de velden hieronder.', fout: true, status: 422 } : {});
  }

  function maakNieuw(res, sessie, b) {
    const fouten = {};
    const n = v.naam(b.naam);
    if (n.fout) fouten.naam = 'Vul een naam in.';
    let t = { waarde: null, soort: null };
    if (String(b.telefoon || '').trim()) { t = v.telefoon(b.telefoon); if (t.fout) fouten.telefoon = 'Dit telefoonnummer klopt niet.'; }
    const e = v.email(b.email);
    if (e.fout) fouten.email = 'Dit e-mailadres klopt niet.';
    if (!t.waarde && !e.waarde && !fouten.telefoon && !fouten.email) fouten.telefoon = 'Vul een telefoonnummer of e-mailadres in.';
    if (Object.keys(fouten).length) return nieuwFormulier(res, sessie, b, fouten);
    const kanaal = KANALEN.some((k) => k[0] === b.kanaal) ? b.kanaal : 'anders';
    const dienst = cfg.diensten.some((d) => d.code === b.dienst) ? b.dienst : 'onbekend';
    const partner = b.partner ? db.prepare('SELECT id, naam, ref_code FROM partners WHERE id = ?').get(Number(b.partner)) : null;
    const hoe = HANDMATIG.includes(b.hoe) ? b.hoe : 'anders';
    const nu = ctx.klok().toISOString();
    const r = db.prepare(`INSERT INTO aanvragen (aangemaakt, kanaal, formulier, naam, telefoon, telefoon_soort, email, dienst, voorkeurstijd,
      opmerking, ref, partner_id, bron, bron_detail, grondslag, status, status_tijd, gewijzigd)
      VALUES (?, ?, NULL, ?, ?, ?, ?, ?, 'maakt-niet-uit', ?, ?, ?, ?, ?, 'zelf contact opgenomen', 'nieuw', ?, ?)`).run(
      nu, kanaal, n.waarde, t.waarde || null, t.soort || null, e.waarde || null, dienst, v.tekst(b.opmerking, 2000).waarde || null,
      partner ? partner.ref_code : null, partner ? partner.id : null, partner ? 'partner' : hoe, partner ? partner.naam : null, nu, nu);
    dbm.log(db, ctx.klok, 'aanvraag toegevoegd', 'nummer ' + r.lastInsertRowid + ', ' + kanaal);
    return terug(res, '/beheer/aanvraag/' + r.lastInsertRowid, 'nieuw');
  }

  /* ---------------- privacy: alles van één persoon ---------------- */
  function zoekPersoon(q) {
    const s = String(q || '').trim();
    const t = v.telefoon(s);
    const e = v.email(s);
    if (t.waarde) {
      return {
        wat: v.telefoonWeergave(t.waarde), aanvragen: db.prepare('SELECT * FROM aanvragen WHERE telefoon = ? ORDER BY aangemaakt').all(t.waarde), herinneringen: [],
        partners: db.prepare('SELECT * FROM partners WHERE telefoon = ?').all(t.waarde)
      };
    }
    if (e.waarde) {
      return {
        wat: e.waarde,
        aanvragen: db.prepare('SELECT * FROM aanvragen WHERE email = ? ORDER BY aangemaakt').all(e.waarde),
        herinneringen: db.prepare('SELECT * FROM herinneringen WHERE email = ?').all(e.waarde),
        partners: db.prepare('SELECT * FROM partners WHERE email = ?').all(e.waarde)
      };
    }
    return null;
  }

  function persoonPagina(res, url, sessie) {
    const q = url.searchParams.get('q') || '';
    const r = q ? zoekPersoon(q) : null;
    const inhoud = h`<h1>Privacy: alle gegevens van één persoon</h1>
      <p>Vraagt iemand welke gegevens wij hebben, of om alles te verwijderen? Zoek op telefoonnummer of e-mailadres. U moet binnen een maand antwoorden.</p>
      <form method="get" action="/beheer/persoon" class="kaart rij"><label for="p-q" class="verborgen">Telefoon of e-mail</label>
        <input type="search" id="p-q" name="q" value="${q}" placeholder="06 12 34 56 78 of naam@voorbeeld.nl"><button type="submit">Zoek</button></form>
      ${q && !r ? h`<p class="melding fout">Vul een geldig telefoonnummer of e-mailadres in.</p>` : ''}
      ${r ? h`<section class="kaart"><h2>Gevonden voor ${r.wat}</h2>
        <p>${r.aanvragen.length} aanvraag/aanvragen, ${r.herinneringen.length} inschrijving(en) op de herinneringslijst en ${r.partners.length} keer contactpersoon bij een partner.</p>
        ${r.aanvragen.length ? h`<ul>${r.aanvragen.map((a) => h`<li><a href="/beheer/aanvraag/${a.id}">${a.naam}</a>, ${leesbaar(a.aangemaakt)}, ${STATUS_NAAM[a.status]}</li>`)}</ul>` : ''}
        ${r.herinneringen.length ? h`<ul>${r.herinneringen.map((x) => h`<li>Herinneringslijst: ${x.status === 'bevestigd' ? 'bevestigd' : 'nog niet bevestigd'}, aangemeld ${leesbaar(x.aangemaakt)}</li>`)}</ul>` : ''}
        ${r.partners.length ? h`<ul>${r.partners.map((p) => h`<li>Contactpersoon bij partner <a href="/beheer/partner/${p.id}">${p.naam}</a>${p.contactpersoon ? ' (' + p.contactpersoon + ')' : ''}</li>`)}</ul>
          <p class="klein">Bij een partner wist "Alles verwijderen" de contactpersoon, het nummer, het e-mailadres en de notities; de organisatie zelf blijft.</p>` : ''}
        ${r.aanvragen.length + r.herinneringen.length + r.partners.length ? h`<div class="rij">
          <a class="knop licht" href="/beheer/persoon.json?q=${encodeURIComponent(q)}">Exporteer (JSON)</a>
          <a class="knop licht" href="/beheer/persoon.csv?q=${encodeURIComponent(q)}">Exporteer (CSV)</a>
          <form method="post" action="/beheer/persoon/verwijderen" data-bevestig="Alle gegevens van deze persoon verwijderen? Dat kan niet ongedaan worden. Klanten met een lopende bewaarplicht: eerst nagaan!">${csrfVeld(sessie)}
            <input type="hidden" name="q" value="${q}"><button type="submit" class="gevaar">Alles verwijderen</button></form></div>` : ''}
      </section>` : ''}`;
    return pagina(res, sessie, 'Privacy', 'persoon', inhoud, { melding: melding(url) });
  }

  function persoonExport(res, url, formaat) {
    const q = url.searchParams.get('q') || '';
    const r = zoekPersoon(q);
    if (!r) return http.json(res, 400, { ok: false, fout: 'geen geldig nummer of e-mailadres' });
    const datum = nl(ctx.klok()).datum;
    dbm.log(db, ctx.klok, 'privacy-export', formaat + ': ' + r.aanvragen.length + ' aanvragen, ' + r.herinneringen.length + ' herinneringen, ' + r.partners.length + ' partnercontacten');
    if (formaat === 'json') {
      const data = {
        gemaakt: ctx.klok().toISOString(), door: 'Belastinghulp Zaanstad', gezocht_op: r.wat,
        aanvragen: r.aanvragen.map((a) => Object.assign({}, a, {
          berekening: a.berekening ? JSON.parse(a.berekening) : null,
          notities: db.prepare('SELECT tijd, tekst FROM notities WHERE aanvraag_id = ? ORDER BY tijd').all(a.id)
        })),
        herinneringslijst: r.herinneringen,
        contactpersoon_bij_partner: r.partners.map((p) => ({ organisatie: p.naam, contactpersoon: p.contactpersoon, telefoon: p.telefoon, email: p.email,
          notities: p.notities, status: p.status, sinds: p.aangemaakt }))
      };
      return bestand(res, 'gegevens-' + datum + '.json', 'application/json; charset=utf-8', JSON.stringify(data, null, 2));
    }
    const rijen = r.aanvragen.map((a) => Object.assign({}, a, { partner_naam: null }));
    return bestand(res, 'gegevens-' + datum + '.csv', 'text/csv; charset=utf-8', csv(tabel(rijen)));
  }

  function persoonVerwijderen(res, sessie, b) {
    const r = zoekPersoon(b.q);
    if (!r) return terug(res, '/beheer/persoon');
    dbm.transactie(db, () => {
      for (const a of r.aanvragen) db.prepare('DELETE FROM aanvragen WHERE id = ?').run(a.id);
      for (const x of r.herinneringen) db.prepare('DELETE FROM herinneringen WHERE id = ?').run(x.id);
      for (const p of r.partners) {
        db.prepare('UPDATE partners SET contactpersoon = NULL, telefoon = NULL, email = NULL, notities = NULL, gewijzigd = ? WHERE id = ?').run(ctx.klok().toISOString(), p.id);
      }
    });
    dbm.log(db, ctx.klok, 'privacy-verwijderd', r.aanvragen.length + ' aanvragen, ' + r.herinneringen.length + ' herinneringen, ' + r.partners.length + ' partnercontacten');
    return terug(res, '/beheer/persoon', 'persoonweg');
  }

  /* ---------------- herinnering ---------------- */
  function herinneringPagina(res, url, sessie) {
    const telling = db.prepare("SELECT SUM(status = 'bevestigd') AS bevestigd, SUM(status = 'wacht') AS wacht FROM herinneringen").get();
    const rondes = cfg.herinnering.rondes.map((r) => {
      const goed = ctx.herinnering.goedgekeurd(r);
      const ooit = dbm.instelling(db, 'herinnering-goedgekeurd-' + r.jaar);
      const verstuurd = db.prepare('SELECT COUNT(*) AS n FROM herinneringen WHERE laatst_verstuurd = ?').get(r.jaar).n;
      const m = ctx.herinnering.voorbeeld(r.jaar);
      return h`<section class="kaart"><h2>Ronde ${r.jaar}: aangifte over ${r.aangiftejaar}</h2>
        <p>Gaat uit vanaf <strong>${r.verstuur_vanaf}</strong>, maximaal ${cfg.herinnering.max_per_dag} per dag. Al verstuurd: ${verstuurd}.</p>
        <p>${goed ? h`<span class="badge klant">Goedgekeurd</span>` : ooit ? h`<span class="badge verdacht">Tekst gewijzigd na goedkeuren: opnieuw goedkeuren</span>` : h`<span class="badge nieuw">Nog niet goedgekeurd</span>`}</p>
        <p><strong>Onderwerp:</strong> ${m.onderwerp}</p>
        <pre class="mail">${m.tekst}</pre>
        <p class="rij"><a class="knop licht" href="/beheer/herinnering/${r.jaar}/voorbeeld" target="_blank" rel="noopener">Bekijk de mail zoals hij aankomt</a></p>
        ${goed ? '' : h`<form method="post" action="/beheer/herinnering/${r.jaar}/goedkeuren" data-bevestig="Klopt de tekst, ook de datums? Controleer ze op belastingdienst.nl.">${csrfVeld(sessie)}
          <button type="submit">Tekst goedkeuren</button></form>`}
      </section>`;
    });
    const inhoud = h`<h1>Herinneringslijst</h1>
      <p>${telling.bevestigd || 0} bevestigde aanmelding(en), ${telling.wacht || 0} wachten nog op bevestiging (die verdwijnen na ${cfg.bewaren.herinnering_onbevestigd_dagen} dagen).</p>
      <p class="klein">De tekst staat in data/aanvraag.json. Na een wijziging moet u hem hier opnieuw goedkeuren. Iemand van de lijst halen: Privacy, zoek op e-mailadres.</p>
      ${rondes}`;
    return pagina(res, sessie, 'Herinnering', 'herinnering', inhoud, { melding: melding(url) });
  }

  function herinneringVoorbeeld(res, jaar) {
    const r = cfg.herinnering.rondes.find((x) => x.jaar === Number(jaar));
    if (!r) return http.html(res, 404, 'niet gevonden');
    const m = ctx.herinnering.voorbeeld(r.jaar);
    return http.html(res, 200, m.html, { 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox", 'X-Robots-Tag': 'noindex, nofollow' });
  }

  /* ---------------- status ---------------- */
  function statusPagina(res, url, sessie) {
    const stand = ctx.mail.wachtrijStand();
    const laatsteFout = db.prepare('SELECT fout, pogingen, soort FROM uitgaand WHERE fout IS NOT NULL ORDER BY id DESC LIMIT 1').get();
    let backups = [];
    try { backups = fs.readdirSync(ctx.env.BHZ_BACKUP_MAP).filter((n) => /^leads-\d{4}-\d{2}-\d{2}\.db$/.test(n)).sort().reverse(); } catch (e) { backups = []; }
    let grootte = null;
    try { grootte = fs.statSync(ctx.env.BHZ_DB).size; } catch (e) { grootte = null; }
    const tel = (sql) => db.prepare(sql).get().n;
    const rijen = [
      ['Versie (commit)', ctx.commit ? ctx.commit() : '?'], ['Node', process.version],
      ['Mail', ctx.mail.ingesteld() ? (ctx.env.MAIL_VIA === 'brevo-api' ? 'ingesteld (Brevo-API)' : 'ingesteld (SMTP ' + ctx.env.SMTP_HOST + ':' + (ctx.env.SMTP_POORT || 2525) + ')') : 'NIET ingesteld'],
      ['Wachtrij', stand.wacht + ' wachtend, ' + stand.gestopt + ' opgegeven'],
      ['Laatste mailfout', laatsteFout ? laatsteFout.soort + ' (poging ' + laatsteFout.pogingen + '): ' + laatsteFout.fout : 'geen'],
      ['Laatste back-up', backups[0] || 'nog geen'], ['Back-ups', backups.length + ' bestand(en)'],
      ['Klikken ingelezen t/m', dbm.instelling(db, 'klikken-laatst') || 'nog niet'],
      ['Aanvragen', tel('SELECT COUNT(*) AS n FROM aanvragen') + ' (open: ' + tel("SELECT COUNT(*) AS n FROM aanvragen WHERE status IN ('nieuw','gebeld','afspraak')") + ')'],
      ['Herinneringslijst', tel("SELECT COUNT(*) AS n FROM herinneringen WHERE status = 'bevestigd'") + ' bevestigd'],
      ['Database', grootte === null ? '?' : Math.round(grootte / 1024) + ' KB']
    ];
    const logboek = db.prepare('SELECT * FROM logboek ORDER BY id DESC LIMIT 15').all();
    const inhoud = h`<h1>Status</h1>
      <section class="kaart"><dl class="gegevens">${rijen.map(([k, w]) => h`<dt>${k}</dt><dd>${w}</dd>`)}</dl></section>
      <form method="post" action="/beheer/status/testmail" class="kaart">${csrfVeld(sessie)}
        <p>Stuur een proefmail naar het adres voor de meldingen.</p><button type="submit">Proefmail sturen</button></form>
      <section class="kaart"><h2>Logboek</h2><p class="klein">Zonder namen of nummers; alleen wat er gebeurde.</p>
        <ul>${logboek.map((l) => h`<li>${leesbaar(l.tijd)}: ${l.actie}${l.details ? ' (' + l.details + ')' : ''}</li>`)}</ul></section>`;
    return pagina(res, sessie, 'Status', 'status', inhoud, { melding: melding(url) });
  }

  function testmail(res) {
    if (ctx.env.MAIL_MELDINGEN_AAN) {
      const m = berichten.signaal('Proefmail uit /beheer', ['Deze proefmail komt uit /beheer. Komt hij aan, dan werken de meldingen.']);
      ctx.mail.inWachtrij({ soort: 'signaal', aan: ctx.env.MAIL_MELDINGEN_AAN, onderwerp: m.onderwerp, tekst: m.tekst });
    }
    return terug(res, '/beheer/status', 'testmail');
  }

  function nietGevonden(res, sessie) {
    return pagina(res, sessie, 'Niet gevonden', '', h`<h1>Niet gevonden</h1><p>Deze pagina of aanvraag bestaat niet (meer). <a href="/beheer/aanvragen">Naar de aanvragen</a>.</p>`, { status: 404 });
  }

  /* ---------------- routes ---------------- */
  function route(methode, patroon, fn) { routes.push({ methode, patroon, fn }); }
  route('GET', /^\/beheer\/aanvragen$/, (req, res, url, s) => lijstPagina(req, res, url, s));
  route('GET', /^\/beheer\/aanvragen\.csv$/, (req, res, url) => exporteer(res, url, 'csv'));
  route('GET', /^\/beheer\/aanvragen\.xlsx$/, (req, res, url) => exporteer(res, url, 'xlsx'));
  route('GET', /^\/beheer\/aanvraag\/(\d+)$/, (req, res, url, s, m) => detailPagina(req, res, url, s, m[1]));
  route('POST', /^\/beheer\/aanvraag\/(\d+)\/status$/, (req, res, url, s, m, b) => zetStatus(res, s, m[1], b));
  route('POST', /^\/beheer\/aanvraag\/(\d+)\/notitie$/, (req, res, url, s, m, b) => voegNotitieToe(res, s, m[1], b));
  route('POST', /^\/beheer\/aanvraag\/(\d+)\/omzet$/, (req, res, url, s, m, b) => zetOmzet(res, s, m[1], b));
  route('POST', /^\/beheer\/aanvraag\/(\d+)\/verwijderen$/, (req, res, url, s, m) => verwijder(res, s, m[1]));
  route('GET', /^\/beheer\/nieuw$/, (req, res, url, s) => nieuwFormulier(res, s));
  route('POST', /^\/beheer\/nieuw$/, (req, res, url, s, m, b) => maakNieuw(res, s, b));
  route('GET', /^\/beheer\/persoon$/, (req, res, url, s) => persoonPagina(res, url, s));
  route('GET', /^\/beheer\/persoon\.json$/, (req, res, url) => persoonExport(res, url, 'json'));
  route('GET', /^\/beheer\/persoon\.csv$/, (req, res, url) => persoonExport(res, url, 'csv'));
  route('POST', /^\/beheer\/persoon\/verwijderen$/, (req, res, url, s, m, b) => persoonVerwijderen(res, s, b));
  route('GET', /^\/beheer\/herinnering$/, (req, res, url, s) => herinneringPagina(res, url, s));
  route('GET', /^\/beheer\/herinnering\/(\d{4})\/voorbeeld$/, (req, res, url, s, m) => herinneringVoorbeeld(res, m[1]));
  route('POST', /^\/beheer\/herinnering\/(\d{4})\/goedkeuren$/, (req, res, url, s, m) => {
    try { ctx.herinnering.keurGoed(m[1]); } catch (e) { return nietGevonden(res, s); }
    return terug(res, '/beheer/herinnering', 'goedgekeurd');
  });
  route('GET', /^\/beheer\/status$/, (req, res, url, s) => statusPagina(res, url, s));
  route('POST', /^\/beheer\/status\/testmail$/, (req, res) => testmail(res));
  route('POST', /^\/beheer\/uitloggen$/, (req, res) => {
    S.stopSessie(db, http.cookies(req)[S.COOKIE]);
    return http.doorsturen(res, '/beheer/inloggen?m=uitgelogd', 303, { 'Set-Cookie': S.cookieKop(null) });
  });

  /* ---------------- de ingang ---------------- */
  async function beheer(req, res, url) {
    const p = url.pathname;
    if (req.method === 'GET' && (p === '/beheer/stijl.css' || p === '/beheer/beheer.js')) {
      const f = path.join(BESTANDEN, p.slice('/beheer/'.length));
      const data = fs.readFileSync(f);
      res.writeHead(200, Object.assign({ 'Content-Type': p.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8', 'Content-Length': data.length }, http.GEEN_CACHE));
      return res.end(data);
    }
    if (p === '/beheer/inloggen') {
      if (req.method === 'POST') return inloggen(req, res);
      const s = S.zoekSessie(db, ctx.klok, http.cookies(req)[S.COOKIE]);
      if (s) return http.doorsturen(res, '/beheer/aanvragen');
      return inlogScherm(res, 200, null, melding(url));
    }
    const sessie = S.zoekSessie(db, ctx.klok, http.cookies(req)[S.COOKIE]);
    if (!sessie) {
      if (req.method === 'GET') return http.doorsturen(res, '/beheer/inloggen');
      return http.html(res, 403, document('Verlopen', h`<main class="inhoud"><p class="melding fout">Uw sessie is verlopen. <a href="/beheer/inloggen">Log opnieuw in</a>.</p></main>`), KOPPEN);
    }
    if (p === '/beheer' || p === '/beheer/') return http.doorsturen(res, '/beheer/aanvragen');
    let body = {};
    if (req.method === 'POST') {
      if (!http.vanEigenSite(req, ctx.origins)) return pagina(res, sessie, 'Geweigerd', '', h`<h1>Geweigerd</h1><p>Dit kan alleen vanaf de eigen site.</p>`, { status: 403 });
      const groot = routes.find((r) => r.methode === 'POST' && r.groot && r.patroon.test(p));
      body = await http.leesFormulier(req, groot ? 2 * 1024 * 1024 : 64 * 1024);
      if (!S.csrfOk(sessie, body.csrf)) {
        return pagina(res, sessie, 'Verlopen', '', h`<h1>Formulier verlopen</h1><p>Ga terug, ververs de pagina en probeer het opnieuw.</p>`, { status: 403 });
      }
    }
    for (const r of routes) {
      if (r.methode !== req.method) continue;
      const m = r.patroon.exec(p);
      if (m) return await r.fn(req, res, url, sessie, m, body);
    }
    return nietGevonden(res, sessie);
  }

  beheer.route = (methode, patroon, fn, opties) => { routes.push(Object.assign({ methode, patroon, fn }, opties || {})); };
  beheer.pagina = pagina;
  beheer.csrfVeld = csrfVeld;
  beheer.terug = terug;
  beheer.melding = melding;
  beheer.bestand = bestand;
  beheer.nietGevonden = (res, s) => nietGevonden(res, s);
  return beheer;
}

module.exports = { maakBeheer, centen, euro, STATUSSEN, STATUS_NAAM, OPEN };
