'use strict';
/*
 * berichten.js — de teksten van alle mails.
 *
 * Elke mail heeft platte tekst en eenvoudige HTML met inline stijl: dat is wat
 * mailprogramma's betrouwbaar tonen. Alles wat een bezoeker heeft ingevuld,
 * gaat door esc() voordat het in de HTML komt.
 *
 * Mails aan Stan (melding, signalen) hebben geen naam in het onderwerp: het
 * onderwerp staat op het vergrendelscherm van een telefoon.
 */
const { telefoonWeergave } = require('./valideer');
const { leesbaar, datumTekst } = require('./tijd');
const { NAMEN } = require('./bron');

function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const KLEUR = { teal: '#15756a', groen: '#188741', tekst: '#2c2520', zacht: '#6b5d52', achtergrond: '#f6f1ea' };

function knop(href, label, kleur) {
  return '<a href="' + esc(href) + '" style="display:inline-block;background:' + kleur + ';color:#ffffff;font-weight:bold;' +
    'font-size:18px;line-height:1.2;padding:14px 22px;border-radius:999px;text-decoration:none;margin:0 8px 10px 0">' + label + '</a>';
}

function omhulsel(inhoud, voet) {
  return '<!doctype html><html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>' +
    '<body style="margin:0;background:' + KLEUR.achtergrond + ';font-family:Arial,Helvetica,sans-serif;color:' + KLEUR.tekst + ';font-size:16px;line-height:1.55">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:20px 12px">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:580px;background:#ffffff;border-radius:12px">' +
    '<tr><td style="padding:24px 24px 8px">' + inhoud + '</td></tr>' +
    (voet ? '<tr><td style="padding:8px 24px 22px;font-size:13px;color:' + KLEUR.zacht + '">' + voet + '</td></tr>' : '') +
    '</table></td></tr></table></body></html>';
}

function alinea(t) { return '<p style="margin:0 0 14px">' + t + '</p>'; }

/* het nummer voor bellen en WhatsApp, zoals op de site */
const TELEFOON = { weergave: '06 19 71 18 48', e164: '+31619711848' };

function afzender(cfg) {
  const b = cfg.bedrijf.bedrijf;
  return b.naam + ' · ' + b.vestigingsplaats + ' · ' + b.email + ' · ' + TELEFOON.weergave;
}

function label(lijst, code) {
  const x = (lijst || []).find((d) => d.code === code);
  return x ? x.label : (code || '');
}

/* Voor in een zin: "u vroeg om teruggebeld te worden over ..." */
const DIENST_ZIN = {
  aangifte: 'uw belastingaangifte', 'aangifte-senioren': 'uw belastingaangifte', 'voorlopige-teruggave': 'een voorlopige teruggave',
  correctie: 'een correctie of te late aangifte', box3: 'box 3', toeslagen: 'toeslagen', 'eerste-baan': 'uw eerste aangifte',
  erfbelasting: 'erfbelasting of een schenking'
};

function waLink(e164, tekst) {
  return 'https://wa.me/' + String(e164).replace(/^\+/, '') + (tekst ? '?text=' + encodeURIComponent(tekst) : '');
}

/* ---------------- melding aan Stan: een nieuwe aanvraag ---------------- */
function meldingAanvraag(a, cfg, basisUrl) {
  const dienst = label(cfg.diensten, a.dienst);
  const tijd = label(cfg.voorkeurstijden, a.voorkeurstijd);
  const nummer = telefoonWeergave(a.telefoon);
  const voornaam = String(a.naam).split(' ')[0];
  const zin = DIENST_ZIN[a.dienst] ? ' over ' + DIENST_ZIN[a.dienst] : '';
  const groet = 'Goedendag ' + voornaam + ', u vroeg via onze website om teruggebeld te worden' + zin +
    '. Wanneer komt het u uit? Groet, Stan (Belastinghulp Zaanstad)';
  const kanWa = a.telefoon && (a.telefoon_soort === 'mobiel' || a.telefoon_soort === 'buitenland');
  const beheer = basisUrl + '/beheer/aanvraag/' + a.id;
  const bron = (NAMEN[a.bron] || a.bron) + (a.bron_detail ? ': ' + a.bron_detail : '');
  const reken = a.berekening ? JSON.parse(a.berekening) : null;

  const rijen = [
    ['Naam', a.naam],
    ['Telefoon', nummer + (a.telefoon_soort === 'vast' ? ' (vast nummer)' : a.telefoon_soort === 'buitenland' ? ' (buitenlands nummer)' : '')],
    a.email ? ['E-mail', a.email] : null,
    ['Waarover', dienst],
    ['Voorkeur', tijd || 'Maakt niet uit'],
    a.opmerking ? ['Opmerking', a.opmerking] : null,
    a.rekentool ? ['Rekentool', cfg.rekentools[a.rekentool] || a.rekentool] : null,
    ['Bron', bron],
    ['Pagina', a.pagina || ''],
    ['Binnen', leesbaar(a.aangemaakt)]
  ].filter(Boolean);

  const rekenRegels = [];
  if (reken && reken.tekst) rekenRegels.push(reken.tekst);
  if (reken && reken.invoer) reken.invoer.forEach((p) => rekenRegels.push(p[0] + ': ' + p[1]));
  if (reken && reken.uitkomst) reken.uitkomst.forEach((p) => rekenRegels.push(p[0] + ': ' + p[1]));

  /* "Weekend, avond 17:00–21:00" wordt "weekend avond" */
  const kortTijd = tijd.replace(/\s*\d.*$/, '').replace(/,/g, '').trim().toLowerCase();
  const onderwerp = (a.verdacht ? '[Controleer] ' : '') + 'Nieuwe aanvraag: ' + dienst +
    (a.voorkeurstijd && a.voorkeurstijd !== 'maakt-niet-uit' ? ' (' + kortTijd + ')' : '');
  const twijfel = a.verdacht ? 'Let op, misschien spam: ' + a.verdacht + '. Kijk even of het echt lijkt voordat u belt.' : null;

  const tekst = [
    'Nieuwe aanvraag via de website.',
    twijfel,
    '',
    'Bel: tel:' + a.telefoon + '  (' + nummer + ')',
    kanWa ? 'WhatsApp: ' + waLink(a.telefoon, groet) : null,
    '',
    ...rijen.map((r) => r[0] + ': ' + r[1]),
    rekenRegels.length ? '\nBerekening:\n' + rekenRegels.join('\n') : null,
    '',
    'In beheer: ' + beheer
  ].filter((x) => x !== null).join('\n');

  const html = omhulsel(
    '<p style="margin:0 0 6px;font-size:14px;color:' + KLEUR.zacht + '">Nieuwe aanvraag via de website</p>' +
    (twijfel ? '<p style="margin:0 0 12px;padding:10px 12px;background:#fff3d6;border:2px solid #8b5a00;border-radius:8px;color:#5c3b00;font-weight:bold">' + esc(twijfel) + '</p>' : '') +
    '<h1 style="margin:0 0 16px;font-size:22px">' + esc(a.naam) + ' &middot; ' + esc(dienst) + '</h1>' +
    '<p style="margin:0 0 8px">' + knop('tel:' + a.telefoon, '&#128222; Bel ' + esc(nummer), KLEUR.teal) +
    (kanWa ? knop(waLink(a.telefoon, groet), '&#128172; WhatsApp', KLEUR.groen) : '') + '</p>' +
    '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:6px 0 14px">' +
    rijen.map((r) => '<tr><td style="padding:6px 10px 6px 0;color:' + KLEUR.zacht + ';vertical-align:top;white-space:nowrap">' + esc(r[0]) +
      '</td><td style="padding:6px 0;vertical-align:top">' + esc(r[1]).replace(/\n/g, '<br>') + '</td></tr>').join('') +
    '</table>' +
    (rekenRegels.length ? '<p style="margin:0 0 6px;font-weight:bold">Berekening</p><p style="margin:0 0 14px;font-size:15px">' +
      rekenRegels.map(esc).join('<br>') + '</p>' : '') +
    alinea('<a href="' + esc(beheer) + '" style="color:' + KLEUR.teal + ';font-weight:bold">Open in beheer</a>'),
    'Automatisch bericht van belastinghulpzaanstad.nl'
  );
  return { onderwerp, tekst, html };
}

/* ---------------- herinneringslijst ---------------- */
function bevestigHerinnering(link, cfg) {
  const dagen = cfg.bewaren.herinnering_onbevestigd_dagen;
  const onderwerp = 'Bevestig uw herinnering voor de belastingaangifte';
  const tekst = [
    'Goedendag,',
    '',
    'U heeft zich aangemeld voor de herinnering van Belastinghulp Zaanstad: één mail per jaar, eind februari, als de aangifte opengaat.',
    '',
    'Bevestig uw aanmelding via deze link:',
    link,
    '',
    'Heeft u zich niet aangemeld? Dan hoeft u niets te doen. Zonder bevestiging verwijderen wij uw e-mailadres na ' + dagen + ' dagen.',
    '',
    'Met vriendelijke groet,',
    'Stan van der Hoeven',
    'Belastinghulp Zaanstad',
    '',
    afzender(cfg)
  ].join('\n');
  const html = omhulsel(
    alinea('Goedendag,') +
    alinea('U heeft zich aangemeld voor de herinnering van Belastinghulp Zaanstad: één mail per jaar, eind februari, als de aangifte opengaat.') +
    '<p style="margin:0 0 16px">' + knop(link, 'Ja, ik wil de herinnering', KLEUR.teal) + '</p>' +
    alinea('Heeft u zich niet aangemeld? Dan hoeft u niets te doen. Zonder bevestiging verwijderen wij uw e-mailadres na ' + dagen + ' dagen.') +
    alinea('Met vriendelijke groet,<br>Stan van der Hoeven<br>Belastinghulp Zaanstad'),
    esc(afzender(cfg))
  );
  return { onderwerp, tekst, html };
}

function alAangemeld(afmeldLink, cfg) {
  const onderwerp = 'U staat al op de lijst voor de herinnering';
  const tekst = [
    'Goedendag,',
    '',
    'U staat al op de lijst voor de herinnering als de aangifte opengaat. U hoeft niets te doen.',
    '',
    'Wilt u zich toch afmelden? Dat kan hier; wij verwijderen uw e-mailadres dan meteen:',
    afmeldLink,
    '',
    'Met vriendelijke groet,',
    'Stan van der Hoeven',
    'Belastinghulp Zaanstad',
    '',
    afzender(cfg)
  ].join('\n');
  const html = omhulsel(
    alinea('Goedendag,') +
    alinea('U staat al op de lijst voor de herinnering als de aangifte opengaat. U hoeft niets te doen.') +
    alinea('Wilt u zich toch afmelden? <a href="' + esc(afmeldLink) + '" style="color:' + KLEUR.teal + '">Afmelden</a>; wij verwijderen uw e-mailadres dan meteen.') +
    alinea('Met vriendelijke groet,<br>Stan van der Hoeven<br>Belastinghulp Zaanstad'),
    esc(afzender(cfg))
  );
  return { onderwerp, tekst, html };
}

/* {prijs:aangifte} -> €59, {prijs:aangifte.partner} -> €89 */
function vulPrijzen(s, cfg) {
  return s.replace(/\{prijs:([a-z_]+)(\.partner)?\}/g, (heel, k, partner) => {
    const p = cfg.bedrijf.prijzen[k];
    const v = p && (partner ? p.partner : p.bedrag);
    if (typeof v !== 'number') throw new Error('onbekende prijs in de herinneringstekst: ' + heel);
    return '€' + v;
  });
}

function terugbelLink(ronde, basisUrl) {
  return basisUrl + '/contact/?utm_source=herinnering&utm_medium=email&utm_campaign=aangifte-' + ronde.aangiftejaar + '#terugbellen';
}

/* De jaarlijkse herinnering. aangemeld: ISO-datum van aanmelden. */
function herinneringRonde(ronde, cfg, basisUrl, afmeldLink, aangemeld) {
  const link = terugbelLink(ronde, basisUrl);
  const alineas = ronde.alineas.map((a) => vulPrijzen(a, cfg));
  const voet = 'U ontvangt deze mail omdat u zich op ' + datumTekst(aangemeld) + ' heeft aangemeld voor de herinnering op belastinghulpzaanstad.nl. ' +
    'Afmelden kan met één klik; wij verwijderen uw e-mailadres dan meteen: ';
  const tekst = alineas.map((a) => a.replace('{link}', link)).join('\n\n') + '\n\n--\n' + voet + afmeldLink + '\n' + afzender(cfg);
  const html = omhulsel(
    alineas.map((a) => alinea(esc(a).replace(/\n/g, '<br>').replace('{link}',
      '<a href="' + esc(link) + '" style="color:' + KLEUR.teal + ';font-weight:bold">laat uw nummer achter</a>'))).join('') +
    '<p style="margin:0 0 16px">' + knop('tel:+31619711848', '&#128222; Bel 06 19 71 18 48', KLEUR.teal) +
    knop('https://wa.me/31619711848?text=' + encodeURIComponent('Hoi! Ik wil mijn aangifte over ' + ronde.aangiftejaar + ' laten doen.'), '&#128172; App', KLEUR.groen) + '</p>',
    esc(voet) + '<a href="' + esc(afmeldLink) + '" style="color:' + KLEUR.zacht + '">afmelden</a>.<br>' + esc(afzender(cfg))
  );
  return { onderwerp: ronde.onderwerp, tekst, html };
}

/* ---------------- dagoverzicht aan Stan ----------------
 * open: de open aanvragen, nieuw eerst. extra: { nieuwSindsGisteren, lijst, waarschuwingen } */
function dagoverzicht(open, extra, cfg, basisUrl) {
  const STATUS = { nieuw: 'Nieuw', gebeld: 'Gebeld', afspraak: 'Afspraak' };
  const nieuw = open.filter((a) => a.status === 'nieuw').length;
  const onderwerp = open.length
    ? 'Dagoverzicht: ' + open.length + ' open (' + nieuw + ' nieuw)'
    : 'Dagoverzicht: geen open aanvragen';
  const regel = (a) => {
    const tijd = label(cfg.voorkeurstijden, a.voorkeurstijd);
    return {
      a,
      kop: '[' + (STATUS[a.status] || a.status) + '] ' + a.naam + ' · ' + label(cfg.diensten, a.dienst) +
        (a.voorkeurstijd && a.voorkeurstijd !== 'maakt-niet-uit' ? ' · ' + tijd : '') + (a.verdacht ? ' · CONTROLEER' : ''),
      nummer: telefoonWeergave(a.telefoon) || a.email || '',
      binnen: leesbaar(a.aangemaakt),
      beheer: basisUrl + '/beheer/aanvraag/' + a.id
    };
  };
  const regels = open.map(regel);
  const kopTekst = [
    open.length ? open.length + ' open aanvra' + (open.length === 1 ? 'ag' : 'gen') + ', waarvan ' + nieuw + ' nieuw.' : 'Er staan geen open aanvragen. Alles werkt.',
    extra.nieuwSindsGisteren ? extra.nieuwSindsGisteren + ' nieuwe aanvra' + (extra.nieuwSindsGisteren === 1 ? 'ag' : 'gen') + ' sinds gisteren.' : null,
    'Herinneringslijst: ' + extra.lijst + ' bevestigde aanmelding(en).'
  ].filter(Boolean);
  const tekst = kopTekst.concat(extra.waarschuwingen.map((w) => 'LET OP: ' + w), [''],
    regels.map((r) => r.kop + '\n  ' + r.nummer + (r.a.telefoon ? '  tel:' + r.a.telefoon : '') + '\n  binnen ' + r.binnen + '\n  ' + r.beheer + '\n'),
    ['Alle aanvragen: ' + basisUrl + '/beheer/aanvragen']).join('\n');
  const html = omhulsel(
    '<h1 style="margin:0 0 10px;font-size:20px">' + esc(onderwerp) + '</h1>' +
    kopTekst.map((t) => alinea(esc(t))).join('') +
    extra.waarschuwingen.map((w) => '<p style="margin:0 0 12px;padding:10px 12px;background:#fff3d6;border:2px solid #8b5a00;border-radius:8px;color:#5c3b00;font-weight:bold">' + esc(w) + '</p>').join('') +
    regels.map((r) => '<div style="border-top:1px solid #e5ddd3;padding:12px 0">' +
      '<p style="margin:0 0 6px;font-weight:bold">' + esc(r.kop) + '</p>' +
      '<p style="margin:0 0 8px;color:' + KLEUR.zacht + '">' + esc(r.nummer) + ' · binnen ' + esc(r.binnen) + '</p>' +
      (r.a.telefoon ? knop('tel:' + r.a.telefoon, '&#128222; Bel', KLEUR.teal) : '') +
      '<a href="' + esc(r.beheer) + '" style="color:' + KLEUR.teal + ';font-weight:bold;margin-left:4px">Open</a></div>').join('') +
    alinea('<a href="' + esc(basisUrl + '/beheer/aanvragen') + '" style="color:' + KLEUR.teal + ';font-weight:bold">Alle aanvragen</a>'),
    'Automatisch dagoverzicht van belastinghulpzaanstad.nl'
  );
  return { onderwerp, tekst, html };
}

/* Korte signalen aan Stan: platte tekst */
function signaal(onderwerp, regels) {
  return { onderwerp: '[Belastinghulp] ' + onderwerp, tekst: regels.join('\n') + '\n\nAutomatisch bericht van belastinghulpzaanstad.nl' };
}

module.exports = { meldingAanvraag, bevestigHerinnering, alAangemeld, herinneringRonde, dagoverzicht, signaal, vulPrijzen, terugbelLink, esc, waLink, label, omhulsel, knop, alinea, KLEUR, TELEFOON };
