'use strict';
/*
 * partners.js — /beheer/partners: bedrijven en organisaties die klanten naar
 * u doorverwijzen (makelaar, notaris, ouderenbond, ...).
 *
 * Alleen zakelijke relaties: een rechtsvorm is verplicht en "particulier" kan
 * niet. Geen scraping of ingekochte lijsten: u voert partners zelf in, of
 * importeert een CSV die u zelf maakte. De app stuurt partners nooit iets.
 *
 * Per partner: een eigen code (?ref=...), een link naar de pagina die past
 * bij het soort partner, een QR-code en een kaart (A5, PDF) om aan klanten
 * mee te geven. Wie via die link binnenkomt, heeft in de aanvraag en in de
 * klikmeting de partner als bron. Hoeveel aanvragen, klanten en omzet dat
 * opleverde, rekent de app uit de aanvragen.
 *
 * Privacy: de contactpersoon, het nummer, het e-mailadres en de notities zijn
 * persoonsgegevens. Het privacybeleid zegt "zolang wij samenwerken"; zet u
 * een partner op Gestopt, dan worden die meteen gewist. De naam van de
 * organisatie en de cijfers blijven. Een partner hoort nooit wie er via hem
 * kwam; daarom staat er op de kaart alleen onze eigen informatie.
 */
const v = require('./valideer');
const dbm = require('./db');
const qr = require('./qr');
const pdf = require('./pdf');
const { TELEFOON } = require('./berichten');
const { csv } = require('./export');
const { h, veilig } = require('./html');
const { leesbaar } = require('./tijd');
const { STATUS_NAAM, euro } = require('./beheer');

const TYPES = [
  { code: 'makelaar', naam: 'Makelaar', landing: '/diensten/voorlopige-teruggave/', ook: ['makelaardij', 'makelaars'] },
  { code: 'hypotheekadviseur', naam: 'Hypotheekadviseur', landing: '/diensten/voorlopige-teruggave/', ook: ['hypotheekadvies', 'hypotheek', 'hypotheekadviseurs'] },
  { code: 'notaris', naam: 'Notaris', landing: '/diensten/erfbelasting-schenking/', ook: ['notariskantoor', 'notarissen'] },
  { code: 'uitvaart', naam: 'Uitvaartonderneming', landing: '/diensten/erfbelasting-schenking/', ook: ['uitvaartverzorger', 'uitvaartverzorging', 'uitvaartzorg', 'begrafenisonderneming'] },
  { code: 'ouderenbond', naam: 'Ouderenbond of -vereniging', landing: '/senioren/', ook: ['ouderenvereniging', 'seniorenvereniging', 'kbo', 'pcob', 'anbo'] },
  { code: 'buurthuis', naam: 'Buurthuis of wijkcentrum', landing: '/', ook: ['wijkcentrum', 'buurtcentrum'] },
  { code: 'anders', naam: 'Anders', landing: '/', ook: ['overig', 'overige'] }
];
const RECHTSVORMEN = [
  ['bv', 'BV', ['besloten vennootschap']], ['nv', 'NV', ['naamloze vennootschap']], ['eenmanszaak', 'Eenmanszaak', ['zzp']],
  ['vof', 'VOF', ['vennootschap onder firma']], ['maatschap', 'Maatschap', []], ['cv', 'CV', ['commanditaire vennootschap']],
  ['stichting', 'Stichting', []], ['vereniging', 'Vereniging', []], ['cooperatie', 'Coöperatie', ['coop']],
  ['overheid', 'Overheid (bijvoorbeeld gemeente)', ['gemeente', 'overheidsinstelling']]
];
const PARTICULIER = ['particulier', 'prive', 'persoon', 'natuurlijk persoon', 'consument'];
const STATUSSEN = [['benaderd', 'Benaderd'], ['actief', 'Actief'], ['gestopt', 'Gestopt']];
const PSTATUS = Object.fromEntries(STATUSSEN);
const LANDINGEN = [
  ['/', 'Homepage'], ['/senioren/', 'Senioren'], ['/diensten/voorlopige-teruggave/', 'Voorlopige teruggave (huis gekocht)'],
  ['/diensten/erfbelasting-schenking/', 'Erfbelasting en schenking'], ['/diensten/belastingaangifte-laten-doen/', 'Belastingaangifte laten doen'],
  ['/diensten/toeslagen/', 'Toeslagen'], ['/diensten/box-3-bezwaar/', 'Box 3']
];
/* De regel op de kaart, per landingspagina. Dezelfde feiten als in de beschrijving
 * van die pagina; geen prijzen, die kunnen veranderen nadat de kaart gedrukt is. */
const KAART_REGEL = {
  '/diensten/voorlopige-teruggave/': 'Net een huis gekocht? Ontvang uw hypotheekrenteaftrek elke maand in plaats van achteraf.',
  '/diensten/erfbelasting-schenking/': 'Aangifte erfbelasting na een overlijden? Wij helpen u, bij u thuis in Zaanstad.',
  '/senioren/': 'Wij doen uw belastingaangifte bij u thuis. U hoeft niets uit te zoeken.',
  '/': 'Wij doen uw belastingaangifte bij u thuis in Zaanstad en omgeving, ook ’s avonds en in het weekend.'
};
const CSV_KOPPEN = {
  naam: ['naam', 'bedrijf', 'bedrijfsnaam', 'organisatie'], type: ['type', 'soort'], rechtsvorm: ['rechtsvorm'],
  contactpersoon: ['contactpersoon', 'contact'], telefoon: ['telefoon', 'telefoonnummer', 'tel'], email: ['email', 'emailadres', 'mail'],
  status: ['status'], ref_code: ['code', 'ref', 'refcode', 'partnercode'], landingspagina: ['landingspagina', 'pagina'],
  notities: ['notities', 'notitie', 'opmerking', 'opmerkingen']
};
const MAX_IMPORT = 500;
const MELDINGEN = {
  nieuw: 'Partner toegevoegd.', opgeslagen: 'Opgeslagen.', status: 'Status opgeslagen.', verwijderd: 'De partner is verwijderd.',
  gestopt: 'Samenwerking gestopt. De contactpersoon, het telefoonnummer, het e-mailadres en de notities zijn gewist.'
};

/* "Coöperatie U.A." -> "cooperatie-u-a"; voor codes en om invoer te vergelijken */
function slug(s) {
  return String(s || '').normalize('NFD').replace(/\p{M}/gu, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}
const vergelijk = (s) => slug(s).replace(/-/g, '');

function typeVan(s) {
  const x = vergelijk(s);
  if (!x) return null;
  const t = TYPES.find((t) => t.code === x || vergelijk(t.naam) === x || t.ook.some((o) => vergelijk(o) === x));
  return t ? t.code : null;
}

/* code van de rechtsvorm, 'particulier', of null */
function rechtsvormVan(s) {
  const x = vergelijk(s);
  if (!x) return null;
  if (PARTICULIER.some((p) => vergelijk(p) === x)) return 'particulier';
  const r = RECHTSVORMEN.find(([code, naam, ook]) => code === x || vergelijk(naam) === x || ook.some((o) => vergelijk(o) === x));
  return r ? r[0] : null;
}

/* "Jansen Makelaardij B.V." -> "jansen-makelaardij"; bezet(code) zegt of hij al gebruikt is */
function maakCode(naam, bezet) {
  const basis = slug(naam).replace(/-(b-v|bv|n-v|nv|v-o-f|vof|c-v|cv|u-a)$/, '').slice(0, 30).replace(/-+$/, '') || 'partner';
  let code = basis;
  for (let i = 2; bezet(code); i++) code = basis.slice(0, 26).replace(/-+$/, '') + '-' + i;
  return code;
}

function landingVan(p) { return p.landingspagina || (TYPES.find((t) => t.code === p.type) || TYPES[TYPES.length - 1]).landing; }
function linkVan(basisUrl, p) { return basisUrl + landingVan(p) + '?ref=' + p.ref_code; }

/*
 * Controle van één partner (formulier of CSV-regel). Geeft { waarden, fouten }.
 * bezet(code) en dubbel(naam) zeggen of een code of naam al van een ander is.
 */
function controleer(b, bezet, dubbel, nieuw) {
  const fouten = {};
  const naam = v.kort(b.naam, 100);
  if (naam.length < 2) fouten.naam = 'Vul de naam van het bedrijf of de organisatie in.';
  else if (/https?:|www\.|[<>]/i.test(naam)) fouten.naam = 'Alleen de naam, zonder link.';
  else if (dubbel(naam)) fouten.naam = 'Er is al een partner met deze naam.';
  const type = typeVan(b.type);
  if (!type) fouten.type = String(b.type || '').trim() ? 'Soort onbekend: kies uit ' + TYPES.map((t) => t.code).join(', ') + '.' : 'Kies het soort partner.';
  const rechtsvorm = rechtsvormVan(b.rechtsvorm);
  if (rechtsvorm === 'particulier') fouten.rechtsvorm = 'Een particulier kan geen partner zijn: alleen bedrijven en organisaties.';
  else if (!rechtsvorm) fouten.rechtsvorm = String(b.rechtsvorm || '').trim() ? 'Rechtsvorm onbekend: kies uit ' + RECHTSVORMEN.map((r) => r[1].split(' ')[0]).join(', ') + '.' : 'Kies de rechtsvorm (verplicht).';
  const contactpersoon = v.kort(b.contactpersoon, 80) || null;
  let telefoon = null;
  if (String(b.telefoon || '').trim()) {
    const t = v.telefoon(b.telefoon);
    if (t.fout) fouten.telefoon = 'Dit telefoonnummer klopt niet.';
    else telefoon = t.waarde;
  }
  const e = v.email(b.email);
  if (e.fout) fouten.email = 'Dit e-mailadres klopt niet.';
  let status = 'benaderd';
  if (nieuw && String(b.status || '').trim()) {
    status = slug(b.status);
    if (status !== 'benaderd' && status !== 'actief') fouten.status = 'Status: Benaderd of Actief.';
  }
  let landingspagina = null;
  if (String(b.landingspagina || '').trim()) {
    /* "senioren" en "/senioren" zijn ook goed */
    landingspagina = v.pad(('/' + String(b.landingspagina).trim() + '/').replace(/\/{2,}/g, '/'));
    if (!LANDINGEN.some(([p]) => p === landingspagina)) fouten.landingspagina = 'Kies een pagina uit de lijst.';
  }
  let ref = String(b.ref_code || '').trim().toLowerCase();
  if (ref) {
    if (!/^[a-z0-9][a-z0-9-]{1,29}$/.test(ref)) fouten.ref_code = 'Alleen kleine letters, cijfers en streepjes, 2 tot 30 tekens.';
    else if (bezet(ref)) fouten.ref_code = 'Deze code is al van een andere partner.';
  } else ref = null;
  const n = v.tekst(b.notities, 4000);
  if (n.fout) fouten.notities = 'De notities zijn te lang (maximaal 4000 tekens).';
  return {
    fouten,
    waarden: { naam, type, rechtsvorm, contactpersoon, telefoon, email: e.waarde || null, status, landingspagina, ref_code: ref, notities: n.waarde || null }
  };
}

/* CSV uit Excel of Google Sheets: puntkomma, komma of tab, aanhalingstekens, een BOM */
function leesCsv(tekst) {
  const s = String(tekst || '').replace(/^\ufeff/, '');
  const eerste = s.split(/\r?\n/, 1)[0];
  const scheiding = [';', '\t', ','].map((t) => [t, eerste.split(t).length]).sort((a, b) => b[1] - a[1])[0][0];
  const rijen = [];
  let rij = [], veld = '', tussen = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (tussen) {
      if (c !== '"') veld += c;
      else if (s[i + 1] === '"') { veld += '"'; i++; } else tussen = false;
    } else if (c === '"' && !veld.trim()) { veld = ''; tussen = true; }
    else if (c === scheiding) { rij.push(veld); veld = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && s[i + 1] === '\n') i++;
      rij.push(veld); rijen.push(rij); rij = []; veld = '';
    } else veld += c;
  }
  if (veld !== '' || rij.length) { rij.push(veld); rijen.push(rij); }
  return rijen.filter((r) => r.some((x) => x.trim() !== ''));
}

/* CSV-regels naar invoer per veld; null als er geen kolom "naam" is */
function csvNaarInvoer(rijen) {
  if (!rijen.length) return null;
  const kolom = {};
  rijen[0].forEach((k, i) => {
    const x = vergelijk(k);
    for (const [veld, namen] of Object.entries(CSV_KOPPEN)) if (namen.includes(x) && kolom[veld] === undefined) kolom[veld] = i;
  });
  if (kolom.naam === undefined) return null;
  return rijen.slice(1).map((r, i) => {
    const invoer = { regel: i + 2 };
    for (const [veld, k] of Object.entries(kolom)) invoer[veld] = String(r[k] === undefined ? '' : r[k]).trim();
    return invoer;
  });
}

/* ---------------- de kaart (A5) ---------------- */
/* Bovenaan van boven naar beneden, onderaan van onder naar boven; de QR-code vult
 * het midden (hoogstens 190 pt, 67 mm) met 4,5 modules wit erboven en eronder. */
function kaartPdf(p, link, cfg, datum) {
  const B = 420, H = 595, M = 40; /* A5 in punten: 148 x 210 mm */
  const TEAL = '#15756a', TEKST = '#2c2520', ZACHT = '#5f5248';
  const b = cfg.bedrijf.bedrijf;
  const d = pdf.document({ breedte: B, hoogte: H, titel: b.naam + ' - doorverwezen door ' + p.naam, datum });
  d.tekst(B / 2, 70, b.naam, { grootte: 24, vet: true, midden: true, kleur: TEAL });
  const y = d.alinea(M + 10, 100, B - 2 * M - 20, KAART_REGEL[landingVan(p)] || KAART_REGEL['/'], { grootte: 13, midden: true, kleur: TEKST });
  d.lijn(M, y, B - M, y, { kleur: '#d9d4cc', dikte: 1 });
  d.tekst(B / 2, y + 28, 'Doorverwezen door', { grootte: 12, midden: true, kleur: ZACHT });
  const naamGrootte = pdf.afbreken(p.naam, B - 2 * M, 18, true).length > 2 ? 14 : 18;
  const boven = d.alinea(M, y + 52, B - 2 * M, p.naam, { grootte: naamGrootte, vet: true, midden: true, kleur: TEKST }) - naamGrootte * 1.35 + 6;

  d.tekst(B / 2, H - 34, b.email + '  ·  ' + cfg.siteDomein, { grootte: 10, midden: true, kleur: ZACHT });
  d.tekst(B / 2, H - 78, TELEFOON.weergave, { grootte: 28, vet: true, midden: true, kleur: TEAL });
  d.tekst(B / 2, H - 112, 'Liever bellen of appen?', { grootte: 13, midden: true, kleur: TEKST });
  const adres = link.replace(/^https?:\/\//, '');
  const eersteAdres = H - 138 - (pdf.afbreken(adres, B - 2 * M, 8, false).length - 1) * 10.8;
  d.alinea(M, eersteAdres, B - 2 * M, adres, { grootte: 8, regelHoogte: 10.8, midden: true, kleur: ZACHT });
  const scan = eersteAdres - 16;
  d.tekst(B / 2, scan, 'Scan de code met de camera van uw telefoon', { grootte: 12, midden: true, kleur: TEKST });

  const q = qr.maak(link, 'M');
  const ruimte = scan - 9 - boven; /* 9: de hoogte van de hoofdletters op de regel eronder */
  const maat = Math.min(190, ruimte / (1 + 9 / q.grootte));
  d.qr(q, (B - maat) / 2, boven + (ruimte - maat) / 2, maat);
  return d.bytes();
}

/* ---------------- /beheer ---------------- */
function registreer(ctx) {
  const { db, config: cfg, beheer } = ctx;
  const siteDomein = new URL(ctx.basisUrl).host;

  const bezetDoor = (eigenId) => (code) => !!db.prepare('SELECT 1 FROM partners WHERE ref_code = ? AND id != ?').get(code, eigenId || 0);
  const dubbelDoor = (eigenId) => (naam) => db.prepare('SELECT naam FROM partners WHERE id != ?').all(eigenId || 0).some((p) => vergelijk(p.naam) === vergelijk(naam));

  function met(sql, ...p) {
    return db.prepare(`SELECT p.*,
      (SELECT COUNT(*) FROM aanvragen a WHERE a.partner_id = p.id) AS aanvragen,
      (SELECT COUNT(*) FROM aanvragen a WHERE a.partner_id = p.id AND a.status = 'klant') AS klanten,
      (SELECT COALESCE(SUM(a.omzet_centen), 0) FROM aanvragen a WHERE a.partner_id = p.id AND a.status = 'klant') AS omzet,
      (SELECT COALESCE(SUM(k.n), 0) FROM klikken k WHERE k.b = 'partner' AND k.c = p.ref_code AND k.e = 'bezoek') AS bezoeken,
      (SELECT COALESCE(SUM(k.n), 0) FROM klikken k WHERE k.b = 'partner' AND k.c = p.ref_code AND k.e IN ('tel', 'whatsapp')) AS klikken
      FROM partners p ` + sql).all(...p);
  }
  const haal = (id) => met('WHERE p.id = ?', Number(id))[0];
  const typeNaam = (c) => (TYPES.find((t) => t.code === c) || { naam: c }).naam;
  const vormNaam = (c) => (RECHTSVORMEN.find((r) => r[0] === c) || [c, c])[1];
  const melding = (url) => (url.searchParams.get('m') === 'import'
    ? 'Toegevoegd: ' + Number(url.searchParams.get('n') || 0) + ' partner(s).' : MELDINGEN[url.searchParams.get('m')] || null);

  /* aanvragen met deze code die nog aan niemand hingen (code was er eerder dan de partner) */
  function koppel(p) {
    db.prepare("UPDATE aanvragen SET partner_id = ?, bron_detail = ? WHERE ref = ? AND partner_id IS NULL AND bron = 'partner'").run(p.id, p.naam, p.ref_code);
  }

  /* gereserveerd: codes die een andere regel van dezelfde import zelf opgaf */
  function voegToe(w, nu, gereserveerd) {
    const bezet = bezetDoor(0);
    const code = w.ref_code || maakCode(w.naam, (c) => bezet(c) || (gereserveerd ? gereserveerd.has(c) : false));
    const r = db.prepare(`INSERT INTO partners (naam, type, rechtsvorm, contactpersoon, telefoon, email, status, ref_code, landingspagina, notities, aangemaakt, gewijzigd)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(w.naam, w.type, w.rechtsvorm, w.contactpersoon, w.telefoon, w.email, w.status, code, w.landingspagina, w.notities, nu, nu);
    koppel({ id: Number(r.lastInsertRowid), naam: w.naam, ref_code: code });
    return Number(r.lastInsertRowid);
  }

  /* ---------- lijst ---------- */
  function lijst(res, url, sessie) {
    const rijen = met("ORDER BY CASE p.status WHEN 'actief' THEN 0 WHEN 'benaderd' THEN 1 ELSE 2 END, p.naam COLLATE NOCASE");
    const inhoud = h`<h1>Partners</h1>
      <p>Bedrijven en organisaties die klanten naar u doorverwijzen. Alleen zakelijke relaties, geen particulieren. De app stuurt partners nooit iets.</p>
      <p class="rij"><a class="knop" href="/beheer/partners/nieuw">+ Partner toevoegen</a><a class="knop licht" href="/beheer/partners/import">CSV importeren</a></p>
      ${rijen.length ? h`<ul class="lijst">${rijen.map((p) => h`<li><a href="/beheer/partner/${p.id}">
        <span class="badge ${p.status}">${PSTATUS[p.status] || p.status}</span><span class="naam">${p.naam}</span>
        <div class="sub">${typeNaam(p.type)} · ${vormNaam(p.rechtsvorm)}${p.contactpersoon ? ' · ' + p.contactpersoon : ''}</div>
        <div class="sub">${p.aanvragen} doorverwijzing${p.aanvragen === 1 ? '' : 'en'} · ${p.klanten} klant${p.klanten === 1 ? '' : 'en'} · ${euro(p.omzet)} · ${p.bezoeken} bezoek${p.bezoeken === 1 ? '' : 'en'} via de link</div></a></li>`)}</ul>`
      : h`<p class="kaart">Nog geen partners. Voeg er een toe, of importeer een lijst.</p>`}`;
    return beheer.pagina(res, sessie, 'Partners', 'partners', inhoud, { melding: melding(url) });
  }

  /* ---------- formulier (nieuw en wijzigen) ---------- */
  function velden(w, f, nieuw) {
    const fout = (veld) => (f[veld] ? h`<p class="melding fout">${f[veld]}</p>` : '');
    const kies = (lijst, gekozen) => lijst.map(([c, t]) => h`<option value="${c}"${veilig(c === (gekozen || '') ? ' selected' : '')}>${t}</option>`);
    const gestopt = w.status === 'gestopt';
    return h`
      <label for="p-naam">Naam van het bedrijf of de organisatie</label><input type="text" id="p-naam" name="naam" required maxlength="100" value="${w.naam || ''}">${fout('naam')}
      <label for="p-type">Soort</label><select id="p-type" name="type">${kies([['', 'Kies...']].concat(TYPES.map((t) => [t.code, t.naam])), w.type)}</select>${fout('type')}
      <label for="p-vorm">Rechtsvorm</label><select id="p-vorm" name="rechtsvorm">${kies([['', 'Kies...']].concat(RECHTSVORMEN.map((r) => [r[0], r[1]])), w.rechtsvorm)}</select>${fout('rechtsvorm')}
      <p class="klein">Alleen bedrijven en organisaties. Eenmanszaak of zzp’er? Neem alleen contact op als zij daar zelf om vroegen of al met u samenwerken: geen ongevraagde mail, sms, WhatsApp of belacties.</p>
      ${gestopt ? h`<p class="klein">Deze samenwerking is gestopt; daarom staan hier geen contactgegevens. Zet de partner weer op Actief om ze in te vullen.</p>` : h`
      <label for="p-contact">Contactpersoon</label><input type="text" id="p-contact" name="contactpersoon" maxlength="80" value="${w.contactpersoon || ''}">
      <label for="p-tel">Telefoonnummer</label><input type="tel" id="p-tel" name="telefoon" maxlength="32" value="${w.telefoonInvoer !== undefined ? w.telefoonInvoer : v.telefoonWeergave(w.telefoon)}">${fout('telefoon')}
      <label for="p-email">E-mailadres</label><input type="email" id="p-email" name="email" maxlength="254" value="${w.email || ''}">${fout('email')}`}
      ${nieuw ? h`<label for="p-status">Status</label><select id="p-status" name="status">${kies(STATUSSEN.slice(0, 2), w.status || 'benaderd')}</select>${fout('status')}` : ''}
      <label for="p-code">Code voor de link</label><input type="text" id="p-code" name="ref_code" maxlength="30" autocapitalize="none" value="${w.ref_code || ''}"
        placeholder="${nieuw ? 'leeg laten: wordt gemaakt van de naam' : ''}">${fout('ref_code')}
      <p class="klein">Kleine letters, cijfers en streepjes. Zijn er al kaarten of QR-codes uitgedeeld? Verander de code dan niet meer, anders tellen die niet meer mee.</p>
      <label for="p-landing">Pagina waar de link naartoe gaat</label><select id="p-landing" name="landingspagina">${kies([['', 'Passend bij het soort (aanbevolen)']].concat(LANDINGEN), w.landingspagina)}</select>${fout('landingspagina')}
      ${gestopt ? '' : h`<label for="p-notities">Notities</label><textarea id="p-notities" name="notities" maxlength="4000">${w.notities || ''}</textarea>${fout('notities')}`}`;
  }

  function nieuwFormulier(res, sessie, w, f) {
    const fouten = f || {};
    const inhoud = h`<p><a href="/beheer/partners">&larr; Alle partners</a></p><h1>Partner toevoegen</h1>
      <form method="post" action="/beheer/partners/nieuw" class="kaart">${beheer.csrfVeld(sessie)}${velden(w || {}, fouten, true)}
        <p><button type="submit">Toevoegen</button></p></form>`;
    return beheer.pagina(res, sessie, 'Partner toevoegen', 'partners', inhoud,
      Object.keys(fouten).length ? { melding: 'Controleer de velden hieronder.', fout: true, status: 422 } : {});
  }

  function maakNieuw(res, sessie, b) {
    const { fouten, waarden } = controleer(b, bezetDoor(0), dubbelDoor(0), true);
    if (Object.keys(fouten).length) return nieuwFormulier(res, sessie, Object.assign({}, b, { telefoonInvoer: b.telefoon || '' }), fouten);
    const id = voegToe(waarden, ctx.klok().toISOString());
    dbm.log(db, ctx.klok, 'partner toegevoegd', 'nummer ' + id);
    return beheer.terug(res, '/beheer/partner/' + id, 'nieuw');
  }

  /* ---------- één partner ---------- */
  function detail(res, url, sessie, id, w, f) {
    const p = haal(id);
    if (!p) return beheer.nietGevonden(res, sessie);
    const fouten = f || {};
    const link = linkVan(ctx.basisUrl, p);
    const via = db.prepare('SELECT id, naam, aangemaakt, status FROM aanvragen WHERE partner_id = ? ORDER BY aangemaakt DESC LIMIT 100').all(p.id);
    const tegel = (label, waarde) => h`<div class="kpi-tegel"><div class="kpi-label">${label}</div><div class="kpi-waarde">${waarde}</div></div>`;
    const inhoud = h`<p><a href="/beheer/partners">&larr; Alle partners</a></p>
      <h1><span class="badge ${p.status}">${PSTATUS[p.status] || p.status}</span>${p.naam}</h1>
      <p class="klein">${typeNaam(p.type)} · ${vormNaam(p.rechtsvorm)} · sinds ${leesbaar(p.aangemaakt)}</p>
      ${p.telefoon || p.email ? h`<div class="bel-rij">${p.telefoon ? h`<a class="knop" href="tel:${p.telefoon}">Bel${p.contactpersoon ? ' ' + p.contactpersoon : ''}</a>` : ''}
        ${p.email ? h`<a class="knop licht" href="mailto:${p.email}">Mail</a>` : ''}</div>` : ''}
      <section class="kpi" aria-label="Wat het opleverde">
        ${tegel('Doorverwijzingen', p.aanvragen)}${tegel('Klant geworden', p.klanten)}${tegel('Omzet', euro(p.omzet))}
        ${tegel('Bezoeken via de link', p.bezoeken)}${tegel('Daarna bellen of WhatsApp', p.klikken)}
      </section>
      <section class="kaart"><h2>Link, QR-code en kaart</h2>
        <label for="p-link">Link voor deze partner</label>
        <div class="rij link-rij"><input type="text" id="p-link" value="${link}" readonly><button type="button" class="licht" data-kopieer="p-link">Kopieer</button></div>
        <div class="qr-voorbeeld">${veilig(qr.svg(qr.maak(link, 'M'), { rand: 4, schaal: 4, titel: 'QR-code voor ' + p.naam }))}</div>
        <p class="rij"><a class="knop" href="/beheer/partner/${p.id}/kaart.pdf">Kaart om af te geven (PDF, A5)</a>
          <a class="knop licht" href="/beheer/partner/${p.id}/qr.svg">Alleen de QR-code (SVG)</a></p>
        <p class="klein">Op de kaart staan alleen onze eigen gegevens. Scan de QR-code één keer met uw telefoon voordat u kaarten laat drukken.</p></section>
      <form method="post" action="/beheer/partner/${p.id}/status" class="kaart">${beheer.csrfVeld(sessie)}
        <h2>Status</h2><div class="status-knoppen">${STATUSSEN.map(([c, t]) => h`<button type="submit" name="status" value="${c}" aria-pressed="${c === p.status ? 'true' : 'false'}"${
          veilig(c === 'gestopt' && p.status !== 'gestopt' ? ' data-bevestig="Samenwerking stoppen? De contactpersoon, het telefoonnummer, het e-mailadres en de notities worden dan gewist. De naam en de cijfers blijven."' : '')}>${t}</button>`)}</div>
        <p class="klein">Gestopt: de contactgegevens en notities worden gewist (privacybeleid: alleen zolang wij samenwerken).</p></form>
      <form method="post" action="/beheer/partner/${p.id}" class="kaart">${beheer.csrfVeld(sessie)}<h2>Gegevens</h2>
        ${velden(w || p, fouten, false)}<p><button type="submit">Opslaan</button></p></form>
      <section class="kaart"><h2>Doorverwijzingen</h2>
        ${via.length ? h`<ul>${via.map((a) => h`<li><a href="/beheer/aanvraag/${a.id}">${a.naam}</a>, ${leesbaar(a.aangemaakt)}, ${STATUS_NAAM[a.status] || a.status}</li>`)}</ul>`
          : h`<p class="klein">Nog niemand via deze partner.</p>`}
        <p class="klein">Aanvragen die geen klant werden, verdwijnen na ${cfg.bewaren.aanvraag_maanden} maanden; ze tellen dan ook hier niet meer mee.</p></section>
      <section class="kaart"><h2>Verwijderen</h2>
        <form method="post" action="/beheer/partner/${p.id}/verwijderen" data-bevestig="Deze partner helemaal verwijderen? De aanvragen blijven, maar hangen dan niet meer aan deze partner. Dit kan niet ongedaan worden.">${beheer.csrfVeld(sessie)}
          <button type="submit" class="gevaar">Partner verwijderen</button></form></section>`;
    return beheer.pagina(res, sessie, p.naam, 'partners', inhoud,
      Object.keys(fouten).length ? { melding: 'Controleer de velden hieronder.', fout: true, status: 422 } : { melding: melding(url) });
  }

  function opslaan(res, url, sessie, id, b) {
    const p = haal(id);
    if (!p) return beheer.nietGevonden(res, sessie);
    const { fouten, waarden: w } = controleer(Object.assign({}, b, { ref_code: b.ref_code || p.ref_code }), bezetDoor(p.id), dubbelDoor(p.id), false);
    if (Object.keys(fouten).length) return detail(res, url, sessie, id, Object.assign({}, b, { status: p.status, telefoonInvoer: b.telefoon || '' }), fouten);
    /* gestopt: geen contactgegevens, ook niet als iemand ze toch meestuurt */
    const weg = p.status === 'gestopt';
    db.prepare(`UPDATE partners SET naam = ?, type = ?, rechtsvorm = ?, contactpersoon = ?, telefoon = ?, email = ?, ref_code = ?, landingspagina = ?,
      notities = ?, gewijzigd = ? WHERE id = ?`).run(w.naam, w.type, w.rechtsvorm, weg ? null : w.contactpersoon, weg ? null : w.telefoon,
      weg ? null : w.email, w.ref_code, w.landingspagina, weg ? null : w.notities, ctx.klok().toISOString(), p.id);
    koppel({ id: p.id, naam: w.naam, ref_code: w.ref_code });
    return beheer.terug(res, '/beheer/partner/' + p.id, 'opgeslagen');
  }

  function zetStatus(res, sessie, id, b) {
    const p = haal(id);
    if (!p) return beheer.nietGevonden(res, sessie);
    const status = PSTATUS[b.status] ? b.status : p.status;
    if (status === p.status) return beheer.terug(res, '/beheer/partner/' + p.id);
    const nu = ctx.klok().toISOString();
    if (status === 'gestopt') {
      db.prepare("UPDATE partners SET status = 'gestopt', contactpersoon = NULL, telefoon = NULL, email = NULL, notities = NULL, gewijzigd = ? WHERE id = ?").run(nu, p.id);
      dbm.log(db, ctx.klok, 'partner gestopt, contactgegevens gewist', 'nummer ' + p.id);
      return beheer.terug(res, '/beheer/partner/' + p.id, 'gestopt');
    }
    db.prepare('UPDATE partners SET status = ?, gewijzigd = ? WHERE id = ?').run(status, nu, p.id);
    return beheer.terug(res, '/beheer/partner/' + p.id, 'status');
  }

  function verwijder(res, sessie, id) {
    const p = haal(id);
    if (!p) return beheer.nietGevonden(res, sessie);
    db.prepare('DELETE FROM partners WHERE id = ?').run(p.id);
    dbm.log(db, ctx.klok, 'partner verwijderd', 'nummer ' + p.id);
    return beheer.terug(res, '/beheer/partners', 'verwijderd');
  }

  function bestandsnaam(p) { return (p.ref_code || 'partner').replace(/[^a-z0-9-]/g, ''); }

  function qrBestand(res, sessie, id) {
    const p = haal(id);
    if (!p) return beheer.nietGevonden(res, sessie);
    const svg = qr.svg(qr.maak(linkVan(ctx.basisUrl, p), 'M'), { rand: 4, schaal: 10, titel: 'QR-code ' + p.naam });
    return beheer.bestand(res, 'qr-' + bestandsnaam(p) + '.svg', 'image/svg+xml', svg);
  }

  function kaart(res, sessie, id) {
    const p = haal(id);
    if (!p) return beheer.nietGevonden(res, sessie);
    dbm.log(db, ctx.klok, 'partnerkaart gemaakt', 'nummer ' + p.id);
    return beheer.bestand(res, 'kaart-' + bestandsnaam(p) + '.pdf', 'application/pdf',
      kaartPdf(p, linkVan(ctx.basisUrl, p), Object.assign({ siteDomein }, cfg), ctx.klok()));
  }

  /* ---------- CSV importeren ---------- */
  function importFormulier(res, sessie, tekst, fout) {
    const inhoud = h`<p><a href="/beheer/partners">&larr; Alle partners</a></p><h1>Partners importeren</h1>
      <p>Een lijst die u zelf maakte, bijvoorbeeld in Excel (Opslaan als: CSV). Eerste regel: de kolomnamen. Nodig zijn <strong>naam</strong>, <strong>type</strong> en
        <strong>rechtsvorm</strong>; mag ook: contactpersoon, telefoon, email, status (benaderd of actief), code, landingspagina, notities.
        <a href="/beheer/partners/voorbeeld.csv">Download een leeg voorbeeld</a>.</p>
      <p class="klein">Geen gekochte of van internet geplukte lijsten, en geen particulieren.</p>
      ${fout ? h`<p class="melding fout" role="alert">${fout}</p>` : ''}
      <form method="post" action="/beheer/partners/import" class="kaart">${beheer.csrfVeld(sessie)}<input type="hidden" name="stap" value="voorbeeld">
        <label for="i-bestand">Kies het bestand</label><input type="file" id="i-bestand" accept=".csv,text/csv,text/plain" data-naar="i-csv">
        <label for="i-csv">Of plak hier de inhoud</label><textarea id="i-csv" name="csv" rows="8" required>${tekst || ''}</textarea>
        <p><button type="submit">Eerst bekijken</button></p></form>`;
    return beheer.pagina(res, sessie, 'Partners importeren', 'partners', inhoud, fout ? { status: 422 } : {});
  }

  function vormDeelVan(tekst) {
    const invoer = csvNaarInvoer(leesCsv(tekst));
    if (!invoer) return { fout: 'Geen kolom "naam" gevonden in de eerste regel.' };
    if (!invoer.length) return { fout: 'Er staan geen partners onder de kolomnamen.' };
    if (invoer.length > MAX_IMPORT) return { fout: 'Te veel regels: maximaal ' + MAX_IMPORT + ' per keer.' };
    /* ook dubbelen binnen het bestand zelf: de eerste telt */
    const namen = new Set(), codes = new Set();
    const bezet = bezetDoor(0), dubbel = dubbelDoor(0);
    return {
      regels: invoer.map((x) => {
        const r = controleer(x, (c) => bezet(c) || codes.has(c), (n) => dubbel(n) || namen.has(vergelijk(n)), true);
        if (!Object.keys(r.fouten).length) {
          namen.add(vergelijk(r.waarden.naam));
          if (r.waarden.ref_code) codes.add(r.waarden.ref_code);
        }
        return Object.assign({ regel: x.regel }, r);
      })
    };
  }

  function importeer(res, sessie, b) {
    const tekst = String(b.csv || '');
    const deel = vormDeelVan(tekst);
    if (deel.fout) return importFormulier(res, sessie, tekst, deel.fout);
    const goed = deel.regels.filter((r) => !Object.keys(r.fouten).length);
    if (b.stap === 'opslaan' && goed.length) {
      const nu = ctx.klok().toISOString();
      const gereserveerd = new Set(goed.map((r) => r.waarden.ref_code).filter(Boolean));
      dbm.transactie(db, () => { for (const r of goed) voegToe(r.waarden, nu, gereserveerd); });
      dbm.log(db, ctx.klok, 'partners geïmporteerd', goed.length + ' toegevoegd, ' + (deel.regels.length - goed.length) + ' overgeslagen');
      return beheer.terug(res, '/beheer/partners?n=' + goed.length, 'import');
    }
    const inhoud = h`<p><a href="/beheer/partners/import">&larr; Ander bestand</a></p><h1>Partners importeren: controle</h1>
      <p>${goed.length} van de ${deel.regels.length} regels zijn goed.${goed.length < deel.regels.length ? ' Regels met een fout slaan wij over; verbeter ze in het bestand en importeer ze daarna nog eens.' : ''}</p>
      <div class="tabel-wrap"><table class="tabel"><thead><tr><th>Regel</th><th>Naam</th><th>Soort</th><th>Rechtsvorm</th><th>Resultaat</th></tr></thead><tbody>
        ${deel.regels.map((r) => h`<tr><td class="getal">${r.regel}</td><td>${r.waarden.naam}</td><td>${r.waarden.type ? typeNaam(r.waarden.type) : ''}</td>
          <td>${r.waarden.rechtsvorm && r.waarden.rechtsvorm !== 'particulier' ? vormNaam(r.waarden.rechtsvorm) : ''}</td>
          <td>${Object.keys(r.fouten).length ? h`<span class="import-fout">${Object.values(r.fouten).join(' ')}</span>` : 'Goed'}</td></tr>`)}
      </tbody></table></div>
      ${goed.length ? h`<form method="post" action="/beheer/partners/import" class="kaart">${beheer.csrfVeld(sessie)}<input type="hidden" name="stap" value="opslaan">
        <input type="hidden" name="csv" value="${tekst}">
        <button type="submit">${goed.length} partner${goed.length === 1 ? '' : 's'} toevoegen</button></form>` : ''}`;
    return beheer.pagina(res, sessie, 'Partners importeren', 'partners', inhoud);
  }

  function voorbeeldCsv(res) {
    const kop = ['naam', 'type', 'rechtsvorm', 'contactpersoon', 'telefoon', 'email', 'status', 'code', 'landingspagina', 'notities'];
    return beheer.bestand(res, 'partners-voorbeeld.csv', 'text/csv; charset=utf-8', csv({ kolommen: kop.map((k) => ({ kop: k })), rijen: [] }));
  }

  beheer.route('GET', /^\/beheer\/partners$/, (req, res, url, s) => lijst(res, url, s));
  beheer.route('GET', /^\/beheer\/partners\/nieuw$/, (req, res, url, s) => nieuwFormulier(res, s));
  beheer.route('POST', /^\/beheer\/partners\/nieuw$/, (req, res, url, s, m, b) => maakNieuw(res, s, b));
  beheer.route('GET', /^\/beheer\/partners\/import$/, (req, res, url, s) => importFormulier(res, s));
  beheer.route('POST', /^\/beheer\/partners\/import$/, (req, res, url, s, m, b) => importeer(res, s, b), { groot: true });
  beheer.route('GET', /^\/beheer\/partners\/voorbeeld\.csv$/, (req, res) => voorbeeldCsv(res));
  beheer.route('GET', /^\/beheer\/partner\/(\d+)$/, (req, res, url, s, m) => detail(res, url, s, m[1]));
  beheer.route('POST', /^\/beheer\/partner\/(\d+)$/, (req, res, url, s, m, b) => opslaan(res, url, s, m[1], b));
  beheer.route('POST', /^\/beheer\/partner\/(\d+)\/status$/, (req, res, url, s, m, b) => zetStatus(res, s, m[1], b));
  beheer.route('POST', /^\/beheer\/partner\/(\d+)\/verwijderen$/, (req, res, url, s, m) => verwijder(res, s, m[1]));
  beheer.route('GET', /^\/beheer\/partner\/(\d+)\/qr\.svg$/, (req, res, url, s, m) => qrBestand(res, s, m[1]));
  beheer.route('GET', /^\/beheer\/partner\/(\d+)\/kaart\.pdf$/, (req, res, url, s, m) => kaart(res, s, m[1]));
}

module.exports = { registreer, controleer, leesCsv, csvNaarInvoer, maakCode, typeVan, rechtsvormVan, kaartPdf, linkVan, TYPES, LANDINGEN, KAART_REGEL };
