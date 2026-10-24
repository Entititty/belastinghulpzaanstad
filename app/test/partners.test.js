'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { startApp, terugbellen, ROOT } = require('./hulp');
const P = require('../lib/partners');
const qr = require('../lib/qr');
const { matrixVan, uitSvg, uitPdf } = require('./qr-hulp');
const BOM = String.fromCharCode(0xfeff); /* Excel zet die voor een UTF-8-CSV */

test('soort en rechtsvorm: ook zoals mensen het typen; een particulier nooit', () => {
  assert.equal(P.typeVan('Makelaardij'), 'makelaar');
  assert.equal(P.typeVan('NOTARIS'), 'notaris');
  assert.equal(P.typeVan('Ouderenbond of -vereniging'), 'ouderenbond');
  assert.equal(P.typeVan('KBO'), 'ouderenbond');
  assert.equal(P.typeVan('bakker'), null);
  assert.equal(P.rechtsvormVan('B.V.'), 'bv');
  assert.equal(P.rechtsvormVan('Besloten Vennootschap'), 'bv');
  assert.equal(P.rechtsvormVan('v.o.f.'), 'vof');
  assert.equal(P.rechtsvormVan('Coöperatie'), 'cooperatie');
  assert.equal(P.rechtsvormVan('Particulier'), 'particulier');
  assert.equal(P.rechtsvormVan('privé'), 'particulier');
  assert.equal(P.rechtsvormVan(''), null);
});

test('code voor de link: van de naam, zonder rechtsvorm, kort en uniek', () => {
  assert.equal(P.maakCode('Jansen Makelaardij B.V.', () => false), 'jansen-makelaardij');
  assert.equal(P.maakCode('Jansen Makelaardij B.V.', (c) => c === 'jansen-makelaardij'), 'jansen-makelaardij-2');
  assert.equal(P.maakCode('Notariskantoor Het Zaanse Huis Coöperatie U.A.', () => false), 'notariskantoor-het-zaanse-huis');
  assert.equal(P.maakCode('!!!', () => false), 'partner');
});

test('CSV lezen: puntkomma, komma of tab, aanhalingstekens, BOM, een regel in een veld', () => {
  assert.deepEqual(P.leesCsv(BOM + 'naam;type\r\n"Jansen; Zn";makelaar\r\n\r\n'), [['naam', 'type'], ['Jansen; Zn', 'makelaar']]);
  assert.deepEqual(P.leesCsv('naam,notities\nA,"zei ""ja""\nen nog wat"\n'), [['naam', 'notities'], ['A', 'zei "ja"\nen nog wat']]);
  assert.deepEqual(P.leesCsv('naam\ttype\nA\tnotaris'), [['naam', 'type'], ['A', 'notaris']]);
  const invoer = P.csvNaarInvoer(P.leesCsv('Bedrijfsnaam;Soort;Rechtsvorm;E-mail;Telefoonnummer\nA;notaris;BV;a@b.nl;075 123 4567'));
  assert.deepEqual(invoer, [{ regel: 2, naam: 'A', type: 'notaris', rechtsvorm: 'BV', email: 'a@b.nl', telefoon: '075 123 4567' }]);
  assert.equal(P.csvNaarInvoer(P.leesCsv('foo;bar\n1;2')), null);
});

test('elke landingspagina bestaat; elk soort en elke kaarttekst hoort bij een pagina uit de lijst', () => {
  for (const [pad] of P.LANDINGEN) assert.ok(fs.existsSync(path.join(ROOT, pad, 'index.html')), pad);
  for (const t of P.TYPES) assert.ok(P.LANDINGEN.some(([p]) => p === t.landing), t.code);
  for (const pad of Object.keys(P.KAART_REGEL)) assert.ok(P.LANDINGEN.some(([p]) => p === pad), pad);
});

test('partners in /beheer: toevoegen, link en QR, kaart, stoppen, importeren, verwijderen', async () => {
  const t = await startApp();
  try {
    const b = await t.beheer();
    /* een aanvraag met de code van een partner die er nog niet is */
    let r = await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000101', h_ref: 'jansen-makelaardij' }));
    assert.equal(r.status, 200);

    let s = await (await b.haal('/beheer/partners')).text();
    assert.match(s, /Nog geen partners/);
    assert.match(s, /<a href="\/beheer\/partners" aria-current="page">Partners<\/a>/);

    /* een particulier en een fout nummer: niet */
    r = await b.stuur('/beheer/partners/nieuw', { naam: 'Piet Particulier', type: 'anders', rechtsvorm: 'particulier', telefoon: 'onzin' });
    assert.equal(r.status, 422);
    s = await r.text();
    assert.match(s, /Een particulier kan geen partner zijn/);
    assert.match(s, /Dit telefoonnummer klopt niet/);
    assert.match(s, /value="onzin"/, 'wat u typte, blijft staan');

    r = await b.stuur('/beheer/partners/nieuw', { naam: 'Jansen Makelaardij B.V.', type: 'makelaar', rechtsvorm: 'bv', contactpersoon: 'Els Jansen',
      telefoon: '075 123 4567', email: 'Els@Jansen.example', status: 'actief', notities: 'kaartjes op de balie' });
    assert.equal(r.status, 303);
    const p = t.db.prepare('SELECT * FROM partners').get();
    assert.equal(r.headers.get('location'), '/beheer/partner/' + p.id + '?m=nieuw');
    assert.equal(p.ref_code, 'jansen-makelaardij');
    assert.equal(p.telefoon, '+31751234567');
    assert.equal(p.email, 'els@jansen.example');
    assert.equal(p.status, 'actief');
    /* de aanvraag van eerder hangt nu aan de partner */
    const a = t.db.prepare("SELECT partner_id, bron, bron_detail FROM aanvragen WHERE ref = 'jansen-makelaardij'").get();
    assert.deepEqual({ ...a }, { partner_id: p.id, bron: 'partner', bron_detail: 'Jansen Makelaardij B.V.' });

    /* bezoeken en klikken via de link (uit de klikmeting) */
    t.db.prepare("INSERT INTO klikken (dag, e, p, k, b, c, n) VALUES ('2026-11-01', 'bezoek', '/diensten/voorlopige-teruggave/', '', 'partner', 'jansen-makelaardij', 7)").run();
    t.db.prepare("INSERT INTO klikken (dag, e, p, k, b, c, n) VALUES ('2026-11-01', 'whatsapp', '/diensten/voorlopige-teruggave/', 'balk', 'partner', 'jansen-makelaardij', 2)").run();
    const link = 'https://belastinghulpzaanstad.nl/diensten/voorlopige-teruggave/?ref=jansen-makelaardij';
    s = (await (await b.haal('/beheer/partner/' + p.id + '?m=nieuw')).text()).replace(/>\s+</g, '><');
    assert.ok(s.includes('value="' + link + '"'));
    assert.match(s, /Doorverwijzingen<\/div><div class="kpi-waarde">1</);
    assert.match(s, /Bezoeken via de link<\/div><div class="kpi-waarde">7</);
    assert.match(s, /Daarna bellen of WhatsApp<\/div><div class="kpi-waarde">2</);
    assert.match(s, /aria-label="QR-code voor Jansen Makelaardij B\.V\."/);
    assert.match(s, /Partner toegevoegd\./);
    s = await (await b.haal('/beheer/partners')).text();
    assert.match(s, /1 doorverwijzing · 0 klanten · € 0,00 · 7 bezoeken via de link/);

    /* de QR-code: precies het adres */
    r = await b.haal('/beheer/partner/' + p.id + '/qr.svg');
    assert.equal(r.headers.get('content-type'), 'image/svg+xml');
    assert.match(r.headers.get('content-disposition'), /filename="qr-jansen-makelaardij\.svg"/);
    assert.deepEqual(uitSvg(await r.text()), matrixVan(qr.maak(link, 'M')));

    /* de kaart: PDF met onze gegevens en de QR-code, zonder de contactpersoon */
    r = await b.haal('/beheer/partner/' + p.id + '/kaart.pdf');
    assert.equal(r.headers.get('content-type'), 'application/pdf');
    assert.match(r.headers.get('content-disposition'), /filename="kaart-jansen-makelaardij\.pdf"/);
    const kaart = Buffer.from(await r.arrayBuffer()).toString('latin1');
    assert.ok(kaart.startsWith('%PDF-1.4'));
    assert.match(kaart, /\/MediaBox \[0 0 420 595\]/, 'A5');
    for (const tekst of ['(Doorverwezen door) Tj', '(Jansen Makelaardij B.V.) Tj', '(06 19 71 18 48) Tj', 'Net een huis gekocht?', '(Belastinghulp Zaanstad) Tj']) {
      assert.ok(kaart.includes(tekst), tekst);
    }
    assert.ok(!/Els|kaartjes|075/.test(kaart), 'geen contactpersoon, notities of nummer van de partner op de kaart');
    const q = qr.maak(link, 'M');
    assert.deepEqual(uitPdf(kaart, q.grootte), matrixVan(q));

    /* "+ Nieuw" (wie belde) kan de partner kiezen */
    assert.match(await (await b.haal('/beheer/nieuw')).text(), /<option value="\d+">Jansen Makelaardij B\.V\.<\/option>/);

    /* importeren: eerst bekijken, dan alleen de goede regels */
    const bestand = [
      'naam;type;rechtsvorm;contactpersoon;telefoon;email;status;code;landingspagina',
      'Notariskantoor Zaan;notaris;B.V.;;075 765 4321;;actief;;',
      'Buurthuis De Kolk;Buurthuis;Stichting;;;;;kolk;senioren',
      'Piet Prive;anders;particulier;;;;;;',
      'Zonder Soort;;BV;;;;;;',
      'Jansen Makelaardij B.V.;makelaar;bv;;;;;;',
      'Fout Nummer;notaris;bv;;12;;;;'
    ].join('\r\n');
    r = await b.stuur('/beheer/partners/import', { stap: 'voorbeeld', csv: bestand });
    assert.equal(r.status, 200);
    s = await r.text();
    assert.match(s, /2 van de 6 regels zijn goed/);
    for (const fout of ['Een particulier kan geen partner zijn', 'Kies het soort partner', 'Er is al een partner met deze naam', 'Dit telefoonnummer klopt niet']) {
      assert.ok(s.includes(fout), fout);
    }
    assert.match(s, /2 partners toevoegen/);
    assert.equal(t.db.prepare('SELECT COUNT(*) AS n FROM partners').get().n, 1, 'nog niets opgeslagen');
    r = await b.stuur('/beheer/partners/import', { stap: 'opslaan', csv: bestand });
    assert.equal(r.status, 303);
    assert.equal(r.headers.get('location'), '/beheer/partners?n=2&m=import');
    const kolk = t.db.prepare("SELECT * FROM partners WHERE ref_code = 'kolk'").get();
    assert.deepEqual([kolk.naam, kolk.type, kolk.rechtsvorm, kolk.landingspagina, kolk.status], ['Buurthuis De Kolk', 'buurthuis', 'stichting', '/senioren/', 'benaderd']);
    assert.equal(t.db.prepare("SELECT ref_code FROM partners WHERE naam = 'Notariskantoor Zaan'").get().ref_code, 'notariskantoor-zaan');
    assert.match(await (await b.haal('/beheer/partners?n=2&m=import')).text(), /Toegevoegd: 2 partner\(s\)\./);
    r = await b.stuur('/beheer/partners/import', { stap: 'voorbeeld', csv: 'bedrijf2;type\nA;notaris' });
    assert.equal(r.status, 422);
    assert.match(await r.text(), /Geen kolom &quot;naam&quot; gevonden/);
    r = await b.haal('/beheer/partners/voorbeeld.csv');
    assert.equal(Buffer.from(await r.arrayBuffer()).toString('utf8'), BOM + 'naam;type;rechtsvorm;contactpersoon;telefoon;email;status;code;landingspagina;notities\r\n');

    /* wijzigen: een code van een ander of met rare tekens niet */
    const basis = { naam: 'Jansen Makelaardij B.V.', type: 'makelaar', rechtsvorm: 'bv', contactpersoon: 'Els Jansen', telefoon: '075 123 4567' };
    r = await b.stuur('/beheer/partner/' + p.id, Object.assign({}, basis, { ref_code: 'kolk' }));
    assert.equal(r.status, 422);
    assert.match(await r.text(), /Deze code is al van een andere partner/);
    r = await b.stuur('/beheer/partner/' + p.id, Object.assign({}, basis, { ref_code: 'jansen!' }));
    assert.equal(r.status, 422);
    r = await b.stuur('/beheer/partner/' + p.id, Object.assign({}, basis, { ref_code: 'jansen', landingspagina: '/senioren/' }));
    assert.equal(r.status, 303);
    assert.deepEqual({ ...t.db.prepare('SELECT ref_code, landingspagina FROM partners WHERE id = ?').get(p.id) }, { ref_code: 'jansen', landingspagina: '/senioren/' });

    /* gestopt: contactgegevens en notities weg, de naam en de cijfers blijven */
    r = await b.stuur('/beheer/partner/' + p.id + '/status', { status: 'gestopt' });
    assert.equal(r.status, 303);
    assert.deepEqual({ ...t.db.prepare('SELECT naam, status, contactpersoon, telefoon, email, notities FROM partners WHERE id = ?').get(p.id) },
      { naam: 'Jansen Makelaardij B.V.', status: 'gestopt', contactpersoon: null, telefoon: null, email: null, notities: null });
    assert.match(await (await b.haal('/beheer/partner/' + p.id + '?m=gestopt')).text(), /Samenwerking gestopt/);
    r = await b.stuur('/beheer/partner/' + p.id, Object.assign({}, basis, { ref_code: 'jansen', notities: 'toch' }));
    assert.equal(r.status, 303);
    assert.deepEqual({ ...t.db.prepare('SELECT telefoon, notities FROM partners WHERE id = ?').get(p.id) }, { telefoon: null, notities: null }, 'blijft leeg zolang gestopt');
    assert.ok(!(await (await b.haal('/beheer/nieuw')).text()).includes('Jansen Makelaardij'), 'een gestopte partner staat niet in de keuzelijst');
    r = await b.stuur('/beheer/partner/' + p.id + '/status', { status: 'actief' });
    assert.equal(t.db.prepare('SELECT status FROM partners WHERE id = ?').get(p.id).status, 'actief');

    /* verwijderen: de aanvraag blijft, zonder partner */
    r = await b.stuur('/beheer/partner/' + p.id + '/verwijderen', {});
    assert.equal(r.status, 303);
    assert.equal(r.headers.get('location'), '/beheer/partners?m=verwijderd');
    assert.equal(t.db.prepare("SELECT partner_id FROM aanvragen WHERE ref = 'jansen-makelaardij'").get().partner_id, null);
    assert.equal((await b.haal('/beheer/partner/' + p.id)).status, 404);

    /* nooit mail aan een partner, en geen namen in het logboek */
    await t.wachtrijLeeg();
    assert.ok(!JSON.stringify(t.smtp.berichten).includes('jansen.example'));
    const log = t.db.prepare('SELECT group_concat(actie || details) AS d FROM logboek').get().d;
    assert.ok(!/Jansen|Els|Kolk/.test(log), log);
    assert.match(log, /partner toegevoegd/);
    assert.match(log, /partners geïmporteerd2 toegevoegd, 4 overgeslagen/);
  } finally {
    await t.stop();
  }
});
