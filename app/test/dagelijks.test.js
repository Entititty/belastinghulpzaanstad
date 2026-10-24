'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { startApp, terugbellen } = require('./hulp');
const { dagoverzicht, dagoverzichtTijd, backup, klikkenInlezen } = require('../lib/dagelijks');
const { maakPlanner } = require('../lib/taken');
const { nl } = require('../lib/tijd');
const nep = require('./nep-smtp');

test('dagoverzicht: open aanvragen, nieuw eerst, zonder namen in het onderwerp', async () => {
  const t = await startApp();
  try {
    await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000001', naam: 'Jan Oud' }), { 'X-Real-IP': '198.51.100.1' });
    await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000002', naam: 'Kees Klant' }), { 'X-Real-IP': '198.51.100.2' });
    t.db.prepare("UPDATE aanvragen SET status = 'gebeld' WHERE naam = 'Jan Oud'").run();
    t.db.prepare("UPDATE aanvragen SET status = 'klant' WHERE naam = 'Kees Klant'").run();
    await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000003', naam: 'Nina Nieuw' }), { 'X-Real-IP': '198.51.100.3' });
    await t.wachtrijLeeg();
    const voor = t.smtp.berichten.length;
    dagoverzicht(t.ctx);
    const mails = await t.mails(voor + 1);
    const m = mails[mails.length - 1];
    assert.equal(nep.onderwerp(m.data), 'Dagoverzicht: 2 open (1 nieuw)');
    const tekst = nep.tekst(m.data);
    assert.ok(tekst.indexOf('Nina Nieuw') < tekst.indexOf('Jan Oud'), 'nieuw eerst');
    assert.ok(!tekst.includes('Kees Klant'), 'klanten staan er niet in');
    assert.match(tekst, /tel:\+31612000003/);
    assert.match(tekst, /LET OP: Er is nog geen back-up gemaakt/);
    /* ook als er niets open staat, als teken van leven */
    t.db.prepare("UPDATE aanvragen SET status = 'klant'").run();
    dagoverzicht(t.ctx);
    const nu = await t.mails(voor + 2);
    assert.equal(nep.onderwerp(nu[nu.length - 1].data), 'Dagoverzicht: geen open aanvragen');
  } finally {
    await t.stop();
  }
});

test('dagoverzicht: 17:30 door de week, 08:30 in het weekend', async () => {
  const t = await startApp({ start: '2026-11-07T07:00:00Z' }); /* zaterdag 08:00 */
  try {
    assert.equal(dagoverzichtTijd(t.config)(nl(t.nu())), '08:30');
    assert.equal(dagoverzichtTijd(t.config)(nl(new Date('2026-11-09T12:00:00Z'))), '17:30'); /* maandag */
    let n = 0;
    const p = maakPlanner(t.ctx, [{ naam: 'dagoverzicht', om: dagoverzichtTijd(t.config), doe: () => { n++; } }]);
    await p.tik();
    assert.equal(n, 0, '08:00: nog niet');
    t.zetTijd('2026-11-07T07:31:00Z');
    await p.tik();
    assert.equal(n, 1, 'zaterdag 08:31');
    t.zetTijd('2026-11-09T16:31:00Z');
    await p.tik();
    assert.equal(n, 2, 'maandag 17:31');
  } finally {
    await t.stop();
  }
});

test('back-up: een leesbare kopie, oude na 14 dagen weg', async () => {
  const t = await startApp({ start: '2026-11-20T02:45:00Z' });
  try {
    await t.post('/api/aanvraag', terugbellen({ telefoon: '0612000009' }), { 'X-Real-IP': '198.51.100.9' });
    const map = t.ctx.env.BHZ_BACKUP_MAP;
    fs.mkdirSync(map, { recursive: true });
    fs.writeFileSync(path.join(map, 'leads-2026-11-01.db'), 'oud');
    fs.writeFileSync(path.join(map, 'leads-2026-11-10.db'), 'jonger');
    fs.writeFileSync(path.join(map, 'iets-anders.txt'), 'blijft');
    const r = backup(t.ctx);
    assert.equal(r.naam, 'leads-2026-11-20.db');
    assert.deepEqual(fs.readdirSync(map).sort(), ['iets-anders.txt', 'leads-2026-11-10.db', 'leads-2026-11-20.db']);
    const kopie = new DatabaseSync(path.join(map, 'leads-2026-11-20.db'), { readOnly: true });
    assert.equal(kopie.prepare('SELECT COUNT(*) AS n FROM aanvragen').get().n, 1);
    kopie.close();
    backup(t.ctx); /* nog eens dezelfde dag: overschrijven, geen fout */
    assert.ok(t.db.prepare("SELECT waarde FROM instellingen WHERE sleutel = 'backup-laatste'").get());
  } finally {
    await t.stop();
  }
});

test('klikken inlezen: tellen per dag, herhaalbaar, rommel overslaan', async () => {
  const t = await startApp();
  try {
    const map = t.ctx.env.BHZ_TELLINGEN_MAP;
    fs.mkdirSync(map, { recursive: true });
    const regel = (o) => JSON.stringify(Object.assign({ t: '2026-11-01T19:00', v: '' }, o));
    fs.writeFileSync(path.join(map, '2026-11-01.ndjson'), [
      regel({ e: 'whatsapp', p: '/senioren/', k: 'balk', b: 'flyer', c: 'rosmolenwijk' }),
      regel({ e: 'whatsapp', p: '/senioren/', k: 'balk', b: 'flyer', c: 'rosmolenwijk' }),
      regel({ e: 'tel', p: '/', k: 'hero', b: 'direct', c: '' }),
      regel({ e: 'tel', p: '/' }), /* oude regel zonder k, b, c */
      'geen json', regel({ e: 'onbekend', p: '/' }), regel({ e: 'tel', p: '/', k: '<script>' })
    ].join('\n'));
    fs.writeFileSync(path.join(map, 'START'), '2026-11-01');
    let r = klikkenInlezen(t.ctx);
    assert.deepEqual(r, { dagen: 1, regels: 5, fout: 2 });
    const rijen = () => t.db.prepare('SELECT e, p, k, b, c, n FROM klikken ORDER BY e, k').all().map((x) => ({ ...x }));
    assert.deepEqual(rijen(), [
      { e: 'tel', p: '/', k: '', b: '', c: '', n: 1 },
      { e: 'tel', p: '/', k: 'hero', b: 'direct', c: '', n: 1 },
      { e: 'tel', p: '/', k: 'overig', b: '', c: '', n: 1 },
      { e: 'whatsapp', p: '/senioren/', k: 'balk', b: 'flyer', c: 'rosmolenwijk', n: 2 }
    ]);
    /* nog eens: niets dubbel */
    r = klikkenInlezen(t.ctx);
    assert.equal(rijen().reduce((a, x) => a + x.n, 0), 5);
    /* een nieuwe dag erbij */
    fs.appendFileSync(path.join(map, '2026-11-02.ndjson'), regel({ t: '2026-11-02T10:00', e: 'bezoek', p: '/senioren/', b: 'flyer', c: 'kogerveld' }) + '\n');
    klikkenInlezen(t.ctx);
    assert.equal(t.db.prepare("SELECT n FROM klikken WHERE e = 'bezoek'").get().n, 1);
    assert.equal(t.db.prepare("SELECT waarde FROM instellingen WHERE sleutel = 'klikken-laatst'").get().waarde, '2026-11-02');
  } finally {
    await t.stop();
  }
});
