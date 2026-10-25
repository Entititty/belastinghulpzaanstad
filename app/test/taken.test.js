'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./hulp');
const { opruimen, maakPlanner } = require('../lib/taken');

test('bewaartermijn: geen klant na 12 maanden weg, klant blijft, notities gaan mee', async () => {
  const t = await startApp({ start: '2026-11-02T19:00:00Z' });
  try {
    const voeg = t.db.prepare(`INSERT INTO aanvragen (aangemaakt, kanaal, naam, telefoon, dienst, bron, grondslag, status, klant_sinds, gewijzigd)
      VALUES (?, 'formulier', 'x', '+31612345678', 'aangifte', 'direct', 'toestemming', ?, ?, ?)`);
    const oud = voeg.run('2025-11-01T10:00:00.000Z', 'gebeld', null, 'x').lastInsertRowid;
    const oudKlant = voeg.run('2025-10-01T10:00:00.000Z', 'klant', '2025-10-05T10:00:00.000Z', 'x').lastInsertRowid;
    const recent = voeg.run('2025-11-03T10:00:00.000Z', 'nieuw', null, 'x').lastInsertRowid;
    const heelOudeKlant = voeg.run('2018-01-01T10:00:00.000Z', 'klant', '2018-01-02T10:00:00.000Z', 'x').lastInsertRowid;
    t.db.prepare("INSERT INTO notities (aanvraag_id, tijd, tekst) VALUES (?, 'x', 'gebeld, geen gehoor')").run(oud);

    const r = opruimen(t.ctx);
    assert.equal(r.aanvragen, 1);
    assert.equal(r.klanten, 1);
    const over = t.db.prepare('SELECT id FROM aanvragen ORDER BY id').all().map((x) => x.id);
    assert.deepEqual(over, [Number(oudKlant), Number(recent)]);
    assert.equal(t.db.prepare('SELECT COUNT(*) n FROM notities').get().n, 0);
    assert.ok(!over.includes(Number(heelOudeKlant)));
    assert.match(t.db.prepare("SELECT details FROM logboek WHERE actie = 'opgeruimd'").get().details, /^1 aanvragen, 1 oude klanten/);
  } finally {
    await t.stop();
  }
});

test('mailwachtrij: opgegeven mails na 7 dagen weg, en mails die nooit weg konden na 9', async () => {
  const t = await startApp({ start: '2026-11-20T02:30:00Z' });
  try {
    /* volgende poging ver weg, zodat de wachtrij ze in deze test niet verstuurt */
    const voeg = t.db.prepare(`INSERT INTO uitgaand (soort, aan, onderwerp, tekst, volgende_poging, gestopt, aangemaakt)
      VALUES ('dagoverzicht', 'stan@voorbeeld.nl', 'Dagoverzicht', 'Jan, 06 12 34 56 78', '2099-01-01T00:00:00.000Z', ?, ?)`);
    voeg.run('2026-11-12T10:00:00.000Z', '2026-11-10T10:00:00.000Z');
    voeg.run(null, '2026-11-10T10:00:00.000Z');
    const jong = voeg.run(null, '2026-11-15T10:00:00.000Z').lastInsertRowid;
    const r = opruimen(t.ctx);
    assert.equal(r.mails, 2);
    assert.deepEqual(t.db.prepare('SELECT id FROM uitgaand ORDER BY id').all().map((x) => x.id), [Number(jong)]);
  } finally {
    await t.stop();
  }
});

test('planner: een dagtaak één keer per dag, alleen binnen twee uur na zijn tijd', async () => {
  const t = await startApp({ start: '2026-11-02T15:00:00Z' });
  try {
    let n = 0;
    const p = maakPlanner(t.ctx, [{ naam: 'proef', om: '17:30', doe: () => { n++; } }]);
    await p.tik();
    assert.equal(n, 0, '16:00: te vroeg');
    t.zetTijd('2026-11-02T16:31:00Z');
    await p.tik();
    await p.tik();
    assert.equal(n, 1, '17:31: één keer');
    t.zetTijd('2026-11-03T21:00:00Z');
    await p.tik();
    assert.equal(n, 1, '22:00 de dag erna: te laat');
    t.zetTijd('2026-11-04T16:45:00Z');
    await p.tik();
    assert.equal(n, 2);
  } finally {
    await t.stop();
  }
});
