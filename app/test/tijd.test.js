'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const t = require('../lib/tijd');

test('Nederlandse tijd in winter en zomer', () => {
  assert.deepEqual(t.nl(new Date('2027-02-25T09:00:00Z')), { datum: '2027-02-25', tijd: '10:00', weekdag: 4 });
  assert.deepEqual(t.nl(new Date('2026-07-01T15:30:00Z')), { datum: '2026-07-01', tijd: '17:30', weekdag: 3 });
  assert.equal(t.nl(new Date('2026-10-24T22:30:00Z')).datum, '2026-10-25');
});

test('kloktijd naar Date', () => {
  assert.equal(t.vanNl('2027-02-25 10:00').toISOString(), '2027-02-25T09:00:00.000Z');
  assert.equal(t.vanNl('2026-07-01 17:30').toISOString(), '2026-07-01T15:30:00.000Z');
  assert.throws(() => t.vanNl('25-02-2027'));
  assert.throws(() => t.vanNl('2027-03-28 02:30'), /zomertijd/);
});

test('maanden terug', () => {
  assert.equal(t.minMaanden(new Date('2026-11-02T19:00:00Z'), 12).toISOString(), '2025-11-02T19:00:00.000Z');
});
