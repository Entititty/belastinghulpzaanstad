#!/usr/bin/env node
/*
 * check-fiscale-cijfers.js
 * Eén bron van waarheid: data/fiscale-cijfers.json.
 * Dit script faalt (exit 1) als een VEROUDERDE fiscale waarde nog in de HTML staat.
 * Zo voorkom je dat oude cijfers (bv. 36,93% of ouderenkorting €2.035) terugsluipen.
 *
 * Gebruik:  node scripts/check-fiscale-cijfers.js
 * Er is geen build op de server; draai dit vóór elke push (of in een pre-commit hook).
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'fiscale-cijfers.json'), 'utf8'));

const guards = [];
for (const [key, c] of Object.entries(data.cijfers)) {
  (c.verouderd || []).forEach(function (old) { guards.push({ key: key, old: old, correct: c.waarde }); });
}

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      walk(path.join(dir, e.name), acc);
    } else if (e.name.endsWith('.html')) {
      acc.push(path.join(dir, e.name));
    }
  }
  return acc;
}

const files = walk(ROOT, []);
let hits = 0;
for (const f of files) {
  const lines = fs.readFileSync(f, 'utf8').split(/\r?\n/);
  lines.forEach(function (ln, i) {
    for (const g of guards) {
      if (ln.indexOf(g.old) !== -1) {
        hits++;
        console.log('STALE  ' + path.relative(ROOT, f) + ':' + (i + 1) + '  "' + g.old + '"  -> gebruik ' + g.correct + '  (' + g.key + ')');
      }
    }
  });
}

console.log('\nGescand: ' + files.length + ' HTML-bestanden, ' + guards.length + ' verouderde waarden bewaakt (belastingjaar ' + data.belastingjaar + ').');
if (hits) {
  console.error('FAIL: ' + hits + ' verouderde waarde(n) gevonden. Corrigeer ze of werk data/fiscale-cijfers.json bij.');
  process.exit(1);
}
console.log('OK: geen verouderde fiscale waarden in de HTML.');
