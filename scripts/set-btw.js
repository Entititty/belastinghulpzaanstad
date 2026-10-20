#!/usr/bin/env node
/*
 * set-btw.js
 * Vervangen in oktober 2026 door VAT_NOTE in data/bedrijf.json.
 *
 * WAT HET WAS
 * Dit script haalde op 27 augustus 2026 alle "inclusief BTW"-vermeldingen
 * van de site (136 claims in 30 bestanden) en kon ze bit-identiek
 * terugzetten zodra er een BTW-registratie was.
 *
 * WAAROM HET NIET MEER WERKT
 * Sindsdien zijn de pagina's veranderd: de prijzen staan in data-prijs-spans
 * en een deel van de zinnen is herschreven. Een proefdraai van --zet vond
 * op 20 oktober 2026 nog 61 van de vermeldingen terug, in 21 bestanden.
 * Terugzetten zou dus een half beeld geven: op de ene pagina "inclusief
 * BTW", op de andere niets.
 *
 * WAT ER NU IS
 * Eén zin over de btw, op /tarieven/, uit data/bedrijf.json:
 *   "VAT_NOTE": "Alle prijzen zijn inclusief btw."
 * of, bij de kleineondernemersregeling:
 *   "VAT_NOTE": "Wij vallen onder de kleineondernemersregeling; u betaalt geen btw."
 * met daarbij "KOR": true of false. Draai daarna node scripts/config-sync.js.
 * Het btw-id in de footer zet je met node scripts/set-kvk.js.
 *
 * De oude vervangtabel staat in de git-geschiedenis van dit bestand
 * (git log -- scripts/set-btw.js), mocht je hem ooit nodig hebben.
 */
console.error('set-btw.js is vervangen. Zet de btw-zin als VAT_NOTE in data/bedrijf.json');
console.error('en draai daarna: node scripts/config-sync.js');
console.error('Zie de toelichting bovenin scripts/set-btw.js.');
process.exit(1);
