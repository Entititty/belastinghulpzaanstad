#!/usr/bin/env node
/*
 * check-formulieren.js
 * Bewaakt dat elk formulier op de site naar de eigen app gaat, en dat wat de
 * bezoeker ziet klopt met wat de app opslaat. Faalt (exit 1) bij een afwijking.
 *
 * WAAROM
 * De app slaat bij elke aanvraag de toestemmingstekst op die bij de versie
 * hoort (data/aanvraag.json). Staat er op de pagina een andere tekst, dan is
 * de opgeslagen toestemming niet de toestemming die gegeven is. Een pagina die
 * uit een oude kopie komt, neemt bovendien de Formspree-action mee; dan komt
 * de aanvraag nooit in /beheer. Dit script vangt beide.
 *
 * WAT HET CONTROLEERT (pagina's met een meta-refresh tellen niet mee)
 * - action is /api/aanvraag, /api/herinnering, /api/herinnering/bevestig of
 *   /api/herinnering/afmelden; method is POST
 * - aanvraag: verborgen "formulier" en "toestemming_versie"; de versie bestaat
 *   en hoort bij het soort formulier; honeypot _gotcha in .form-hp; naam en
 *   telefoon verplicht; dienst als keuzelijst met precies de diensten uit de
 *   instellingen, of verborgen met een bestaande code; voorkeurstijd idem; het
 *   akkoordvinkje verplicht met letterlijk de tekst uit het register; bij een
 *   bericht e-mail en bericht verplicht; bij een rekentool een bestaande
 *   rekentool, het veld "berekening" en data-rh-lead
 * - herinnering: versie herinnering-*, honeypot, e-mail verplicht, en de tekst
 *   in .form-consent-tekst letterlijk gelijk aan het register
 * - bevestigen/afmelden: een verborgen veld t
 * - elke toestemmingstekst voor aanvragen noemt de bewaartermijn uit
 *   bewaren.aanvraag_maanden
 *
 * GEBRUIK
 *   node scripts/check-formulieren.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'aanvraag.json'), 'utf8'));
const DIENSTEN = cfg.diensten.map((d) => d.code);
const TIJDEN = cfg.voorkeurstijden.map((d) => d.code);
const ACTIES = ['/api/aanvraag', '/api/herinnering', '/api/herinnering/bevestig', '/api/herinnering/afmelden'];
const SOORTEN = ['terugbellen', 'rekentool', 'bericht'];

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['.git', 'node_modules', 'docs', 'reports', 'intern', 'app'].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name.endsWith('.html')) acc.push(p);
  }
  return acc;
}

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', nbsp: ' ', rsquo: '’', lsquo: '‘', ndash: '–', mdash: '—', euro: '€', eacute: 'é', euml: 'ë', ldquo: '“', rdquo: '”' };
function tekst(html) {
  return html.replace(/<[^>]+>/g, '')
    .replace(/&#(\d+);/g, (h, n) => String.fromCodePoint(Number(n)))
    .replace(/&([a-z]+);/g, (h, n) => (n in ENT ? ENT[n] : h))
    .replace(/\s+/g, ' ').trim();
}
function attr(tag, naam) {
  const m = new RegExp('\\s' + naam + '(?:="([^"]*)")?(?=[\\s>/])').exec(tag);
  return m ? (m[1] === undefined ? '' : m[1]) : undefined;
}
function tags(html, soort) { return html.match(new RegExp('<' + soort + '\\b[^>]*>', 'g')) || []; }
function veld(html, naam) { return tags(html, 'input').concat(tags(html, 'select'), tags(html, 'textarea')).find((t) => attr(t, 'name') === naam); }
function verborgen(html, naam) {
  const t = tags(html, 'input').find((x) => attr(x, 'name') === naam && attr(x, 'type') === 'hidden');
  return t ? attr(t, 'value') : undefined;
}
function opties(html, naam) {
  const m = new RegExp('<select\\b[^>]*name="' + naam + '"[^>]*>([\\s\\S]*?)</select>').exec(html);
  return m ? (m[1].match(/<option\b[^>]*value="([^"]*)"/g) || []).map((o) => /value="([^"]*)"/.exec(o)[1]) : null;
}
const gelijk = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/* de toestemmingsteksten zelf */
const fouten = [];
for (const [versie, t] of Object.entries(cfg.toestemming)) {
  if (!/^herinnering-/.test(versie) && t.indexOf(cfg.bewaren.aanvraag_maanden + ' maanden') === -1) {
    fouten.push('data/aanvraag.json: toestemming ' + versie + ' noemt niet "' + cfg.bewaren.aanvraag_maanden + ' maanden" (bewaren.aanvraag_maanden). Maak een nieuwe versie.');
  }
}

let paginas = 0, formulieren = 0;
for (const f of walk(ROOT, [])) {
  const ruw = fs.readFileSync(f, 'utf8');
  if (/<meta http-equiv="refresh"/.test(ruw)) continue;
  const rel = path.relative(ROOT, f).split(path.sep).join('/');
  const html = ruw.replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/g, '');
  const fout = (m) => fouten.push(rel + ': ' + m);
  const vormen = [...html.matchAll(/(<form\b[^>]*>)([\s\S]*?)<\/form>/g)];
  if (!vormen.length) continue;
  paginas++;
  for (const [, open, binnen] of vormen) {
    formulieren++;
    const actie = attr(open, 'action');
    if (!ACTIES.includes(actie)) { fout('formulier gaat naar ' + JSON.stringify(actie) + ' (alleen de eigen app: ' + ACTIES.join(', ') + ')'); continue; }
    if ((attr(open, 'method') || '').toUpperCase() !== 'POST') fout(actie + ': method moet POST zijn');
    const honeypot = /<div class="form-hp" aria-hidden="true">[\s\S]*?name="_gotcha"/.test(binnen);

    if (actie === '/api/herinnering/bevestig' || actie === '/api/herinnering/afmelden') {
      if (verborgen(binnen, 't') === undefined) fout(actie + ': verborgen veld t ontbreekt');
      continue;
    }
    const versie = verborgen(binnen, 'toestemming_versie');
    const register = cfg.toestemming[versie];
    if (!register) { fout(actie + ': onbekende toestemmingsversie ' + JSON.stringify(versie)); continue; }
    if (!honeypot) fout(actie + ': honeypot _gotcha in .form-hp ontbreekt');

    if (actie === '/api/herinnering') {
      if (!/^herinnering-/.test(versie)) fout('herinnering met versie ' + versie);
      const e = veld(binnen, 'email');
      if (!e || attr(e, 'required') === undefined || attr(e, 'type') !== 'email') fout('herinnering: verplicht e-mailveld ontbreekt');
      const m = /<p class="form-consent-tekst">([\s\S]*?)<\/p>/.exec(binnen);
      if (!m) fout('herinnering: .form-consent-tekst ontbreekt');
      else if (tekst(m[1]) !== register) fout('herinnering: tekst wijkt af van ' + versie + ':\n      pagina:   ' + tekst(m[1]) + '\n      register: ' + register);
      continue;
    }

    /* /api/aanvraag */
    const soort = verborgen(binnen, 'formulier');
    if (!SOORTEN.includes(soort)) { fout('onbekend formulier ' + JSON.stringify(soort)); continue; }
    if (versie.indexOf(soort + '-') !== 0) fout(soort + ': toestemmingsversie ' + versie + ' hoort bij een ander soort formulier');
    for (const naam of ['naam', 'telefoon']) {
      const x = veld(binnen, naam);
      if (!x || attr(x, 'required') === undefined) fout(soort + ': verplicht veld ' + naam + ' ontbreekt');
    }
    const tel = veld(binnen, 'telefoon');
    if (tel && attr(tel, 'type') !== 'tel') fout(soort + ': telefoon moet type="tel" zijn');
    const dienstVast = verborgen(binnen, 'dienst');
    const dienstLijst = opties(binnen, 'dienst');
    if (dienstVast !== undefined) { if (!DIENSTEN.includes(dienstVast)) fout(soort + ': onbekende dienst ' + dienstVast); }
    else if (!dienstLijst) fout(soort + ': geen dienst (keuzelijst of verborgen veld)');
    else if (!gelijk(dienstLijst, DIENSTEN)) fout(soort + ': de keuzelijst dienst wijkt af van data/aanvraag.json');
    const tijden = opties(binnen, 'voorkeurstijd');
    if (tijden && !gelijk(tijden, TIJDEN)) fout(soort + ': de keuzelijst voorkeurstijd wijkt af van data/aanvraag.json');
    const m = /<label class="form-consent">([\s\S]*?)<\/label>/.exec(binnen);
    if (!m) fout(soort + ': akkoordvinkje (label.form-consent) ontbreekt');
    else {
      const vink = tags(m[1], 'input')[0] || '';
      if (attr(vink, 'name') !== 'akkoord' || attr(vink, 'type') !== 'checkbox' || attr(vink, 'required') === undefined) fout(soort + ': het vinkje moet name="akkoord", type="checkbox" en required zijn');
      if (tekst(m[1]) !== register) fout(soort + ': toestemmingstekst wijkt af van ' + versie + ':\n      pagina:   ' + tekst(m[1]) + '\n      register: ' + register);
    }
    if (soort === 'bericht') {
      for (const naam of ['email', 'opmerking']) {
        const x = veld(binnen, naam);
        if (!x || attr(x, 'required') === undefined) fout('bericht: verplicht veld ' + naam + ' ontbreekt');
      }
    }
    if (soort === 'rekentool') {
      const tool = verborgen(binnen, 'rekentool');
      if (!cfg.rekentools[tool]) fout('rekentool: onbekende rekentool ' + JSON.stringify(tool));
      if (verborgen(binnen, 'berekening') === undefined) fout('rekentool: verborgen veld berekening ontbreekt');
      if (attr(open, 'data-rh-lead') === undefined) fout('rekentool: data-rh-lead ontbreekt (dan vult rekenhulp.js de berekening niet in)');
    }
  }
}

console.log('check-formulieren: ' + formulieren + ' formulieren op ' + paginas + ' pagina\'s');
if (fouten.length) {
  console.error('FAIL: ' + fouten.length + ' afwijking(en):');
  fouten.slice(0, 40).forEach((e) => console.error('  - ' + e));
  process.exit(1);
}
console.log('OK: alle formulieren gaan naar de eigen app, met de juiste toestemmingstekst.');
