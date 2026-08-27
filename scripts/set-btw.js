#!/usr/bin/env node
/*
 * set-btw.js
 * Haalt de BTW-vermeldingen van de site of zet ze terug.
 *
 * WAAROM
 * De onderneming is nog niet bij de KvK ingeschreven en heeft dus geen
 * BTW-identificatienummer. Zolang dat zo is mag er nergens staan dat een
 * prijs "inclusief BTW" is: dat is een bewering over een belasting die niet
 * in rekening wordt gebracht. De prijzen zelf blijven ongewijzigd, alleen de
 * bewering eromheen verdwijnt.
 *
 * Bewust NIET vervangen door "excl. BTW", "vrijgesteld" of "geen BTW". Die
 * beweren alle drie iets nieuws dat ook waar moet zijn. Weglaten beweert niets.
 *
 * De footerregel met het KvK- en BTW-nummer is een aparte zaak: scripts/set-kvk.js.
 *
 * GEBRUIK
 *   node scripts/set-btw.js --verwijder
 *   node scripts/set-btw.js --zet
 *   --dry erbij om alleen te tellen
 *
 * Zodra de BTW-registratie er is:
 *   node scripts/set-btw.js --zet
 *   node scripts/set-kvk.js --kvk <8 cijfers> --btw NL........B..
 *   node scripts/build-sitemap.js
 *
 * OVER DE TABEL
 * Gegenereerd uit de repo, niet met de hand getypt. Exacte strings, geen
 * reguliere expressies. Elke schone vorm is uniek en niet leeg; dat is
 * nodig, want anders pakt de ene regel bij terugzetten het resultaat van de
 * andere weer op, of loopt indexOf op een lege string eeuwig door.
 *
 * De scanner raakt elke positie in het bestand precies een keer aan, dus
 * een vervanging kan nooit opnieuw gevonden worden.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DRY = process.argv.indexOf('--dry') !== -1;
const VERWIJDER = process.argv.indexOf('--verwijder') !== -1;
const ZET = process.argv.indexOf('--zet') !== -1;

if (VERWIJDER === ZET) {
  console.error('Kies er precies een: --verwijder of --zet');
  process.exit(1);
}

const PAREN = [
  { met: "    { \"@type\": \"Question\", \"name\": \"What does it cost to have my tax return done?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Our prices start at \\u20ac59 for a single return and go up to \\u20ac109 for a complete home owner package (including mortgage interest deduction). With a partner you pay \\u20ac30 extra. All prices include VAT, with no surprises afterwards.\" } },\r",
    zonder: " { \"@type\": \"Question\", \"name\": \"What does it cost to have my tax return done?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Our prices start at \\u20ac59 for a single return and go up to \\u20ac109 for a complete home owner package (including mortgage interest deduction). With a partner you pay \\u20ac30 extra. No surprises afterwards.\" } },\r",
    verwacht: 1 },
  { met: "    { \"@type\": \"Question\", \"name\": \"What does it cost and what do I need?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"The complete package with mortgage calculation costs \\u20ac109 (incl. VAT); with your partner \\u20ac149. We need your mortgage details, property valuation (WOZ) and income information \\u2014 we tell you exactly what.\" } }\r",
    zonder: " { \"@type\": \"Question\", \"name\": \"What does it cost and what do I need?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"The complete package with mortgage calculation costs \\u20ac109; with your partner \\u20ac149. We need your mortgage details, property valuation (WOZ) and income information \\u2014 we tell you exactly what.\" } }\r",
    verwacht: 1 },
  { met: "    { \"@type\": \"Question\", \"name\": \"Wat kost het en wat heb ik nodig?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Het complete pakket met hypotheekberekening kost €109 (incl. BTW); samen met uw partner €149. Wij hebben uw hypotheekgegevens, WOZ-beschikking en inkomensgegevens nodig, wij vertellen u precies wat.\" } }\r",
    zonder: " { \"@type\": \"Question\", \"name\": \"Wat kost het en wat heb ik nodig?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Het complete pakket met hypotheekberekening kost €109; samen met uw partner €149. Wij hebben uw hypotheekgegevens, WOZ-beschikking en inkomensgegevens nodig, wij vertellen u precies wat.\" } }\r",
    verwacht: 1 },
  { met: "    { \"@type\": \"Question\", \"name\": \"Wat kost een correctie of late aangifte?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Een correctie of alsnog in te dienen jaaraangifte kost €69 per jaar (incl. BTW). Het aanvragen van uitstel is gratis. Vooraf doen wij een kosteloze check of correctie geld oplevert.\" } },\r",
    zonder: " { \"@type\": \"Question\", \"name\": \"Wat kost een correctie of late aangifte?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Een correctie of alsnog in te dienen jaaraangifte kost €69 per jaar. Het aanvragen van uitstel is gratis. Vooraf doen wij een kosteloze check of correctie geld oplevert.\" } },\r",
    verwacht: 1 },
  { met: "      \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Onze tarieven beginnen bij €59 voor een seniorenaangifte en lopen tot €109 voor een complete voorlopige teruggave (inclusief hypotheekrenteaftrek). Met partner betaalt u €30 extra. Alle prijzen zijn inclusief BTW en zonder verrassingen achteraf.\" }\r",
    zonder: " \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"Onze tarieven beginnen bij €59 voor een seniorenaangifte en lopen tot €109 voor een complete voorlopige teruggave (inclusief hypotheekrenteaftrek). Met partner betaalt u €30 extra. Zonder verrassingen achteraf.\" }\r",
    verwacht: 1 },
  { met: "        \"text\": \"Onze prijzen beginnen bij €59 voor een seniorenaangifte. Het Voorlopige teruggave pakket kost €109 en een correctie-aangifte €69, alle prijzen inclusief BTW. Wij komen aan huis in Wormerveer en een eerste gesprek is altijd vrijblijvend. U weet vooraf precies wat het kost.\"\r",
    zonder: " \"text\": \"Onze prijzen beginnen bij €59 voor een seniorenaangifte. Het Voorlopige teruggave pakket kost €109 en een correctie-aangifte €69. Wij komen aan huis in Wormerveer en een eerste gesprek is altijd vrijblijvend. U weet vooraf precies wat het kost.\"\r",
    verwacht: 1 },
  { met: "    { \"@type\": \"Question\", \"name\": \"What does a correction or late return cost?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"A fixed \\u20ac69 per annual return, incl. VAT. We check beforehand for free whether a correction is worthwhile \\u2014 so you never pay for nothing.\" } },\r",
    zonder: " { \"@type\": \"Question\", \"name\": \"What does a correction or late return cost?\", \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"A fixed \\u20ac69 per annual return. We check beforehand for free whether a correction is worthwhile \\u2014 so you never pay for nothing.\" } },\r",
    verwacht: 1 },
  { met: "<p>Onze prijzen beginnen bij €59 voor een seniorenaangifte. Het Voorlopige teruggave pakket kost €109 en een correctie-aangifte €69, alle prijzen inclusief BTW. Wij komen aan huis in Wormerveer en een eerste gesprek is altijd vrijblijvend. U weet vooraf precies wat het kost.</p>",
    zonder: "<p>Onze prijzen beginnen bij €59 voor een seniorenaangifte. Het Voorlopige teruggave pakket kost €109 en een correctie-aangifte €69. Wij komen aan huis in Wormerveer en een eerste gesprek is altijd vrijblijvend. U weet vooraf precies wat het kost.</p>",
    verwacht: 1 },
  { met: "</strong> voor een seniorenaangifte en lopen tot €109 voor een complete voorlopige teruggave (inclusief hypotheekrenteaftrek). Met partner betaalt u €30 extra. Alle prijzen zijn inclusief BTW en zonder verrassingen achteraf. Geen uurtarief, geen meerwerk-rekeningen.</p>",
    zonder: "</strong> voor een seniorenaangifte en lopen tot €109 voor een complete voorlopige teruggave (inclusief hypotheekrenteaftrek). Met partner betaalt u €30 extra. Zonder verrassingen achteraf. Geen uurtarief, geen meerwerk-rekeningen.</p>",
    verwacht: 1 },
  { met: "<p>Our prices start at €59 for a single return and go up to €109 for a complete home owner package (including mortgage interest deduction). With a partner you pay €30 extra. All prices include VAT, with no surprises afterwards.</p>",
    zonder: "<p>Our prices start at €59 for a single return and go up to €109 for a complete home owner package (including mortgage interest deduction). With a partner you pay €30 extra. No surprises afterwards.</p>",
    verwacht: 1 },
  { met: "      \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"59 euro per aangifte, inclusief BTW. Doet u de aangifte samen met uw partner, dan is het 89 euro voor u samen. U weet de prijs vooraf en er komt niets bij.\" }\r",
    zonder: " \"acceptedAnswer\": { \"@type\": \"Answer\", \"text\": \"59 euro per aangifte. Doet u de aangifte samen met uw partner, dan is het 89 euro voor u samen. U weet de prijs vooraf en er komt niets bij.\" }\r",
    verwacht: 1 },
  { met: "        \"text\": \"Niets. Wij kijken uw zorgtoeslag, huurtoeslag, kindgebonden budget en kinderopvangtoeslag gratis na. Pas als u ons daarna de aanvraag of wijziging laat regelen, betaalt u €30 inclusief BTW.\"\r",
    zonder: " \"text\": \"Niets. Wij kijken uw zorgtoeslag, huurtoeslag, kindgebonden budget en kinderopvangtoeslag gratis na. Pas als u ons daarna de aanvraag of wijziging laat regelen, betaalt u €30.\"\r",
    verwacht: 1 },
  { met: "<p>The complete package with mortgage calculation costs €109 (incl. VAT); with your partner €149. We need your mortgage details, property valuation (WOZ) and income information, we tell you exactly what.</p>",
    zonder: "<p>The complete package with mortgage calculation costs €109; with your partner €149. We need your mortgage details, property valuation (WOZ) and income information, we tell you exactly what.</p>",
    verwacht: 1 },
  { met: "<p>Het complete pakket met hypotheekberekening kost €109 (incl. BTW); samen met uw partner €149. Wij hebben uw hypotheekgegevens, WOZ-beschikking en inkomensgegevens nodig, wij vertellen u precies wat.</p>",
    zonder: "<p>Het complete pakket met hypotheekberekening kost €109; samen met uw partner €149. Wij hebben uw hypotheekgegevens, WOZ-beschikking en inkomensgegevens nodig, wij vertellen u precies wat.</p>",
    verwacht: 1 },
  { met: "<p>Niets. Wij kijken uw zorgtoeslag, huurtoeslag, kindgebonden budget en kinderopvangtoeslag gratis na. Pas als u ons daarna de aanvraag of wijziging laat regelen, betaalt u €30 inclusief BTW.</p>",
    zonder: "<p>Niets. Wij kijken uw zorgtoeslag, huurtoeslag, kindgebonden budget en kinderopvangtoeslag gratis na. Pas als u ons daarna de aanvraag of wijziging laat regelen, betaalt u €30.</p>",
    verwacht: 1 },
  { met: "<p style=\"font-size:0.95rem;color:var(--clr-bark);line-height:1.65;\">Per te corrigeren of alsnog in te dienen jaaraangifte betaalt u €69 (incl. BTW). Het aanvragen van uitstel is kosteloos.</p>",
    zonder: "<p style=\"font-size:0.95rem;color:var(--clr-bark);line-height:1.65;\">Per te corrigeren of alsnog in te dienen jaaraangifte betaalt u €69. Het aanvragen van uitstel is kosteloos.</p>",
    verwacht: 1 },
  { met: "<p>Een correctie of alsnog in te dienen jaaraangifte kost €69 per jaar (incl. BTW). Het aanvragen van uitstel is gratis. Vooraf doen wij een kosteloze check of correctie geld oplevert.</p>",
    zonder: "<p>Een correctie of alsnog in te dienen jaaraangifte kost €69 per jaar. Het aanvragen van uitstel is gratis. Vooraf doen wij een kosteloze check of correctie geld oplevert.</p>",
    verwacht: 1 },
  { met: "<p>&euro;&nbsp;59 per aangifte, inclusief BTW. Samen met uw partner &euro;&nbsp;89 voor u samen. U weet de prijs vooraf en er komt niets bij.</p>",
    zonder: "<p>&euro;&nbsp;59 per aangifte. Samen met uw partner &euro;&nbsp;89 voor u samen. U weet de prijs vooraf en er komt niets bij.</p>",
    verwacht: 1 },
  { met: "<p>You pay a fixed €69 per annual return, incl. VAT. We check beforehand for free whether a correction actually pays off, no false promises.</p>",
    zonder: "<p>You pay a fixed €69 per annual return. We check beforehand for free whether a correction actually pays off, no false promises.</p>",
    verwacht: 1 },
  { met: "<p>A fixed €69 per annual return, incl. VAT. We check beforehand for free whether a correction is worthwhile. So you never pay for nothing.</p>",
    zonder: "<p>A fixed €69 per annual return. We check beforehand for free whether a correction is worthwhile. So you never pay for nothing.</p>",
    verwacht: 1 },
  { met: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">per aanvraag of wijziging · controle vooraf gratis · incl. BTW</div>",
    zonder: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">per aanvraag of wijziging · controle vooraf gratis</div>",
    verwacht: 1 },
  { met: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">per jaaraangifte · uitstel aanvragen kosteloos · incl. BTW</div>",
    zonder: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">per jaaraangifte · uitstel aanvragen kosteloos</div>",
    verwacht: 1 },
  { met: "<p class=\"hero-card-disclaimer\">* Vaste prijs inclusief BTW. Geen verrassingen, geen uurtarief. U weet vooraf wat u betaalt.</p>",
    zonder: "<p class=\"hero-card-disclaimer\">* Vaste prijs. Geen verrassingen, geen uurtarief. U weet vooraf wat u betaalt.</p>",
    verwacht: 1 },
  { met: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">complete package · with partner €149 · incl. VAT</div>",
    zonder: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">complete package · with partner €149</div>",
    verwacht: 1 },
  { met: "<p>You know the price upfront: from €59 for a single return, incl. VAT. No hourly billing, no surprise invoices afterwards.</p>",
    zonder: "<p>You know the price upfront: from €59 for a single return. No hourly billing, no surprise invoices afterwards.</p>",
    verwacht: 1 },
  { met: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">compleet pakket · met partner €149 · incl. BTW</div>",
    zonder: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">compleet pakket · met partner €149</div>",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">Geen verrassingen achteraf. U weet vooraf wat het kost. Alle prijzen zijn inclusief BTW.</p>",
    zonder: "<p class=\"section-desc\">Geen verrassingen achteraf. U weet vooraf wat het kost.</p>",
    verwacht: 5 },
  { met: "<p class=\"section-desc\">You know the cost upfront. All prices include VAT. No extra-work invoices afterwards.</p>",
    zonder: "<p class=\"section-desc\">You know the cost upfront. No extra-work invoices afterwards.</p>",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">No surprises afterwards. You know upfront what it will cost. All prices include VAT.</p>",
    zonder: "<p class=\"section-desc\">No surprises afterwards. You know upfront what it will cost.</p>",
    verwacht: 4 },
  { met: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">per annual return · incl. VAT</div>",
    zonder: "<div style=\"font-size:0.85rem;color:var(--clr-bark);margin-bottom:18px;\">per annual return</div>",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">Alle prijzen zijn inclusief BTW. Persoonlijke hulp aan huis in Wormerland.</p>",
    zonder: "<p class=\"section-desc\"> Persoonlijke hulp aan huis in Wormerland.</p>",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">Geen verrassingen achteraf. Alle prijzen zijn inclusief BTW.</p>",
    zonder: "<p class=\"section-desc\">Geen verrassingen achteraf.</p>",
    verwacht: 4 },
  { met: "<div style=\"font-size:0.78rem;color:var(--clr-bark);\">per application · incl. VAT</div>",
    zonder: "<div style=\"font-size:0.78rem;color:var(--clr-bark);\">per application</div>",
    verwacht: 1 },
  { met: "<div style=\"font-size:0.78rem;color:var(--clr-bark);\">per aanvraag · incl. BTW</div>",
    zonder: "<div style=\"font-size:0.78rem;color:var(--clr-bark);\">per aanvraag</div>",
    verwacht: 7 },
  { met: "Alle genoemde prijzen zijn <strong>inclusief btw</strong>, tenzij anders vermeld.",
    zonder: "Alle genoemde prijzen staan vooraf vast.",
    verwacht: 1 },
  { met: "<div style=\"font-size:0.78rem;color:var(--clr-bark);\">surcharge · incl. VAT</div>",
    zonder: "<div style=\"font-size:0.78rem;color:var(--clr-bark);\">surcharge</div>",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">Fixed price per year, including VAT. No hourly rate.</p>",
    zonder: "<p class=\"section-desc\">Fixed price per year. No hourly rate.</p>",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">No surprises afterwards. All prices include VAT.</p>",
    zonder: "<p class=\"section-desc\">No surprises afterwards.</p>",
    verwacht: 6 },
  { met: "<p class=\"section-desc\">Vaste prijzen, inclusief BTW. Geen uurtarief.</p>",
    zonder: "<p class=\"section-desc\">Vaste prijzen. Geen uurtarief.</p>",
    verwacht: 1 },
  { met: "<span style=\"font-size:0.78rem;color:var(--clr-bark);\">· incl. BTW</span>",
    zonder: "<span style=\"font-size:0.78rem;color:var(--clr-bark);\"></span>",
    verwacht: 1 },
  { met: "Alle bedragen zijn inclusief BTW en vast vooraf (geen verborgen kosten):\r",
    zonder: "Alle bedragen zijn vast vooraf (geen verborgen kosten):\r",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">Vaste prijs per jaaraangifte, inclusief BTW.</p>",
    zonder: "<p class=\"section-desc\">Vaste prijs per jaaraangifte.</p>",
    verwacht: 1 },
  { met: "<p class=\"section-desc\">Fixed prices, including VAT. No hourly rate.</p>",
    zonder: "<p class=\"section-desc\">Fixed prices. No hourly rate.</p>",
    verwacht: 1 },
  { met: "<div style=\"color:var(--clr-bark);\">per aangifte, inclusief BTW</div>",
    zonder: "<div style=\"color:var(--clr-bark);\">per aangifte</div>",
    verwacht: 1 },
  { met: "<div class=\"tarief-price-note\">per annual return · incl. VAT</div>",
    zonder: "<div class=\"tarief-price-note\">per annual return</div>",
    verwacht: 1 },
  { met: "<div class=\"tarief-price-note\">met partner €149 · incl. BTW</div>",
    zonder: "<div class=\"tarief-price-note\">met partner €149</div>",
    verwacht: 2 },
  { met: "<div class=\"tarief-price-note\">per tax return · incl. VAT</div>",
    zonder: "<div class=\"tarief-price-note\">per tax return</div>",
    verwacht: 26 },
  { met: "<div class=\"tarief-price-note\">per aangifte · incl. BTW</div>",
    zonder: "<div class=\"tarief-price-note\">per aangifte</div>",
    verwacht: 22 },
  { met: "<div class=\"tarief-price-note\">per aanvraag · incl. BTW</div>",
    zonder: "<div class=\"tarief-price-note\">per aanvraag</div>",
    verwacht: 1 },
  { met: "<div class=\"tarief-price-note\">per bezwaar · incl. BTW</div>",
    zonder: "<div class=\"tarief-price-note\">per bezwaar</div>",
    verwacht: 1 },
  { met: "<div class=\"tarief-price-note\">per return · incl. VAT</div>",
    zonder: "<div class=\"tarief-price-note\">per return</div>",
    verwacht: 3 },
  { met: "<div class=\"tarief-price-note\">per check · incl. BTW</div>",
    zonder: "<div class=\"tarief-price-note\">per check</div>",
    verwacht: 1 },
  { met: "<div class=\"tarief-price-note\">eenmalig · incl. BTW</div>",
    zonder: "<div class=\"tarief-price-note\">eenmalig</div>",
    verwacht: 9 },
  { met: "<div class=\"tarief-price-note\">per jaar · incl. BTW</div>",
    zonder: "<div class=\"tarief-price-note\">per jaar</div>",
    verwacht: 2 },
  { met: "<div class=\"tarief-price-note\">one-off · incl. VAT</div>",
    zonder: "<div class=\"tarief-price-note\">one-off</div>",
    verwacht: 3 }
];

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (e.name === '.git' || e.name === 'node_modules' || e.name === 'docs') continue;
      walk(path.join(dir, e.name), acc);
    } else if (/\.(html|json|txt|xml)$/.test(e.name)) acc.push(path.join(dir, e.name));
  }
  return acc;
}
const rel = f => path.relative(ROOT, f).split(path.sep).join('/');
const bestanden = walk(ROOT, []).filter(f => !rel(f).startsWith('scripts/'));

/* de te zoeken vormen, langste eerst zodat een lange vorm voorgaat op een
 * kortere die erin zit */
const REGELS = PAREN.map(p => ({
  van: VERWIJDER ? p.met : p.zonder,
  naar: VERWIJDER ? p.zonder : p.met,
  met: p.met
})).sort((a, b) => b.van.length - a.van.length);

let raak = 0, geraakteBestanden = 0;
const perVorm = {};

for (const f of bestanden) {
  const s = fs.readFileSync(f, 'utf8');
  let uit = '', i = 0, geraakt = 0;

  /* een pass: op elke positie de langste passende vorm, dan doorspringen */
  while (i < s.length) {
    let hit = null;
    for (const r of REGELS) {
      if (s.startsWith(r.van, i)) { hit = r; break; }
    }
    if (hit) {
      uit += hit.naar;
      i += hit.van.length;
      raak++; geraakt++;
      perVorm[hit.met] = (perVorm[hit.met] || 0) + 1;
    } else {
      uit += s[i];
      i++;
    }
  }

  if (geraakt) { if (!DRY) fs.writeFileSync(f, uit, 'utf8'); geraakteBestanden++; }
}

console.log((DRY ? '[dry] ' : '') + (VERWIJDER ? 'verwijderd' : 'teruggezet') +
  ': ' + raak + ' vermelding(en) in ' + geraakteBestanden + ' bestanden');

/* ---------- controle ---------- */
const CLAIM = /inclusief\s+BTW|incl\.?\s*BTW|BTW\s+inbegrepen|including\s+VAT|incl\.?\s*VAT|(?:prices\s+)?includes?\s+VAT|VAT\s+included|inclusief\s+btw/gi;

if (!DRY) {
  let aanwezig = 0;
  for (const f of bestanden) {
    const m = fs.readFileSync(f, 'utf8').match(new RegExp(CLAIM.source, 'gi'));
    if (!m) continue;
    aanwezig += m.length;
    if (VERWIJDER) console.error('  nog aanwezig in ' + rel(f) + ': ' + m.length + 'x');
  }
  if (VERWIJDER) {
    console.log(aanwezig === 0
      ? 'ok  geen enkele BTW- of VAT-vermelding meer, in geen enkele vorm'
      : 'FOUT: ' + aanwezig + ' vermelding(en) over');
    if (aanwezig) process.exit(1);
  } else {
    console.log('ok  ' + aanwezig + ' vermelding(en) staan er weer');
  }

  let ld = 0, ldFout = 0;
  for (const f of bestanden) {
    if (!f.endsWith('.html')) continue;
    const s = fs.readFileSync(f, 'utf8');
    for (const m of s.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)) {
      ld++;
      try { JSON.parse(m[1]); } catch (e) { console.error('  JSON-LD stuk in ' + rel(f) + ': ' + e.message); ldFout++; }
    }
  }
  console.log((ldFout === 0 ? 'ok  ' : 'FOUT ') + ld + ' JSON-LD-blokken, ' + ldFout + ' stuk');
  if (ldFout) process.exit(1);
}
