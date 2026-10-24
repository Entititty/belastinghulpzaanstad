'use strict';
/*
 * overzicht.js — /beheer/overzicht: wat levert wat op.
 *
 * Eén periodekeuze bovenaan geldt voor alles op de pagina. Daaronder:
 * kerncijfers, aanvragen per week, per bron/dienst/rekentool/partner (met
 * klanten, conversie en omzet), de klikken op bellen en WhatsApp, en per
 * flyerbuurt de trechter scans -> klikken -> aanvragen -> klanten -> omzet.
 *
 * Grafieken als SVG van de server, zonder bibliotheek. Volgens de dataviz-
 * regels: dunne kolommen (max. 24px) met een afgeronde kop, lijnen van 2px,
 * haarlijnen voor het raster, één kleur bij één reeks, een legenda bij twee,
 * waarden alleen waar ze iets zeggen, en bij elke grafiek een tabel. Het
 * palet (#2a78d6, #eb6834) is met de validator van de dataviz-skill
 * gecontroleerd tegen het witte vlak. Elke grafiek wordt twee keer gemaakt,
 * smal voor de telefoon en breed voor de computer, zodat de tekst in beide
 * leesbaar blijft; de CSS toont er één.
 */
const { h, veilig } = require('./html');
const { nl } = require('./tijd');
const { NAMEN } = require('./bron');
const dbm = require('./db');
const berichten = require('./berichten');
const { klikkenInlezen } = require('./dagelijks');

const KLEUR = { s1: '#2a78d6', s2: '#eb6834', raster: '#e1e0d9', as: '#c3c2b7', vlak: '#ffffff' };
const PERIODES = [['4', 'Laatste 4 weken'], ['13', 'Laatste 13 weken'], ['52', 'Laatste 52 weken'], ['jaar', 'Dit kalenderjaar'], ['alles', 'Alles']];
const MAANDEN = ['jan', 'feb', 'mrt', 'apr', 'mei', 'jun', 'jul', 'aug', 'sep', 'okt', 'nov', 'dec'];

const getal = (n) => Number(n || 0).toLocaleString('nl-NL');
const procent = (a, b) => (b ? Math.round((a / b) * 100) + '%' : '–');
const euro = (c) => '€ ' + Math.round((c || 0) / 100).toLocaleString('nl-NL');
const dagNaarDate = (d) => new Date(d + 'T12:00:00Z');
const dagTekst = (d) => { const x = dagNaarDate(d); return x.getUTCDate() + ' ' + MAANDEN[x.getUTCMonth()]; };
function plusDagen(d, n) { const x = dagNaarDate(d); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); }
function maandag(d) { const x = dagNaarDate(d); return plusDagen(d, -((x.getUTCDay() + 6) % 7)); }
function campagneCode(s) { return String(s || '').toLowerCase().replace(/[ ._+/]+/g, '-').replace(/[^a-z0-9-]/g, '').slice(0, 40); }

/* ---------------- periode en emmers ---------------- */
function periode(keuze, vandaag, vroegste) {
  if (keuze === 'jaar') return { van: vandaag.slice(0, 4) + '-01-01', tot: vandaag, vorige: null };
  if (keuze === 'alles') return { van: vroegste && vroegste < vandaag ? vroegste : vandaag, tot: vandaag, vorige: null };
  const n = Number(keuze);
  const van = plusDagen(maandag(vandaag), -7 * (n - 1));
  return { van, tot: vandaag, vorige: { van: plusDagen(van, -7 * n), tot: plusDagen(van, -1) } };
}

/* weken bij een korte periode, maanden bij een lange: nooit meer dan ~26 kolommen */
function emmers(van, tot) {
  const dagen = (dagNaarDate(tot) - dagNaarDate(van)) / 864e5;
  if (dagen <= 26 * 7) {
    const r = [];
    for (let w = maandag(van); w <= tot; w = plusDagen(w, 7)) r.push({ sleutel: w, label: dagTekst(w), lang: 'week van ' + dagTekst(w) });
    return { soort: 'week', lijst: r, van: (d) => maandag(d) };
  }
  const r = [];
  for (let m = van.slice(0, 7); m <= tot.slice(0, 7);) {
    const [j, mm] = m.split('-').map(Number);
    r.push({ sleutel: m, label: MAANDEN[mm - 1] + (mm === 1 ? " '" + String(j).slice(2) : ''), lang: MAANDEN[mm - 1] + ' ' + j });
    m = mm === 12 ? (j + 1) + '-01' : j + '-' + String(mm + 1).padStart(2, '0');
  }
  return { soort: 'maand', lijst: r, van: (d) => d.slice(0, 7) };
}

/* ---------------- grafieken ---------------- */
function mooiMax(m) {
  if (m <= 4) return 4;
  const stap = Math.pow(10, Math.floor(Math.log10(m)));
  for (const f of [1, 2, 2.5, 5, 10]) if (f * stap >= m) return f * stap;
  return 10 * stap;
}
/* astikken bij tellingen: het midden alleen als dat een heel getal is (25 geeft 0 en 25, niet 12,5) */
function tikken(max) { return Number.isInteger(max / 2) ? [0, max / 2, max] : [0, max]; }
const rond = (n) => Math.round(n * 10) / 10;
/* kolom met een afgeronde kop (4px) en een rechte voet op de basislijn */
function kolomPad(x, y, b, hoogte) {
  const r = Math.min(4, hoogte, b / 2);
  return 'M' + rond(x) + ',' + rond(y + hoogte) + 'V' + rond(y + r) + 'Q' + rond(x) + ',' + rond(y) + ' ' + rond(x + r) + ',' + rond(y) +
    'H' + rond(x + b - r) + 'Q' + rond(x + b) + ',' + rond(y) + ' ' + rond(x + b) + ',' + rond(y + r) + 'V' + rond(y + hoogte) + 'Z';
}

/* Kolommen, één reeks. punten: [{ label, waarde, tip }] */
function kolommen(punten, breedte, titel) {
  const L = 30, R = 8, T = 18, B = 26, H = 190;
  const plotB = breedte - L - R, plotH = H - T - B;
  const max = mooiMax(Math.max(0, ...punten.map((p) => p.waarde)));
  const slot = plotB / Math.max(1, punten.length);
  const dik = Math.min(24, slot * 0.62);
  const sprong = Math.max(1, Math.ceil(40 / slot));
  const hoogste = punten.reduce((a, p, i) => (p.waarde > punten[a].waarde ? i : a), 0);
  const delen = [];
  for (const t of tikken(max)) {
    const y = rond(T + plotH - (t / max) * plotH);
    delen.push('<line x1="' + L + '" x2="' + (breedte - R) + '" y1="' + y + '" y2="' + y + '" stroke="' + (t === 0 ? KLEUR.as : KLEUR.raster) + '" stroke-width="1"/>');
    delen.push('<text class="g-as" x="' + (L - 6) + '" y="' + (y + 4) + '" text-anchor="end">' + getal(t) + '</text>');
  }
  punten.forEach((p, i) => {
    const x = rond(L + i * slot + (slot - dik) / 2);
    const hoogte = rond((p.waarde / max) * plotH);
    if (p.waarde > 0) delen.push('<path d="' + kolomPad(x, rond(T + plotH - hoogte), rond(dik), hoogte) + '" fill="' + KLEUR.s1 + '"/>');
    if (p.waarde > 0 && (i === hoogste || i === punten.length - 1)) {
      delen.push('<text class="g-waarde" x="' + rond(x + dik / 2) + '" y="' + rond(T + plotH - hoogte - 5) + '" text-anchor="middle">' + getal(p.waarde) + '</text>');
    }
    if (i % sprong === 0 || i === punten.length - 1 && (punten.length - 1) % sprong >= sprong / 2) {
      delen.push(h`<text class="g-as" x="${rond(L + i * slot + slot / 2)}" y="${H - 8}" text-anchor="middle">${p.label}</text>`.html);
    }
    delen.push(h`<rect class="hit" x="${rond(L + i * slot)}" y="${T}" width="${rond(slot)}" height="${plotH}" fill="transparent" tabindex="0" data-tip="${p.tip}"><title>${p.tip}</title></rect>`.html);
  });
  return veilig('<svg class="grafiek" viewBox="0 0 ' + breedte + ' ' + H + '" width="' + breedte + '" height="' + H + '" role="img" aria-label="' +
    h`${titel}`.html + '">' + delen.join('') + '</svg>');
}

/* Lijnen, twee reeksen. reeksen: [{ naam, kleur, waarden: [] }], labels: [{ label, tip }] */
function lijnen(reeksen, labels, breedte, titel) {
  const L = 30, R = 86, T = 14, B = 26, H = 190;
  const plotB = breedte - L - R, plotH = H - T - B;
  const n = labels.length;
  const max = mooiMax(Math.max(0, ...reeksen.flatMap((r) => r.waarden)));
  const x = (i) => rond(L + (n === 1 ? plotB / 2 : (i / (n - 1)) * plotB));
  const y = (v) => rond(T + plotH - (v / max) * plotH);
  const sprong = Math.max(1, Math.ceil(40 / (plotB / Math.max(1, n - 1))));
  const delen = [];
  for (const t of tikken(max)) {
    delen.push('<line x1="' + L + '" x2="' + (L + plotB) + '" y1="' + y(t) + '" y2="' + y(t) + '" stroke="' + (t === 0 ? KLEUR.as : KLEUR.raster) + '" stroke-width="1"/>');
    delen.push('<text class="g-as" x="' + (L - 6) + '" y="' + (y(t) + 4) + '" text-anchor="end">' + getal(t) + '</text>');
  }
  labels.forEach((l, i) => {
    if (i % sprong === 0) delen.push(h`<text class="g-as" x="${x(i)}" y="${H - 8}" text-anchor="middle">${l.label}</text>`.html);
  });
  for (const r of reeksen) {
    delen.push('<polyline points="' + r.waarden.map((v, i) => x(i) + ',' + y(v)).join(' ') + '" fill="none" stroke="' + r.kleur +
      '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>');
  }
  /* eindpunten met een witte ring, en een label aan het eind als ze elkaar niet raken */
  const einden = reeksen.map((r) => ({ r, v: r.waarden[n - 1] || 0 }));
  const raken = einden.length === 2 && Math.abs(y(einden[0].v) - y(einden[1].v)) < 15;
  for (const e of einden) {
    delen.push('<circle cx="' + x(n - 1) + '" cy="' + y(e.v) + '" r="4" fill="' + e.r.kleur + '" stroke="' + KLEUR.vlak + '" stroke-width="2"/>');
    if (!raken) delen.push(h`<text class="g-label" x="${x(n - 1) + 9}" y="${y(e.v) + 4}">${e.r.naam} ${getal(e.v)}</text>`.html);
  }
  labels.forEach((l, i) => {
    const links = i === 0 ? L : (x(i - 1) + x(i)) / 2, rechts = i === n - 1 ? L + plotB : (x(i) + x(i + 1)) / 2;
    delen.push(h`<rect class="hit" x="${rond(links)}" y="${T}" width="${rond(Math.max(1, rechts - links))}" height="${plotH}" fill="transparent" tabindex="0" data-tip="${l.tip}"><title>${l.tip}</title></rect>`.html);
  });
  return veilig('<svg class="grafiek" viewBox="0 0 ' + breedte + ' ' + H + '" width="' + breedte + '" height="' + H + '" role="img" aria-label="' +
    h`${titel}`.html + '">' + delen.join('') + '</svg>');
}

/* een staafje in een tabelcel, voor de verhouding tussen de rijen */
function staafje(waarde, max) {
  const b = 100, hoog = 10;
  const w = max > 0 ? rond((waarde / max) * b) : 0;
  const r = Math.min(4, w / 2);
  const pad = w > 0 ? 'M0,0H' + rond(w - r) + 'Q' + w + ',0 ' + w + ',' + r + 'V' + (hoog - r) + 'Q' + w + ',' + hoog + ' ' + rond(w - r) + ',' + hoog + 'H0Z' : '';
  return veilig('<svg class="staafje" viewBox="0 0 ' + b + ' ' + hoog + '" width="' + b + '" height="' + hoog + '" aria-hidden="true">' +
    (pad ? '<path d="' + pad + '" fill="' + KLEUR.s1 + '"/>' : '') + '</svg>');
}

/* grafiek in een figuur: smal en breed, plus de tabel */
function figuur(titel, uitleg, maak, tabel) {
  return h`<figure class="kaart figuur"><figcaption><h2>${titel}</h2>${uitleg ? h`<p class="klein">${uitleg}</p>` : ''}</figcaption>
    <div class="alleen-smal">${maak(360)}</div><div class="alleen-breed">${maak(720)}</div>
    <details><summary>Als tabel</summary><div class="tabel-wrap">${tabel}</div></details></figure>`;
}

/* ---------------- de pagina ---------------- */
function registreer(ctx) {
  const { db, config: cfg, beheer } = ctx;

  function cijfers(keuze) {
    const vandaag = nl(ctx.klok()).datum;
    const vroegste = [db.prepare('SELECT MIN(aangemaakt) AS d FROM aanvragen').get().d, db.prepare('SELECT MIN(dag) AS d FROM klikken').get().d]
      .filter(Boolean).map((d) => (d.length > 10 ? nl(new Date(d)).datum : d)).sort()[0];
    const p = periode(keuze, vandaag, vroegste);
    const alle = db.prepare(`SELECT a.id, a.aangemaakt, a.status, a.bron, a.bron_detail, a.dienst, a.rekentool, a.partner_id, a.ref, a.utm_campaign,
      a.omzet_centen, a.kanaal, p.naam AS partner_naam FROM aanvragen a LEFT JOIN partners p ON p.id = a.partner_id`).all()
      .map((a) => Object.assign({}, a, { dag: nl(new Date(a.aangemaakt)).datum }));
    const inPeriode = (a, van, tot) => a.dag >= van && a.dag <= tot;
    const aanvragen = alle.filter((a) => inPeriode(a, p.van, p.tot));
    const vorige = p.vorige ? alle.filter((a) => inPeriode(a, p.vorige.van, p.vorige.tot)) : null;
    const klikken = db.prepare('SELECT * FROM klikken WHERE dag >= ? AND dag <= ?').all(p.van, p.tot);
    const klikkenVorige = p.vorige ? db.prepare('SELECT * FROM klikken WHERE dag >= ? AND dag <= ?').all(p.vorige.van, p.vorige.tot) : null;
    return { p, aanvragen, vorige, klikken, klikkenVorige };
  }

  function groepeer(aanvragen, sleutel, naam) {
    const m = new Map();
    for (const a of aanvragen) {
      const k = sleutel(a);
      if (k === null || k === undefined || k === '') continue;
      const x = m.get(k) || { sleutel: k, naam: naam(a, k), aanvragen: 0, klanten: 0, omzet: 0 };
      x.aanvragen++;
      if (a.status === 'klant') { x.klanten++; x.omzet += a.omzet_centen || 0; }
      m.set(k, x);
    }
    return [...m.values()].sort((a, b) => b.aanvragen - a.aanvragen || b.omzet - a.omzet);
  }

  function dimensieTabel(rijen, kop, leeg) {
    if (!rijen.length) return h`<p class="klein">${leeg}</p>`;
    const max = Math.max(...rijen.map((r) => r.aanvragen));
    return h`<div class="tabel-wrap"><table class="tabel"><thead><tr><th>${kop}</th><th class="getal">Aanvragen</th><th class="staaf-kol"></th>
      <th class="getal">Klant</th><th class="getal">Conversie</th><th class="getal">Omzet</th></tr></thead><tbody>
      ${rijen.map((r) => h`<tr><td>${r.naam}</td><td class="getal">${getal(r.aanvragen)}</td><td class="staaf-kol">${staafje(r.aanvragen, max)}</td>
        <td class="getal">${getal(r.klanten)}</td><td class="getal">${procent(r.klanten, r.aanvragen)}</td><td class="getal">${euro(r.omzet)}</td></tr>`)}
      </tbody></table></div>`;
  }

  function tegel(label, waarde, verschil, uitleg) {
    let delta = '';
    if (verschil !== null && verschil !== undefined) {
      const teken = verschil > 0 ? '▲ +' : verschil < 0 ? '▼ ' : '';
      delta = h`<div class="kpi-delta ${verschil > 0 ? 'op' : verschil < 0 ? 'neer' : ''}">${teken}${getal(verschil)} t.o.v. de periode ervoor</div>`;
    }
    return h`<div class="kpi-tegel"><div class="kpi-label">${label}</div><div class="kpi-waarde">${waarde}</div>${delta}${uitleg ? h`<div class="kpi-uitleg">${uitleg}</div>` : ''}</div>`;
  }

  function pagina(req, res, url, sessie) {
    const keuze = PERIODES.some((x) => x[0] === url.searchParams.get('periode')) ? url.searchParams.get('periode') : '13';
    const { p, aanvragen, vorige, klikken, klikkenVorige } = cijfers(keuze);
    const klant = (l) => l.filter((a) => a.status === 'klant');
    const omzet = (l) => klant(l).reduce((s, a) => s + (a.omzet_centen || 0), 0);
    const belApp = (l) => l.filter((k) => k.e === 'tel' || k.e === 'whatsapp').reduce((s, k) => s + k.n, 0);

    /* kerncijfers */
    const kpi = h`<section class="kpi" aria-label="Kerncijfers">
      ${tegel('Aanvragen', getal(aanvragen.length), vorige ? aanvragen.length - vorige.length : null)}
      ${tegel('Klant geworden', getal(klant(aanvragen).length), vorige ? klant(aanvragen).length - klant(vorige).length : null)}
      ${tegel('Conversie', procent(klant(aanvragen).length, aanvragen.length), null, 'van de aanvragen uit deze periode')}
      ${tegel('Omzet', euro(omzet(aanvragen)), null, 'van klanten uit deze periode')}
      ${tegel('Klikken op bellen of WhatsApp', getal(belApp(klikken)), klikkenVorige ? belApp(klikken) - belApp(klikkenVorige) : null)}
    </section>`;

    /* aanvragen per week of maand */
    const e = emmers(p.van, p.tot);
    const perEmmer = new Map(e.lijst.map((x) => [x.sleutel, 0]));
    for (const a of aanvragen) { const k = e.van(a.dag); if (perEmmer.has(k)) perEmmer.set(k, perEmmer.get(k) + 1); }
    const punten = e.lijst.map((x) => ({ label: x.label, waarde: perEmmer.get(x.sleutel), tip: x.lang.charAt(0).toUpperCase() + x.lang.slice(1) + ': ' + perEmmer.get(x.sleutel) + ' aanvra' + (perEmmer.get(x.sleutel) === 1 ? 'ag' : 'gen') }));
    const titelA = 'Aanvragen per ' + e.soort;
    const figA = figuur(titelA, null, (b) => kolommen(punten, b, titelA),
      h`<table class="tabel"><thead><tr><th>${e.soort === 'week' ? 'Week van' : 'Maand'}</th><th class="getal">Aanvragen</th></tr></thead><tbody>
        ${e.lijst.map((x) => h`<tr><td>${e.soort === 'week' ? dagTekst(x.sleutel) : x.lang}</td><td class="getal">${getal(perEmmer.get(x.sleutel))}</td></tr>`)}</tbody></table>`);

    /* klikken per week of maand, bellen en WhatsApp */
    const kE = new Map(e.lijst.map((x) => [x.sleutel, { tel: 0, whatsapp: 0 }]));
    for (const k of klikken) {
      if (k.e !== 'tel' && k.e !== 'whatsapp') continue;
      const s = e.van(k.dag);
      if (kE.has(s)) kE.get(s)[k.e] += k.n;
    }
    const reeksen = [
      { naam: 'Bellen', kleur: KLEUR.s1, waarden: e.lijst.map((x) => kE.get(x.sleutel).tel) },
      { naam: 'WhatsApp', kleur: KLEUR.s2, waarden: e.lijst.map((x) => kE.get(x.sleutel).whatsapp) }
    ];
    const labels = e.lijst.map((x) => ({ label: x.label, tip: x.lang.charAt(0).toUpperCase() + x.lang.slice(1) + ': ' + kE.get(x.sleutel).tel + ' x bellen, ' + kE.get(x.sleutel).whatsapp + ' x WhatsApp' }));
    const titelK = 'Klikken op bellen en WhatsApp per ' + e.soort;
    const legenda = h`<p class="legenda"><span class="sleutel s1"></span>Bellen <span class="sleutel s2"></span>WhatsApp</p>`;
    const figK = h`<figure class="kaart figuur"><figcaption><h2>${titelK}</h2>${legenda}
      <p class="klein">Een klik is nog geen gesprek: wie belt, komt niet altijd door. Bij WhatsApp ziet u bij een flyer of partner de bron in het bericht.</p></figcaption>
      <div class="alleen-smal">${lijnen(reeksen, labels, 360, titelK)}</div><div class="alleen-breed">${lijnen(reeksen, labels, 720, titelK)}</div>
      <details><summary>Als tabel</summary><div class="tabel-wrap"><table class="tabel"><thead><tr><th>${e.soort === 'week' ? 'Week van' : 'Maand'}</th><th class="getal">Bellen</th><th class="getal">WhatsApp</th></tr></thead><tbody>
        ${e.lijst.map((x) => h`<tr><td>${e.soort === 'week' ? dagTekst(x.sleutel) : x.lang}</td><td class="getal">${getal(kE.get(x.sleutel).tel)}</td><td class="getal">${getal(kE.get(x.sleutel).whatsapp)}</td></tr>`)}</tbody></table></div></details></figure>`;

    /* per dimensie */
    const perBron = groepeer(aanvragen, (a) => a.bron, (a, k) => NAMEN[k] || k);
    const perDienst = groepeer(aanvragen, (a) => a.dienst, (a, k) => berichten.label(cfg.diensten, k));
    const perPartner = groepeer(aanvragen, (a) => (a.partner_id ? 'p' + a.partner_id : a.ref ? 'r' + a.ref : null), (a) => a.partner_naam || a.ref + ' (onbekende code)');

    /* rekentools: gebruik tegenover aanvragen */
    const gebruik = new Map();
    for (const k of klikken) if (k.e === 'rekentool') gebruik.set(k.k, (gebruik.get(k.k) || 0) + k.n);
    const perTool = Object.keys(cfg.rekentools).map((code) => {
      const l = aanvragen.filter((a) => a.rekentool === code);
      return { naam: cfg.rekentools[code], gebruikt: gebruik.get(code) || 0, aanvragen: l.length, klanten: klant(l).length, omzet: omzet(l) };
    });
    const maxTool = Math.max(1, ...perTool.map((r) => r.gebruikt));
    const toolTabel = h`<div class="tabel-wrap"><table class="tabel"><thead><tr><th>Rekentool</th><th class="getal">Gebruikt</th><th class="staaf-kol"></th>
      <th class="getal">Aanvragen</th><th class="getal">Van gebruik</th><th class="getal">Klant</th><th class="getal">Omzet</th></tr></thead><tbody>
      ${perTool.map((r) => h`<tr><td>${r.naam}</td><td class="getal">${getal(r.gebruikt)}</td><td class="staaf-kol">${staafje(r.gebruikt, maxTool)}</td>
        <td class="getal">${getal(r.aanvragen)}</td><td class="getal">${procent(r.aanvragen, r.gebruikt)}</td><td class="getal">${getal(r.klanten)}</td><td class="getal">${euro(r.omzet)}</td></tr>`)}
      </tbody></table></div>`;

    /* klikken per knop */
    const perKnop = new Map();
    for (const k of klikken) {
      if (k.e !== 'tel' && k.e !== 'whatsapp') continue;
      const x = perKnop.get(k.k || '?') || { tel: 0, whatsapp: 0 };
      x[k.e] += k.n;
      perKnop.set(k.k || '?', x);
    }
    const KNOPNAAM = { menu: 'Menu bovenaan', hero: 'Bovenaan de pagina', balk: 'Balk onderin (telefoon)', zwevend: 'Zwevende knop (computer)', slot: 'Onderaan de pagina',
      paar: 'Elders op de pagina', tekst: 'Tekstlink', melding: 'In een foutmelding', bedankt: 'Bedankpagina', footer: 'Voettekst', '?': 'Onbekend (oude meting)', overig: 'Overig' };
    const knopRijen = [...perKnop.entries()].map(([k, x]) => ({ naam: KNOPNAAM[k] || k, tel: x.tel, whatsapp: x.whatsapp, samen: x.tel + x.whatsapp })).sort((a, b) => b.samen - a.samen);
    const maxKnop = Math.max(1, ...knopRijen.map((r) => r.samen));
    const knopTabel = knopRijen.length ? h`<div class="tabel-wrap"><table class="tabel"><thead><tr><th>Knop</th><th class="getal">Samen</th><th class="staaf-kol"></th>
      <th class="getal">Bellen</th><th class="getal">WhatsApp</th></tr></thead><tbody>
      ${knopRijen.map((r) => h`<tr><td>${r.naam}</td><td class="getal">${getal(r.samen)}</td><td class="staaf-kol">${staafje(r.samen, maxKnop)}</td>
        <td class="getal">${getal(r.tel)}</td><td class="getal">${getal(r.whatsapp)}</td></tr>`)}</tbody></table></div>`
      : h`<p class="klein">Nog geen klikken in deze periode.</p>`;

    /* flyers per buurt: de trechter */
    const flyer = new Map();
    const rij = (c) => flyer.get(c) || { campagne: c, bezoek: 0, klikken: 0, aanvragen: 0, klanten: 0, omzet: 0 };
    for (const k of klikken) {
      if (k.b !== 'flyer' || !k.c) continue;
      const x = rij(k.c);
      if (k.e === 'bezoek') x.bezoek += k.n;
      if (k.e === 'tel' || k.e === 'whatsapp') x.klikken += k.n;
      flyer.set(k.c, x);
    }
    for (const a of aanvragen) {
      if (a.bron !== 'flyer') continue;
      const c = campagneCode(a.utm_campaign || a.bron_detail) || 'zonder-code';
      const x = rij(c);
      x.aanvragen++;
      if (a.status === 'klant') { x.klanten++; x.omzet += a.omzet_centen || 0; }
      flyer.set(c, x);
    }
    const flyerRijen = [...flyer.values()].sort((a, b) => b.aanvragen - a.aanvragen || b.bezoek - a.bezoek);
    const flyerTabel = flyerRijen.length ? h`<div class="tabel-wrap"><table class="tabel"><thead><tr><th>Buurt (campagne)</th><th class="getal">Scans</th>
      <th class="getal">Klikken</th><th class="getal">Aanvragen</th><th class="getal">Klant</th><th class="getal">Omzet</th></tr></thead><tbody>
      ${flyerRijen.map((r) => h`<tr><td>${r.campagne}</td><td class="getal">${getal(r.bezoek)}</td><td class="getal">${getal(r.klikken)}</td>
        <td class="getal">${getal(r.aanvragen)}</td><td class="getal">${getal(r.klanten)}</td><td class="getal">${euro(r.omzet)}</td></tr>`)}</tbody></table></div>`
      : h`<p class="klein">Nog geen flyerbezoek in deze periode. De QR-codes per buurt komen uit scripts/buurtscore.js.</p>`;

    const laatst = dbm.instelling(db, 'klikken-laatst');
    const inhoud = h`<h1>Overzicht</h1>
      <form method="get" action="/beheer/overzicht" class="kaart filters" data-direct>
        <div><label for="o-periode">Periode</label><select id="o-periode" name="periode">${PERIODES.map(([c, t]) => h`<option value="${c}"${veilig(c === keuze ? ' selected' : '')}>${t}</option>`)}</select></div>
        <div><button type="submit">Toon</button></div>
      </form>
      <p class="klein">Van ${dagTekst(p.van)} ${p.van.slice(0, 4)} tot en met vandaag. ${p.vorige ? 'Vergeleken met de even lange periode ervoor.' : ''}</p>
      ${kpi}
      ${figA}
      <section class="kaart"><h2>Per bron</h2>${dimensieTabel(perBron, 'Bron', 'Geen aanvragen in deze periode.')}
        <p class="klein">Conversie: het deel van de aanvragen uit deze periode dat nu klant is. Recente aanvragen hebben nog tijd nodig.</p></section>
      <section class="kaart"><h2>Per dienst</h2>${dimensieTabel(perDienst, 'Dienst', 'Geen aanvragen in deze periode.')}</section>
      <section class="kaart"><h2>Rekentools</h2>${toolTabel}<p class="klein">"Gebruikt": iemand vulde iets in. "Van gebruik": hoeveel daarvan een aanvraag werd.</p></section>
      <section class="kaart"><h2>Per partner</h2>${dimensieTabel(perPartner, 'Partner', 'Nog geen aanvragen via een partner in deze periode.')}</section>
      ${figK}
      <section class="kaart"><h2>Klikken per knop</h2>${knopTabel}</section>
      <section class="kaart"><h2>Flyers per buurt</h2>${flyerTabel}
        <p class="klein">Scans: bezoek via de QR-code. Klikken: bellen of WhatsApp na zo'n bezoek. Wie de flyer leest en zonder de site belt, ziet u hier niet; vraag aan de telefoon hoe iemand u vond, en zet dat bij "+ Nieuw".</p></section>
      <form method="post" action="/beheer/overzicht/inlezen" class="kaart rij">${beheer.csrfVeld(sessie)}
        <span class="klein">${laatst ? 'Klikken ingelezen tot en met ' + dagTekst(laatst) + ' ' + laatst.slice(0, 4) + '. Dat gebeurt elke nacht.' : 'De klikken zijn nog niet ingelezen; dat gebeurt elke nacht.'}</span>
        <button type="submit" class="licht">Nu inlezen</button></form>`;
    return beheer.pagina(res, sessie, 'Overzicht', 'overzicht', inhoud, { melding: url.searchParams.get('m') === 'ingelezen' ? 'De klikken zijn ingelezen.' : null });
  }

  beheer.route('GET', /^\/beheer\/overzicht$/, (req, res, url, s) => pagina(req, res, url, s));
  beheer.route('POST', /^\/beheer\/overzicht\/inlezen$/, (req, res) => {
    klikkenInlezen(ctx);
    return beheer.terug(res, '/beheer/overzicht', 'ingelezen');
  });
}

module.exports = { registreer, periode, emmers, mooiMax, tikken, kolommen, lijnen, campagneCode, maandag };
