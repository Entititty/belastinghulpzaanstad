'use strict';
/*
 * valideer.js — controle en opschoning van alles wat een bezoeker invult.
 *
 * Elke functie geeft { waarde } terug, of { fout: '...' }. De foutcodes zet
 * aanvraag.js om in een zin in gewone taal. Niets hier gooit een exceptie op
 * rare invoer: een bot die troep stuurt, krijgt een nette weigering.
 */

/* Kengetallen van twee cijfers (plus de 0). Alle andere vaste nummers hebben
 * een kengetal van drie cijfers. Alleen nodig om het nummer leesbaar te tonen. */
const KORT_KENGETAL = new Set(['010', '013', '015', '020', '023', '024', '026', '030', '033', '035', '036', '038',
  '040', '043', '045', '046', '050', '053', '055', '058', '070', '071', '072', '073', '074', '075', '076', '077',
  '078', '079', '085', '088', '091']);

function weergave(nat) {
  if (/^06/.test(nat)) return '06 ' + nat.slice(2).replace(/(\d{2})(?=\d)/g, '$1 ');
  if (KORT_KENGETAL.has(nat.slice(0, 3))) return nat.slice(0, 3) + ' ' + nat.slice(3, 6) + ' ' + nat.slice(6);
  return nat.slice(0, 4) + ' ' + nat.slice(4, 6) + ' ' + nat.slice(6, 8) + ' ' + nat.slice(8);
}

/*
 * Telefoonnummer. Neemt 06 12345678, 06-12 34 56 78, +31 6 1234 5678,
 * +31 (0)6..., 0031 6..., 31612345678 en 612345678 aan. Resultaat:
 *   { waarde: '+31612345678', soort: 'mobiel' | 'vast' | 'buitenland', weergave: '06 12 34 56 78' }
 * Niet aangenomen: 0800/090x (betaalnummers), 066 (semafoon), 067 (inbelnummers),
 * 097 (machines). Een buitenlands nummer mag wel, met soort 'buitenland': via de
 * Engelse pagina's komen expats met een Brits of Duits mobiel nummer.
 */
function telefoon(invoer) {
  let s = String(invoer == null ? '' : invoer).trim();
  if (!s) return { fout: 'leeg' };
  if (s.length > 32) return { fout: 'ongeldig' };
  s = s.replace(/\(0\)/g, '');
  if (/[^\d+\s\-.()/]/.test(s)) return { fout: 'ongeldig' };
  let c = s.replace(/[\s\-.()/]/g, '');
  if ((c.match(/\+/g) || []).length > 1 || c.indexOf('+') > 0) return { fout: 'ongeldig' };
  if (c[0] === '+') c = '00' + c.slice(1);

  let nat;
  /* +31 06... (met de 0 erachter) komt ook voor */
  if (c.indexOf('0031') === 0) nat = '0' + c.slice(4).replace(/^0/, '');
  else if (c.indexOf('00') === 0) {
    const e = c.slice(2);
    if (!/^[1-9]\d{7,14}$/.test(e)) return { fout: 'ongeldig' };
    return { waarde: '+' + e, soort: 'buitenland', weergave: '+' + e };
  } else if (/^31[1-9]\d{8}$/.test(c)) nat = '0' + c.slice(2);
  else if (/^[1-9]\d{8}$/.test(c)) nat = '0' + c;
  else nat = c;

  if (!/^0[1-9]\d{8}$/.test(nat)) return { fout: 'ongeldig' };
  if (/^0(66|67|800|90|97)/.test(nat)) return { fout: 'ongeldig' };
  const soort = /^06[1-58]/.test(nat) ? 'mobiel' : (/^06/.test(nat) ? null : 'vast');
  if (!soort) return { fout: 'ongeldig' };
  return { waarde: '+31' + nat.slice(1), soort: soort, weergave: weergave(nat) };
}

/* Weergave van een opgeslagen nummer (+31...) */
function telefoonWeergave(e164) {
  if (!e164) return '';
  if (e164.indexOf('+31') === 0) return weergave('0' + e164.slice(3));
  return e164;
}

function email(invoer) {
  const s = String(invoer == null ? '' : invoer).trim();
  if (!s) return { leeg: true };
  if (s.length > 254) return { fout: 'ongeldig' };
  const m = /^([^\s@<>()[\]\\,;:"]{1,64})@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})$/i.exec(s);
  if (!m) return { fout: 'ongeldig' };
  /* Helemaal in kleine letters. Strikt genomen mag het deel voor de @
   * hoofdlettergevoelig zijn, maar geen enkele gangbare provider doet dat, en
   * zo staat Piet@ en piet@ niet twee keer op de herinneringslijst. */
  return { waarde: (m[1] + '@' + m[2]).toLowerCase() };
}

function schoon(s) {
  return String(s == null ? '' : s).replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '');
}

function naam(invoer) {
  const s = schoon(invoer).replace(/\s+/g, ' ').trim();
  if (s.length < 2) return { fout: 'leeg' };
  if (s.length > 80) return { fout: 'te-lang' };
  if (!/\p{L}/u.test(s)) return { fout: 'ongeldig' };
  /* Een naam met een link of een tag erin is altijd spam. */
  if (/https?:|www\.|[<>]/i.test(s)) return { waarde: s, spam: true };
  return { waarde: s };
}

/* Opmerking of bericht. Meer dan één link: spam. */
function tekst(invoer, max) {
  const s = schoon(invoer).trim();
  if (s.length > max) return { fout: 'te-lang' };
  const links = (s.match(/https?:\/\/|www\./gi) || []).length;
  return { waarde: s, spam: links > 1 };
}

/* Een pad op onze eigen site, zonder querystring: "/senioren/" */
function pad(invoer) {
  let s = String(invoer == null ? '' : invoer).trim();
  if (/^https?:\/\//i.test(s)) {
    try { s = new URL(s).pathname; } catch (e) { return ''; }
  }
  s = s.split(/[?#]/)[0].toLowerCase();
  return /^\/[a-z0-9/._-]{0,120}$/.test(s) ? s : '';
}

/* Alleen het domein van een verwijzer: "google.com" */
function domein(invoer) {
  const s = String(invoer == null ? '' : invoer).trim().toLowerCase();
  if (!/^[a-z0-9.-]{3,100}$/.test(s) || s.indexOf('.') === -1) return '';
  return s.replace(/^www\./, '');
}

/* utm-waarden: kort en zonder vreemde tekens */
function campagne(invoer) {
  const s = String(invoer == null ? '' : invoer).trim().toLowerCase();
  return /^[a-z0-9 ._+\-/]{1,80}$/.test(s) ? s : '';
}

function refCode(invoer) {
  const s = String(invoer == null ? '' : invoer).trim().toLowerCase();
  return /^[a-z0-9-]{1,40}$/.test(s) ? s : '';
}

function kort(v, max) { return schoon(v).replace(/\s+/g, ' ').trim().slice(0, max); }

/*
 * De invoer en uitkomst van een rekentool. rekenhulp.js stuurt JSON:
 *   { "invoer": [["WOZ-waarde", "305000"], ...], "uitkomst": [["Per maand", "€ 339"], ...] }
 * Een oude pagina in iemands browsercache stuurt nog platte tekst; die
 * bewaren we dan als { tekst }.
 */
function berekening(invoer) {
  const s = String(invoer == null ? '' : invoer);
  if (!s.trim()) return null;
  if (s.length > 6000) return null;
  let j;
  try { j = JSON.parse(s); } catch (e) { return { tekst: schoon(s).trim().slice(0, 2000) }; }
  if (!j || typeof j !== 'object') return null;
  const lijst = (x) => (Array.isArray(x) ? x : []).slice(0, 30)
    .filter((p) => Array.isArray(p) && p.length === 2)
    .map((p) => [kort(p[0], 120), kort(p[1], 200)]);
  return { invoer: lijst(j.invoer), uitkomst: lijst(j.uitkomst) };
}

module.exports = { telefoon, telefoonWeergave, email, naam, tekst, pad, domein, campagne, refCode, berekening, kort };
