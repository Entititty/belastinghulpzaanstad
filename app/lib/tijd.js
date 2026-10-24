'use strict';
/*
 * tijd.js — Nederlandse tijd, los van de tijdzone van de machine.
 *
 * In de database staat alles in UTC (ISO-tekst). Plannen en tonen gebeurt in
 * Nederlandse tijd: het dagoverzicht om 17:30 is 17:30 in Zaandam, ook in de
 * zomer en ook als de server of de testmachine een andere tijdzone heeft.
 * Daarom Intl met een vaste tijdzone in plaats van getHours().
 */

const ZONE = 'Europe/Amsterdam';
const DELEN = new Intl.DateTimeFormat('en-GB', {
  timeZone: ZONE, year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', weekday: 'short', hourCycle: 'h23'
});
const WEEKDAG = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

/* { datum: '2026-10-24', tijd: '18:03', weekdag: 6 } in Nederlandse tijd */
function nl(d) {
  const p = {};
  for (const x of DELEN.formatToParts(d)) p[x.type] = x.value;
  return {
    datum: p.year + '-' + p.month + '-' + p.day,
    tijd: p.hour + ':' + p.minute,
    weekdag: WEEKDAG[p.weekday]
  };
}

/* Een Nederlandse kloktijd ("2027-02-25 10:00") als Date. Probeert de twee
 * mogelijke UTC-verschuivingen (winter +1, zomer +2) en neemt die welke terug
 * dezelfde kloktijd geeft. */
function vanNl(tekst) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})$/.exec(String(tekst || '').trim());
  if (!m) throw new Error('ongeldige tijd: ' + tekst + ' (verwacht JJJJ-MM-DD UU:MM)');
  for (const uur of [1, 2]) {
    const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4] - uur, +m[5]));
    const t = nl(d);
    if (t.datum === m[1] + '-' + m[2] + '-' + m[3] && t.tijd === m[4] + ':' + m[5]) return d;
  }
  throw new Error('tijd bestaat niet in Nederland (zomertijdsprong): ' + tekst);
}

function isoNu(klok) { return klok().toISOString(); }

function minMaanden(d, n) {
  const x = new Date(d.getTime());
  x.setUTCMonth(x.getUTCMonth() - n);
  return x;
}
function minDagen(d, n) { return new Date(d.getTime() - n * 864e5); }
function minMinuten(d, n) { return new Date(d.getTime() - n * 6e4); }

const LEESBAAR = new Intl.DateTimeFormat('nl-NL', {
  timeZone: ZONE, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'
});
const DATUM = new Intl.DateTimeFormat('nl-NL', { timeZone: ZONE, day: 'numeric', month: 'long', year: 'numeric' });

/* "za 24 okt, 18:03"; een ongeldige datum geeft lege tekst in plaats van een fout */
function leesbaar(iso) {
  const d = iso ? new Date(iso) : null;
  return d && !isNaN(d) ? LEESBAAR.format(d) : '';
}
/* "24 oktober 2026" */
function datumTekst(iso) {
  const d = iso ? new Date(iso) : null;
  return d && !isNaN(d) ? DATUM.format(d) : '';
}

module.exports = { ZONE, nl, vanNl, isoNu, minMaanden, minDagen, minMinuten, leesbaar, datumTekst };
