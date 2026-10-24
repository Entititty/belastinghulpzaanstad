'use strict';
/*
 * bron.js — waar komt een aanvraag vandaan?
 *
 * Eén categorie per aanvraag, plus een detail (welke flyer, welke partner,
 * welke zoekmachine). Volgorde van zekerheid: een partnercode wint van een
 * utm-code, en een utm-code wint van de verwijzende site. Zonder iets van
 * dat alles is het "direct": iemand typte het adres in of had een bladwijzer.
 *
 * DEZELFDE LOGICA STAAT IN js/tellingen.js (de browser rekent de categorie uit
 * voor de klikmeting). app/test/bron.test.js legt beide naast elkaar met een
 * tabel met gevallen; wijzig ze dus samen.
 */

const AI = ['chatgpt.com', 'chat.openai.com', 'perplexity.ai', 'copilot.microsoft.com', 'gemini.google.com', 'claude.ai'];
const ZOEK = ['google.', 'bing.com', 'duckduckgo.com', 'ecosia.org', 'search.yahoo.com', 'yahoo.com', 'startpage.com', 'qwant.com', 'search.brave.com'];
const SOCIAL = ['facebook.com', 'm.facebook.com', 'l.facebook.com', 'lm.facebook.com', 'instagram.com', 'l.instagram.com',
  'linkedin.com', 'lnkd.in', 'x.com', 't.co', 'twitter.com', 'nextdoor.nl', 'nextdoor.com', 'youtube.com', 'tiktok.com', 'pinterest.com', 'reddit.com'];

function past(host, lijst) {
  for (const d of lijst) {
    if (d.slice(-1) === '.') { if (host.indexOf(d) === 0 || host.indexOf('.' + d) !== -1) return true; }
    else if (host === d || host.slice(-(d.length + 1)) === '.' + d) return true;
  }
  return false;
}

/*
 * h: { ref, partnerNaam, utm_source, utm_medium, utm_campaign, verwijzer }
 * geeft { bron, detail }
 */
function bepaalBron(h) {
  const src = String(h.utm_source || '').toLowerCase();
  const med = String(h.utm_medium || '').toLowerCase();
  const camp = String(h.utm_campaign || '').toLowerCase();
  if (h.ref) return { bron: 'partner', detail: h.partnerNaam || h.ref };
  if (src === 'flyer' || med === 'print' || med === 'flyer') return { bron: 'flyer', detail: camp || src };
  if (camp === 'bedrijfsprofiel' || src === 'gbp') return { bron: 'bedrijfsprofiel', detail: 'Google' };
  if (/^(cpc|ppc|paid|ads?|betaald|display|paid-?social)$/.test(med)) return { bron: 'advertentie', detail: [src, camp].filter(Boolean).join(' / ') };
  if (med === 'email' || med === 'e-mail' || src === 'herinnering' || src === 'nieuwsbrief') return { bron: 'e-mail', detail: camp || src };
  if (src) return { bron: 'campagne', detail: [src, med, camp].filter(Boolean).join(' / ') };
  const v = String(h.verwijzer || '').toLowerCase().replace(/^www\./, '');
  if (v) {
    if (past(v, AI)) return { bron: 'ai', detail: v };
    if (past(v, ZOEK)) return { bron: 'zoekmachine', detail: v };
    if (past(v, SOCIAL)) return { bron: 'social', detail: v };
    return { bron: 'verwijzing', detail: v };
  }
  return { bron: 'direct', detail: '' };
}

/* Leesbare namen, voor /beheer en de mails */
const NAMEN = {
  partner: 'Partner', flyer: 'Flyer', bedrijfsprofiel: 'Google-bedrijfsprofiel', advertentie: 'Advertentie',
  'e-mail': 'E-mail', campagne: 'Campagne', ai: 'AI-zoeken', zoekmachine: 'Zoekmachine', social: 'Social media',
  verwijzing: 'Andere website', direct: 'Direct', 'via-via': 'Via via', 'eerder-klant': 'Eerder klant', anders: 'Anders'
};

/* Voor handmatig ingevoerde aanvragen: "Hoe kent u ons?" */
const HANDMATIG = ['via-via', 'flyer', 'partner', 'zoekmachine', 'bedrijfsprofiel', 'social', 'eerder-klant', 'anders'];

module.exports = { bepaalBron, NAMEN, HANDMATIG };
