'use strict';
/*
 * push.js — een seintje op de telefoon bij een nieuwe aanvraag, naast de mail.
 * Staat uit, tenzij PUSH_DIENST in app.env staat:
 *   PUSH_DIENST=pushover  met PUSHOVER_TOKEN en PUSHOVER_GEBRUIKER
 *   PUSH_DIENST=telegram  met TELEGRAM_TOKEN en TELEGRAM_CHAT
 *
 * Er gaan GEEN persoonsgegevens mee: alleen "Nieuwe aanvraag: voorlopige
 * teruggave" en een link naar /beheer. Pushover en Telegram zijn
 * buitenlandse diensten; met alleen dit erin hoeven ze niet in het
 * privacybeleid. Bellen doet u vanuit /beheer of vanuit de mail.
 */
function maakPush(env, log, basisUrl) {
  const stuur = (url, init) => fetch(url, Object.assign({ method: 'POST', signal: AbortSignal.timeout(10000) }, init))
    .then((r) => { if (!r.ok) log('fout', 'push mislukt: HTTP ' + r.status); })
    .catch((e) => log('fout', 'push mislukt: ' + e.message.replace(/bot[0-9]+:[A-Za-z0-9_-]+/g, 'bot[token]')));
  if (env.PUSH_DIENST === 'pushover' && env.PUSHOVER_TOKEN && env.PUSHOVER_GEBRUIKER) {
    return (tekst, pad) => stuur('https://api.pushover.net/1/messages.json', {
      body: new URLSearchParams({ token: env.PUSHOVER_TOKEN, user: env.PUSHOVER_GEBRUIKER, message: tekst, url: basisUrl + pad, url_title: 'Open in beheer' })
    });
  }
  if (env.PUSH_DIENST === 'telegram' && env.TELEGRAM_TOKEN && env.TELEGRAM_CHAT) {
    return (tekst, pad) => stuur('https://api.telegram.org/bot' + env.TELEGRAM_TOKEN + '/sendMessage', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT, text: tekst + '\n' + basisUrl + pad, disable_web_page_preview: true })
    });
  }
  return null;
}

module.exports = { maakPush };
