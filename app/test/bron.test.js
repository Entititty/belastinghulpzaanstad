'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { bepaalBron } = require('../lib/bron');

const GEVALLEN = [
  [{}, 'direct', ''],
  [{ verwijzer: 'google.nl' }, 'zoekmachine', 'google.nl'],
  [{ verwijzer: 'www.google.com' }, 'zoekmachine', 'google.com'],
  [{ verwijzer: 'bing.com' }, 'zoekmachine', 'bing.com'],
  [{ verwijzer: 'duckduckgo.com' }, 'zoekmachine', 'duckduckgo.com'],
  [{ verwijzer: 'chatgpt.com' }, 'ai', 'chatgpt.com'],
  [{ verwijzer: 'gemini.google.com' }, 'ai', 'gemini.google.com'],
  [{ verwijzer: 'www.perplexity.ai' }, 'ai', 'perplexity.ai'],
  [{ verwijzer: 'grok.com' }, 'ai', 'grok.com'],
  [{ verwijzer: 'copilot.cloud.microsoft' }, 'ai', 'copilot.cloud.microsoft'],
  [{ utm_source: 'chatgpt.com' }, 'ai', 'chatgpt.com'],
  [{ utm_source: 'chatgpt.com', verwijzer: 'chatgpt.com' }, 'ai', 'chatgpt.com'],
  [{ utm_source: 'perplexity' }, 'ai', 'perplexity'],
  [{ utm_source: 'chat.openai.com' }, 'ai', 'chat.openai.com'],
  [{ verwijzer: 'l.facebook.com' }, 'social', 'l.facebook.com'],
  [{ verwijzer: 'nextdoor.nl' }, 'social', 'nextdoor.nl'],
  [{ verwijzer: 'zaanstad.nl' }, 'verwijzing', 'zaanstad.nl'],
  [{ utm_source: 'flyer', utm_campaign: 'rosmolenwijk' }, 'flyer', 'rosmolenwijk'],
  [{ utm_source: 'krant', utm_medium: 'print', utm_campaign: 'dagblad-zaanstreek' }, 'flyer', 'dagblad-zaanstreek'],
  [{ utm_source: 'google', utm_medium: 'organic', utm_campaign: 'bedrijfsprofiel' }, 'bedrijfsprofiel', 'Google'],
  [{ utm_source: 'google', utm_medium: 'cpc', utm_campaign: 'vt-2027' }, 'advertentie', 'google / vt-2027'],
  [{ utm_source: 'facebook', utm_medium: 'paid-social' }, 'advertentie', 'facebook'],
  [{ utm_source: 'herinnering', utm_medium: 'email', utm_campaign: 'aangifte-2026' }, 'e-mail', 'aangifte-2026'],
  [{ utm_source: 'buurtkrant' }, 'campagne', 'buurtkrant'],
  [{ ref: 'jansen', utm_source: 'flyer', verwijzer: 'google.nl' }, 'partner', 'jansen'],
  [{ ref: 'jansen', partnerNaam: 'Jansen Makelaardij' }, 'partner', 'Jansen Makelaardij']
];

test('bron per geval', () => {
  for (const [invoer, bron, detail] of GEVALLEN) {
    assert.deepEqual(bepaalBron(invoer), { bron, detail }, JSON.stringify(invoer));
  }
});

/* js/tellingen.js rekent in de browser dezelfde categorie uit voor de
 * klikmeting. Haal die functie uit het bestand en leg hem ernaast. */
test('js/tellingen.js geeft dezelfde bron als de server', () => {
  const fs = require('fs');
  const path = require('path');
  const vm = require('vm');
  const bron = fs.readFileSync(path.join(__dirname, '..', '..', 'js', 'tellingen.js'), 'utf8');
  const m = /\/\* BRON-BEGIN \*\/([\s\S]*?)\/\* BRON-EINDE \*\//.exec(bron);
  assert.ok(m, 'markeringen BRON-BEGIN/BRON-EINDE niet gevonden in js/tellingen.js');
  const browser = vm.runInNewContext(m[1] + '; bepaalBron');
  for (const [invoer] of GEVALLEN) {
    assert.deepEqual({ ...browser(invoer) }, bepaalBron(invoer), JSON.stringify(invoer));
  }
});

module.exports = { GEVALLEN };
