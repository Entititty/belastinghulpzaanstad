'use strict';
/*
 * limiet.js — hoe vaak mag iets per sleutel (meestal een IP-adres) in een venster.
 *
 * Alleen in het geheugen. IP-adressen komen zo nooit in de database of op
 * schijf, en na een herstart begint de telling opnieuw; dat is prima. nginx
 * heeft daarvóór een eigen, grovere limiet.
 */
class Limiet {
  constructor(max, vensterMs) {
    this.max = max;
    this.venster = vensterMs;
    this.tellers = new Map();
  }

  /* true als het mag; telt dan ook meteen mee */
  mag(sleutel, nu) {
    const t = typeof nu === 'number' ? nu : Date.now();
    let x = this.tellers.get(sleutel);
    if (!x || t - x.start >= this.venster) { x = { start: t, n: 0 }; this.tellers.set(sleutel, x); }
    if (x.n >= this.max) return false;
    x.n++;
    if (this.tellers.size > 5000) this.opruimen(t);
    return true;
  }

  opruimen(nu) {
    for (const [k, x] of this.tellers) if (nu - x.start >= this.venster) this.tellers.delete(k);
  }
}

module.exports = { Limiet };
