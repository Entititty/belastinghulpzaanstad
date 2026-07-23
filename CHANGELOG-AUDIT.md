# Changelog — SEO/Performance audit

Branch: `seo-performance-audit`. Wijzigingen n.a.v. `AUDIT.md`, per logische stap.
Ontwerp en merkstem blijven ongemoeid. Contentwijzigingen zijn voorstellen.

---

## 2026-07-23

### Onderzoek & rapport
- **AUDIT.md** geschreven (Fase 3): snelheid/CWV, technische SEO, on-page SEO, GEO.
- **Herprioritering** (jouw akkoord): expert-auteur → P1 (YMYL), consent → nieuw P1, priceRange-regel (verwijderen bij mismatch i.p.v. gelijktrekken).
- **§7 Overlap-analyse stadspagina's** toegevoegd: gemeten % unieke bodytekst per pagina (zaandam/assendelft 18%, krommenie 22%, zaandijk 25%; overige 40-49%). Doorway-risico. Per prioriteitspagina 3-5 lokale contentideeën voorgesteld. **Wacht op reactie** vóór contentwijziging.
- **§8 Consent/privacy** toegevoegd: trackers laden zonder toestemming, geen CMP, dode Privacybeleid-link, geen privacypagina. Oplossing voorgesteld. **Wacht op reactie** vóór implementatie.
- **§9 Auteur-voorstel** toegevoegd: `Person`-schema-structuur; tekst/gegevens komen van de eigenaar.

### Uitgevoerd deze ronde (branch `seo-performance-audit`)
Elke wijziging als aparte commit; na elke wijziging JSON-LD/HTML-sanitycheck gedraaid.

1. **Mojibake** — `â‚¬`→`€` (37×), `â€"`→`—` (8×), `Ã©Ã©`→`éé` (1×) in 9 stadspagina's; 36 JSON-LD-blokken geverifieerd valide.
2. **robots.txt** — ongeldige `Sitemap: …/llms.txt` verwijderd.
3. **datePublished** — toegevoegd aan 22 blog-Article-schema's; datum afgeleid uit eerste git-commit (aantoonbaar), afgetopt op dateModified; 132 JSON-LD-blokken valide.
4. **WebSite + Organization** — schema (met logo, publisher-ref) op homepage; 5 blokken valide.
5. **llms.txt** — 9 nieuwe artikelen + 2 rekentools + EN-sectie; zorgtoeslag-cijfer + huurtoeslag-2026 FAQ; 40 links geverifieerd.
6. **Interne links `/diensten/`** — van ~5 naar 11 linkers (5 contextuele links in aangifte-artikelen).
7. **Fonts self-hosten** — Google Fonts weg; 2 self-hosted variabele woff2 (149,8 KB) via @font-face in de al-geladen CSS + preload display-font. VOOR: 3 externe requests / 2 hosts. NA: 0 externe font-requests. Inline @font-face op 3 CSS-loze pagina's.
8. **Clarity** — ontbrekend tag-script toegevoegd op uitstel-belastingaangifte-2025.

### Nieuwe bevinding tijdens uitvoering (nog niet gefixt — zie AUDIT.md §10)
Verouderde huurtoeslag-cijfers in blogcontent (`huurtoeslag-grens`, mogelijk `huurtoeslag-aanvragen`) die de gecorrigeerde rekentool tegenspreken. Content — wacht op akkoord.
