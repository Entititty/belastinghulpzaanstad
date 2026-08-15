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

## 2026-07-24

### §10 — Verouderde huurtoeslag-cijfers gecorrigeerd (na akkoord "fix de voorstellen")
`blog/huurtoeslag-grens/` + `blog/huurtoeslag-aanvragen/` gelijkgetrokken met de officiële 2026-cijfers uit de rekentool:
- maximale rekenhuur €900,07 → **€932,93**; huurgrens-tabel (23 jaar/€454,47/€808,06) → **21 jaar/€498,20 en 21+/€932,93**
- vermogensgrens €37.395/€74.790 → **€36.952/€73.904**
- "te dure woning = geen recht" → **2026-aftopregel** (huur boven €932,93 diskwalificeert niet meer, telt alleen niet mee)
- servicekosten: "meestal niet mee" → **vanaf 2026 niet meer mee**
- leeftijdsgrens jongeren 23 → **21 jaar**; meta-descriptions bijgewerkt; JSON-LD FAQ's mee gecorrigeerd
- Beide bestanden: JSON-LD geverifieerd valide; geen oude cijfers meer sitebreed.

### Beslissingen (jouw akkoord 2026-07-24)
§7 → nu doen met echte lokale feiten · §8 Pixel → verwijderen · §8 consent → bouwen mét Consent Mode v2 · §9 → organisatie blijft auteur (geen persoon).

### §8a — Meta Pixel verwijderd
Pixel-init + noscript + facebook dns-prefetches van alle 77 pagina's verwijderd (3 verschillende blok-formaten). fbq/connect.facebook.net/facebook.com/tr = 0. Footer-profiellink behouden. GA4 + Clarity blijven staan tot de consent-gate er is.

## 2026-07-25

### §8b — Consent-gate + Google Consent Mode v2 + privacypagina
Gegevens van eigenaar: geen KvK/bezoekadres (nieuw initiatief 2026), contact `info@belastinghulpzaanstad.nl`. Op de privacypagina staat "Belastinghulp Zaanstad" als verwerkingsverantwoordelijke, expliciet zonder KvK/adres; geen verzonnen bedrijfsdata.
- **`/js/consent.js`** (nieuw): zelf-gehoste, tweetalige (NL/EN) consent-banner. Zet Consent Mode v2 defaults op `denied` (analytics_storage, ad_storage, ad_user_data, ad_personalization, personalization_storage) vóór `gtag('config')`. GA4 laadt daardoor cookieloos tot toestemming.
- **Microsoft Clarity** wordt niet meer standaard geladen: de inline IIFE is van alle 78 pagina's verwijderd en de clarity dns-prefetch weg. Clarity wordt alleen geïnjecteerd ná 'Accepteren'.
- Keuze onthouden in `localStorage` (`bhz_consent_v1`); balk verschijnt niet meer na een keuze. `window.bhzResetConsent()` reset de keuze.
- **`consent.js`** ingehangen vóór de gtag-loader op alle 80 pagina's.
- **Privacypagina's** `/privacy/` (NL) + `/en/privacy/` (EN): verantwoordelijke, welke gegevens/grondslag, cookies (GA4 + Clarity), delen met derden, bewaartermijn, rechten (incl. AP-klacht), knop 'cookievoorkeur wijzigen'. Toegevoegd aan sitemap.xml.
- **Dode/verkeerd gerichte footer-link 'Privacybeleid'** (`href="#"` op index, `href="../"`/`"../../"` op 10 stad-/dienstpagina's) → `/privacy/` op alle 11 NL-pagina's.
- Sanity: 80 HTML-pagina's, 292 JSON-LD-blokken valide, exact 1 `<head>`/`<body>` + 1 consent.js per pagina; `node --check` op consent.js OK.

### §7 — 4 stadspagina's uniek gemaakt met geverifieerde lokale cijfers
De twee echt-lokale blokken per kern (LOCAL INTRO + "Belastingtips specifiek voor…") herschreven met onderscheidende, kloppende feiten. Bron cijfers: CBS/AlleCijfers.nl (inwoners 2026, gemiddelde WOZ-waarde 2025, % koop/huur).
- **Assendelft**: 22.000→**25.460** inw, €385.000→**€470.045** WOZ, 60%→**72%** koop. Invalshoek: hoogste huizenwaarde + meeste koopwoningen van Zaanstad; nieuwbouwwijk Saendelft (starters/jonge gezinnen); eigenwoningforfait + hypotheekrenteaftrek.
- **Krommenie**: 17.000→**17.237** inw, €305.000→**€386.390** WOZ, **53%** koop/47% huur. Invalshoek: Forbo-linoleumhistorie; oudere woningen → WOZ-bezwaar; huurders → toeslagen/kwijtschelding; senioren.
- **Zaandijk**: 8.500→**8.868** inw, €330.000→**€382.923** WOZ, **53%** koop. Invalshoek: historische Zaanse panden/Lagedijk/Zaanse Schans → WOZ/monumenten; Rooswijk; senioren. Niet-verifieerbare ANBI-claim (Doopsgezinde kerk) verwijderd.
- **Zaandam**: 75.000→**84.461** inw, €340.000→**€370.266** WOZ; distinctief **52% huurwoningen** → toeslagen/kwijtschelding. Onjuiste "€9.000 aftrek (bron: CBS)" en "€343.000" verwijderd.
- Stat-grids: de niet-verifieerbare velden 'Gem. woningprijs' + 'Gem. maandelijkse teruggave' vervangen door **'Gem. WOZ-waarde'** + **'% koop/huur'** (echte cijfers). Gedeelde dienst-/tarief-/FAQ-secties bewust ongemoeid (zelfde aanbod = terecht identiek). Sanity: JSON-LD valide, 1 head/body per pagina.

### §7-vervolg — overige 5 stadspagina's rechtgetrokken (na akkoord "ga zo door")
Zelfde CBS/AlleCijfers-behandeling toegepast op wormerveer, koog-aan-de-zaan, westzaan, wormerland, oostzaan (inwoners 2026, gem. WOZ 2025, % koop/huur):
- **Wormerveer**: 16.000→**12.735** inw, €280.000→**€338.000** WOZ, **51%** koop. Laagste WOZ van de Zaanse kernen; Wessanen-historie; 49% huurders → toeslagen.
- **Koog aan de Zaan**: 8.000→**11.306** inw, €310.000→**€388.878** WOZ, **61%** koop. Duyvis/Molenmuseum; verhuur bij Zaanse Schans.
- **Westzaan**: 8.000/4.500→**5.131** inw, €350.000→**€510.000** WOZ, **79%** koop (hoogste aandeel van de streek); stolpen/monumenten → WOZ.
- **Oostzaan**: 9.000→**9.778** inw, €375.000→**€522.000** WOZ (hoogste), **67%** koop. **Eigen gemeente** — WOZ/OZB/kwijtschelding via gemeente Oostzaan.
- **Wormerland**: 16.500→**16.328** inw, €340.000→**€441.000** WOZ, **63%** koop. **Eigen gemeente**; kernen gecorrigeerd (Neck → Wijdewormer/Oostknollendam); verzonnen per-kern woningwaardes (€352k/€418k/€310k) verwijderd.
- **Feitfixes**: onjuiste "auto-reiskostenaftrek >10 km" (bestaat niet voor werknemers) en achterhaalde "zonnepaneel-btw teruggave" vervangen door kloppende WOZ/toeslag-content. Niet te verifiëren claims ("30% is 65-plusser", "veel ZZP'ers", specifieke ouderenkorting €2.035) geschrapt.
- Alle 9 stadspagina's dragen nu **'Gem. WOZ-waarde' + '% koopwoningen'** i.p.v. de oude niet-verifieerbare velden. Sanity: JSON-LD valide, 1 head/body per pagina.

### Nog te doen / aandachtspunt
- **§9 — organisatie blijft auteur**: geen actie (Organization-schema is al verrijkt in Fix 4).
- **Herverificatie stadspagina-overlap** (audit §7 mat 18-25% uniek vóór deze ronde) kan opnieuw gedraaid worden om het effect te kwantificeren — optioneel.

## 2026-07-26 — SEO/GEO/CTR-ronde (branch `seo-geo-ctr-round2`)

Uitgevoerd n.a.v. de P0–P2-opdracht. STAP 0-inventarisatie eerst gedraaid; al aanwezige zaken overgeslagen.

**Al aanwezig (overgeslagen):** Taak 2 (FAQPage home) ✅ · Taak 3 (BreadcrumbList + zichtbaar kruimelpad) ✅ · Taak 7 grotendeels (1 `<h1>`/pagina, 0 content-afbeeldingen dus geen alt/lazy/WebP nodig, kern-titles/descriptions 9/9 uniek) ✅.

**Uitgevoerd:**
- **Taak 6** — `meta name="keywords"` van 77 paginas verwijderd.
- **Taak 9** — `## Contact`-blok (telefoon/WhatsApp, e-mail, website, Facebook, privacy) toegevoegd aan llms.txt.
- **Taak 1** — canoniek `LocalBusiness`+`AccountingService`-blok (`@id #business`, areaServed, serviceType, priceRange €49–€109, sameAs, openingHours, geen storefront-adres) op alle 80→84 paginas; oude losse `#localbusiness`-blokken (9 kernen) verwijderd om dubbele entiteiten te voorkomen.
- **Taak 4** — `mainEntityOfPage` toegevoegd aan 36 Article-schema's; nu 52/52 compleet (headline, author=Organization, publisher, datePublished, dateModified, mainEntityOfPage).
- **Taak 5** — 4 indexeerbare servicepagina's: `/diensten/voorlopige-teruggave/`, `/box-3-bezwaar/`, `/correctie-late-aangifte/`, `/erfbelasting-schenking/`. Eigen title/description/H1, `Service`-schema, kruimelpad + `BreadcrumbList`, FAQ (zichtbaar + `FAQPage`), `#business`-blok. In sitemap; intern gelinkt vanaf home-footer + onderlinge kruislinks.
- **Taak 8** — na jouw keuze: **organisatie blijft auteur**, geen persoonsnaam/Beconnummer (niets verzonnen). Geen wijziging.
- **Taak 10** — (a) zichtbare "Laatst bijgewerkt"/"Last updated" op alle 52 artikelen gekoppeld aan `dateModified` (met `<time>`); (b) "Direct antwoord"/"Quick answer"-TL;DR met harde cijfers bovenaan alle 52 artikelen (NL+EN), elk gebaseerd op de eigen cijfers van dat artikel.

**Sanity:** eindstand 84 HTML-paginas, 383 JSON-LD-blokken, 0 ongeldig, 1 `<head>`/`<body>` + 1 `<h1>` per pagina, sitemap 83 URLs.

**Buiten code (jouw actie):** Google Business Profile aanmaken (grootste lokale klikbron); reviews pas verzamelen en dán `Review`/`AggregateRating` toevoegen.

## 2026-07-27 — Ronde 2: template-consistentie + CTR + content (branch `ronde-2-templates`)

STAP 0-inventarisatie eerst gedraaid en teruggekoppeld. Al kloppende zaken overgeslagen
(keywords al weg, datePublished al aanwezig, privacy-link al gefixt, Facebook-pixel bestaat
niet — alleen `sameAs`-link, Clarity via consent.js-injectie i.p.v. hardcoded).

**P0 — consistentie**
- **Taak 1** — één canonieke footer (root-relatief) op alle 83 paginas (NL + EN elk identiek). Diensten-kolom overal `/diensten/*` (was op over-ons+blogs verouderde `#`-ankers); dubbele "Voorlopige teruggave"-link weg; 9 kernen overal; privacy overal.
- **Taak 3** — canonieke nav + nieuwe **Diensten-dropdown** (CSS-only, hover desktop / inline mobiel) op alle 83 paginas; dode lokale `#tarieven/#werkwijze/#faq`-ankers op dienstenpaginas gefixt naar `/#...`; logo-href genormaliseerd. Visueel geverifieerd (headless Edge).
- **Taak 2** — 43 blog-body-CTA's omgelegd: 12 naar `/diensten/*` (seniorenpakket→aangifte, eerste-woning→voorlopige-teruggave, aangifte→aangifte, bezwaar→box-3), rest root-relatief (`/#contact`, `/#tarieven`); EN-blogs root-relatief.

**P1 — CTR & social**
- **Taak 4** — 9 merk-og:images (1200×630, eigen fonts/kleuren, geen foto's): NL+EN default + 5 diensten + 2 rekentools. `og:image`(+secure_url/type/width/height/alt) en `twitter:image` op alle 83 paginas; `twitter:card` overal `summary` → `summary_large_image`. 2 privacypaginas kregen alsnog een twitter:card.
- **Taak 5** — 9 kern-descriptions (meta+og+twitter) waren bijna identiek → per kern uniek herschreven met feitelijke lokale invalshoek. hreflang: 3 niet-wederkerige gevallen gefixt → 100% wederkerig (checker: 0 issues). keywords al weg.
- **Taak 6** — homepage uitstel-strip datumgestuurd: wisselt ná 1-9-2026 automatisch naar Beconregeling (tot 1-5-2027); standaardtekst blijft in HTML (crawler-veilig). Beide staten visueel geverifieerd. **CONTENT-VERVALDATA.md** toegevoegd (alle datumgebonden content + controlemomenten).

**P2 — restant**
- **Taak 8** — llms.txt: `## Diensten` (5 paginas), volledige tariefstructuur, 2 FAQ's (box 3, erfbelasting).
- **Taak 9** — kernartikelen tegen belastingdienst.nl geverifieerd en gecorrigeerd: **ouderenkorting** (€2.035→€2.067, €478→€540, grens €44.770→€46.002, nul €57.310→€59.783; NL+EN+llms), **hypotheekrenteaftrek** (box 1-tarief 36,93%(2023!)→37,56%(2026) + voorbeeld herrekend + wet-Hillen-grens €1,35M + wording), **zorgtoeslag** (grens €38.520/€48.224→€40.857/€51.142; NL+EN+llms). huurtoeslag was al correct. **OPEN (wacht op go):** stale 36,93% staat nog op 15 andere paginas (o.a. homepage-hero €289) — per context 35,75%/37,56% + hercalculatie; gedocumenteerd in CONTENT-VERVALDATA.md.
- **Taak 10** — geverifieerd, **geen wijziging nodig**: geen Facebook-pixel (premisse onjuist); GA4+Clarity laden consistent op alle 84 paginas via Consent Mode v2 (consent.js vóór gtag); NL+EN privacybeleid dekt beide correct incl. intrekken.
- **Taak 7 (E-E-A-T)** — **geblokkeerd**: wacht op eigenaar-gegevens (naam adviseur + achtergrond, Beconnummer, KvK-nummer). Niets verzonnen.

**Buiten code (jouw actie / open):** (1) naam/Becon/KvK aanleveren voor Taak 7; (2) go voor de 36,93%→2026-tarieven-sweep op 15 paginas (raakt zichtbaar homepage-cijfer €289); (3) stadspagina-overlap §7 en definitief og-beeld blijven jouw call.

---

## 2026-08-09 t/m 2026-08-15 — SEO/GEO-plan, fase 0 t/m 3 (branch `seo-geo-2026-08`)

Uitgevoerd n.a.v. het SEO/GEO-plan. Volgorde aangehouden: eerst meten, dan techniek,
dan content, dan CTR.

### Beveiliging
- `.gitignore` was een **map** in plaats van een bestand; de Search Console-sleutel
  stond erin. Omdat de webroot de repo-root is en de server `git reset --hard` doet,
  had een `git add .` die sleutel publiek gezet. Sleutel verplaatst naar
  `~/.secrets/`, echte `.gitignore` aangelegd, nginx weigert nu `/data/gsc/`,
  `/reports/`, `data/crawl.csv` en `data/baseline-*.md`.
- Meetgegevens blijven bewust buiten git: het zijn bedrijfsgegevens.

### Schema
- **Dubbele bedrijfsentiteit weg** (20 pagina's). Naast de canonieke `#business`-knoop
  stond een tweede `ProfessionalService` zonder `@id`, met een afwijkende prijs.
  Op 19 pagina's zat die alleen in JavaScript — onzichtbaar voor GPTBot,
  OAI-SearchBot, PerplexityBot en ClaudeBot, die geen JS uitvoeren.
- Adres en `Zaanstad` als `areaServed` samengevoegd in de canonieke knoop.
- `/en/` kreeg de ontbrekende `Organization` en `WebSite`.
- Schema-gaten t.o.v. plan §4.2: van 58 naar 5, en die 5 zijn terechte weglatingen.

### E-E-A-T
- Echte auteur op 52 artikelen: `Person`-schema, `meta author` en een zichtbare
  byline naar `/over-ons/#stan`. Auteurskaart met foto en LinkedIn op `/over-ons/`
  en `/en/about-us/`.

### Prijzen
- De losse tier "alleen voorlopige teruggave aanvragen" (€49) is vervallen; die
  dienst is nu €109, met partner €149. 34 vindplaatsen in NL en EN bijgewerkt.
- `priceRange` overal €59–€149; stond eerst op twee verschillende waarden.
- Prijsbadge van €59 uit `og-voorlopige-teruggave.png` gehaald (dienst kost €109).

### Interne links
- "Lees ook"-blok op 46 artikelen, drie inhoudelijk verwante links per stuk,
  gekozen op onderwerp én op hoe arm de doelpagina aan links was.
- De 10 dienstpagina's linkten naar géén enkel artikel; dat is nu wel zo.
- Pagina's met minder dan 5 interne in-links: van 21 naar 1.

### Content
- Nieuwe pillar `/diensten/toeslagen/` (1.172 woorden). Search Console wees dit aan:
  18 van de 26 beste content-kansen zijn huurtoeslag-zoekopdrachten. Alle bedragen
  komen uit `data/fiscale-cijfers.json`, dus de bestaande checker bewaakt ze.

### CTR
- 50 meta descriptions ingekort naar 140–155 tekens. Boven de 160: nu 0.

### Techniek
- Alle 18 plaatspagina's misten één `</div>` in de hero. Stond al zo in git.
- Sitemap opgesplitst in diensten, kennisbank, lokaal en overig, met index.
- IndexNow ingericht (sleutelbestand + `scripts/indexnow.js`).

### Meten
- `scripts/gsc-export.js` en `scripts/gsc-report.js` (Node, geen npm-pakketten).
- **Let op bij het lezen van de cijfers:** vraag je de dimensie `query` op, dan laat
  Search Console zeldzame zoekopdrachten weg. Je ziet dan maar ~56% van de
  vertoningen en ~14% van de klikken. De KPI's komen daarom uit `data/gsc/totals.csv`,
  opgehaald zonder query-dimensie.
- Nulmeting in `data/baseline-2026-08.md`: 105 klikken, 30.511 vertoningen,
  CTR 0,34%, positie 30,5 over 2026-05-10 t/m 2026-08-07.

### Nieuwe scripts
`crawl-audit.js`, `gsc-export.js`, `gsc-report.js`, `build-sitemap.js`, `indexnow.js`.
