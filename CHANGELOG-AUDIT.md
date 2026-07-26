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
