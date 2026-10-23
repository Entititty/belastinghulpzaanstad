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

---

## 2026-10-20 — Feiten en vertrouwen (branch `feiten-en-vertrouwen-2026-10`)

Doel: feiten corrigeren, meer vertrouwen, meer aanvragen (bellen, WhatsApp,
terugbelformulier). Ontwerp, telefoonnummer, WhatsApp-links en het honeypot-veld
zijn gebleven. Niets verzonnen: onbekende gegevens staan als placeholder in
`data/bedrijf.json`; `node scripts/bouw.js` waarschuwt zolang ze leeg zijn.
Niet gepusht. Bronnen geraadpleegd op 20-10-2026.

### Fase 1 — Feitelijke correcties
| Wat | Waarom | Bron |
|---|---|---|
| Box 3: "bezwaar" wordt "Hulp bij uw Opgaaf werkelijk rendement"; zelf doen kan gratis; no cure no pay, tarief uit `FEE_BOX3` (nog leeg) | De site zei dat de Hoge Raad over 2021–2024 had geoordeeld en dat een (pro forma) bezwaar nodig was. Over 2021–2024 kan iedereen het werkelijk rendement opgeven, ook zonder bezwaar; de uitspraak van 25 juni 2026 gaat over 2017–2020 | belastingdienst.nl: Massaal bezwaar Plus, formulier Opgaaf werkelijk rendement, eisen bezwaar |
| Overdrachtsbelasting: 2% blijft; starters 18–35 jaar 0% tot €555.000 (was €525.000) | "In 2026 verlaagd voor kopers onder 35" klopte niet | belastingdienst.nl startersvrijstelling; SRA, januari 2026 |
| Rekenvoorbeeld met twee scenario's over saldo €11.390: €4.072 (35,75%) en €4.278 (37,56%), €339–€357 per maand; "€100 tot €400 per maand" wordt "afhankelijk van hypotheek en inkomen" | Het voorbeeld rekende met 37,56% en noemde dat de eerste schijf. De opdracht noemde 35,70%; de Belastingdienst hanteert 35,75% | belastingdienst.nl: tarieven voorlopige aanslag 2026, afbouw tarief aftrekposten |
| Stellige claims voorzichtiger: "veel mensen betalen te veel", "duizenden euro's", gemiddelde teruggaves (€800–€1.200, €1.600), "wij zien regelmatig…", "hundreds of euros per month" (EN-homepage) | Geen bron; de Belastingdienst publiceert geen gemiddelde teruggave. De €1.600 lijkt het oude gemiddelde van de middelingsregeling (afgeschaft per 2023). Een bedrijf uit 2026 kan geen eigen resultaten claimen | — (weggehaald) |
| Blogs op 2026-bedragen: ouderenkorting nulpunt €59.782 (was €59.783); huurtoeslagparameters; 1,28% is het fictieve rendement op spaargeld, niet de werkelijke rente; giften bij €45.000 tegen 37,56% (€169/€338) | Rekenfouten en verkeerde labels | belastingdienst.nl; volkshuisvestingnederland.nl (huurtoeslagparameters) |
| Engelse plaatspagina's: rekenblokken herbouwd (het forfait werd van het voordeel afgetrokken), statistieken gelijk aan NL (inwoners 2026, WOZ 2025, % koop/huur), inwonertallen in de tekst (Westzaan 5.131, niet 8.000), "Avg. monthly refund" weg | Onverifieerbare velden, eerder alleen op de NL-pagina's vervangen | CBS/AlleCijfers.nl (zie de ronde van juli hierboven) |
| Monumentenaftrek (Zaandijk, Koog aan de Zaan) weg | Per 1 januari 2019 afgeschaft, vervangen door een subsidie | belastingdienst.nl: aftrek onderhoudskosten monumentenpanden |
| Verlopen teksten: EN-banner "extension until 1 September 2026", EN-blogkaart "deadline 1 May 2026, €59", seizoensbanner "voorlopige teruggave vanaf €49" | Data verstreken; €49 is de prijs voor eerste baan | — |
| `llms.txt` gelijk met de site; Beconregeling weg | De site noemt geen Beconregeling en een Beconnummer is niet bevestigd | — |
| Verzuimboete €469 (max. €6.709) ongewijzigd, nu met "pas na herinnering en aanmaning" | Klopte al | `data/fiscale-cijfers.json` |

### Fase 2 — Eén bron voor prijzen en diensten
- `data/bedrijf.json` + `scripts/config-sync.js`: 309 prijsplekken (`data-prijs`), cfg-blokken
  en de JSON-LD (Offers, priceRange, LocalBusiness) komen uit één bestand. Gevonden:
  AggregateOffer correctie €69–€69 (moet €69–€99) en aangifte laten doen €59–€149 (moet €59–€89).
- Homepage: drie ingangen (senioren, koopwoning, correctie en box 3) plus "Meer diensten".
- Over ons in de ik-vorm (Stan van der Hoeven); de diensten zijn de zeven dienstpagina's.
  WOZ-bezwaar en kwijtschelding weg (geen pagina, geen prijs: open vraag).
- €20-korting: "nieuwe klanten in 2026, met of zonder review" (hing aan reviews).

### Fase 3 — Vertrouwen en aanvragen
- Footer uit de config: naam, vestigingsplaats, e-mail; KvK, btw/KOR en BAV zodra bekend.
- Blok "Waarom betalen als er gratis hulp is?" (BelastingTelefoon, balie, bibliotheek/IDO,
  wijkteam, ouderenbonden). Bron: rijksoverheid.nl en belastingdienst.nl (bellen).
- Correctiepagina: in 2026 kan 2021 nog worden teruggevraagd (5 jaar). Bron:
  belastingdienst.nl, "te laat voor bezwaar". Een exacte einddatum pas na bevestiging.
- `/beoordeling/` (noindex) en `docs/reviewverzoek.md`: reviewverzoek zonder selectie of
  tegenprestatie; de Google-knop verschijnt pas met `GOOGLE_REVIEW_URL`.
- Heroknoppen op dienst- en plaatspagina's: WhatsApp en bellen.

### Fase 4 — Techniek
- Eén LocalBusiness-blok uit de config op 98 pagina's (werkgebied 9 plaatsen,
  ma–vr 18–21, za–zo 9–21). FAQ-schema's op 36 pagina's gelijk met de zichtbare vragen;
  daarbij verdwenen onjuiste schema-antwoorden (Wlz/Wmo/tandarts aftrekbaar, 140%-norm).
- Nieuwe scripts: `check-jsonld.js`, `check-rekenvoorbeelden.js`, `bouw.js`.
- Canonicals en hreflang: 0 problemen. Plaatspagina's: eigen intro per plaats
  (ter controle door de eigenaar).

### Fase 5 — Toegankelijkheid
- 18px basis ook op mobiel; koppen op telefoons op hun oude maat.
- De kop paste niet op 375px: de menuknop viel buiten beeld. Nu logo op twee regels en
  een menuknop van 48×48, ook bij A++ en op 320px.
- Tikdoelen 48px (menu, NL/EN, footer, FAQ, formulier, belknoppen, A/A+/A++, cookieknoppen);
  het open menu heeft een dichte achtergrond en scrollt.
- Footerkoppen h2 (koppenvolgorde); rekendisclaimer 4,24:1 → 6,4:1; witte focusrand op
  donkere vlakken; links in lopende tekst onderstreept.
- 85 tabellen schuifbaar op telefoons (vielen buiten beeld); 36 grids krimpen op 320px.
- Engelse labels voor de contactbalk en de tekstgrootteknop.

### Lighthouse mobiel (lokaal, Edge headless)
| pagina | prestaties voor → na | toegankelijkheid | best practices | CLS |
|---|---|---|---|---|
| / | 56 → 84 | 99 → 100 | 100 → 96* | 0 → 0 |
| /tarieven/ | 95 → 97 | 98 → 100 | 100 → 96* | 0,004 → 0,062 |
| /over-ons/ | 97 → 97 | 98 → 100 | 100 → 96* | 0 → 0 |
| /senioren/ | 90 → 94 | 99 → 100 | 100 → 96* | 0,149 → 0,002 |
| /contact/ | 97 → 97 | 98 → 100 | 100 → 96* | 0,004 → 0,002 |
| /diensten/box-3-bezwaar/ | 97 → 90 | 98 → 100 | 100 → 96* | 0,003 → 0,001 |
| /diensten/voorlopige-teruggave/ | 96 → 89 | 95 → 100 | 100 → 96* | 0,003 → 0 |
| /diensten/correctie-late-aangifte/ | 97 → 97 | 98 → 100 | 100 → 96* | 0 → 0 |
| /zaandam/ | 97 → 90 | 98 → 100 | 100 → 96* | 0 → 0 |
| /blog/hypotheekrenteaftrek-berekenen/ | 97 → 97 | 98 → 100 | 100 → 96* | 0,005 → 0,001 |
| /en/ | 90 → 88 | 98 → 100 | 100 → 96* | 0 → 0 |

SEO 100 voor en na. \* Best practices: gtag.js van googletagmanager.com laadde tijdens
de na-meting niet (certificaatfout in het netwerk van de meetmachine); een herhaalde
meting van de oude stand op hetzelfde moment gaf ook 96. Prestaties schommelen tussen
runs: bij herhaalde metingen van beide versies kwam de LCP willekeurig op ~9,3 s door
hetzelfde mislukte verzoek. Een verschil in prestaties is met deze metingen niet aan te
tonen. De CLS op /tarieven/ komt door het wisselen van lettertype (Nunito Sans) bij de
grotere tekst en blijft onder de grens van 0,1.

### Open vragen (placeholders in `data/bedrijf.json`)
KVK_NUMMER, BTW_ID of KOR, BAV/BAV_EN, FEE_BOX3 (met minimum, maximum, grondslag en
betaalmoment), VAT_NOTE, GOOGLE_REVIEW_URL, ACHTERGROND_STAN en
EINDDATUM_CORRECTIE_2021. Verder: de €20-korting na 2026, WOZ-bezwaar en kwijtschelding
(nog genoemd op plaatspagina's en in blogs), een Beconnummer, en de mededelingen over
de KvK-inschrijving op `/privacy/` en in de algemene voorwaarden.

---

## 2026-10-21 — Antwoorden eigenaar, FAQ en rekentools (zelfde branch)

### Antwoorden van de eigenaar verwerkt
| Wat | Waarom | Bron |
|---|---|---|
| Box 3: 15% van de box 3-belasting die u terugkrijgt of minder betaalt, maximaal €500 voor alle jaren samen, geen minimum; u betaalt pas na de beslissing, bij een teruggave pas als het geld op uw rekening staat | Eigenaar: "doe wat het beste is". Geen minimum, zodat niemand meer betaalt dan hij terugkrijgt; een maximum voor grote teruggaves | `data/bedrijf.json` (FEE_BOX3, FEE_BOX3_MAX, FEE_BOX3_GRONDSLAG en een nieuwe Engelse grondslag) |
| Btw: "Alle prijzen zijn inclusief btw. Er komen geen kosten bij." op /tarieven/ | Eigenaar: inclusief | `VAT_NOTE`; KOR blijft open tot de KvK-inschrijving |
| Achtergrond Stan (NL in de ik-vorm, EN in de derde persoon): begonnen met aangiften inkomstenbelasting via zijn werk, plezier in uitzoeken en in het contact met mensen | Eigenaar vroeg om een algemene tekst; geen opleiding of jaren ervaring genoemd | `ACHTERGROND_STAN`, nieuw `ACHTERGROND_STAN_EN` |
| Correctie 2021: uiterste datum 31 december 2026; het verzoek moet dan binnen zijn | Een verzoek om ambtshalve vermindering moet binnen vijf jaar na het einde van het belastingjaar zijn ontvangen; de verzendtheorie geldt niet | belastingdienst.nl (te laat voor bezwaar); taxlive.nl (gemitigeerde verzendtheorie geldt niet bij ambtshalve vermindering) |
| WOZ-bezwaar en kwijtschelding geen dienst meer: weg uit de dienstenlijst (LocalBusiness op 98 pagina's), meta-descriptions van 9 plaatspagina's, "wij dienen kosteloos bezwaar in" (8 plaatspagina's), de CTA's van de WOZ- en kwijtscheldingsblogs (NL en EN), de toeslagen-FAQ en het privacybeleid | Eigenaar: geen dienst, geen mogelijkheid meer. De blogs blijven als uitleg om het zelf te doen | — |
| Startkorting blijft tot 31-12-2026 | Eigenaar | De build waarschuwt na die datum |
| KvK, btw-id, Becon, reviews | Nog niet; blijft leeg, niets op de site | — |

### FAQ
- 44 juiste vragen die eerder alleen in het schema stonden, zichtbaar teruggezet op 22 pagina's
  (o.a. AOW én pensioen bijbetalen, periodieke gift, aflossingsvrije hypotheek, huurtoeslag met
  tijdelijk contract, ouderenkorting terugvragen). Bijgewerkt waar nodig: huurtoeslag over 2026
  kan tot 1 september 2027, tarief hypotheekrente 35,75% of maximaal 37,56%.
- Niet teruggezet, omdat ze fout of onbewezen waren: aftrekbare zorgkosten "eigen bijdragen
  Wlz/Wmo, tandarts, brillen", de 140%-doelurennorm, "boete blijft vaak achterwege",
  kinderopvangtoeslag €225 bij €55.000, gemiddelde teruggave €1.600, kwijtschelding-vermogensgrens.
- Het FAQ-schema volgt nu op alle 86 pagina's de zichtbare antwoorden (op 16 pagina's week het
  antwoord af; faq-audit vergeleek alleen de vragen). faq-sync zet geen spatie meer voor leestekens
  na een prijs in een span ("€89 ." werd "€89.").
- Fouten in zichtbare antwoorden en checklists hersteld: "eigen bijdragen" en tandarts als aftrekbare
  zorgkosten (pensioenblog en seniorenchecklist, NL en EN); "uitstel aanvragen tot 1 september"
  (aanvragen moet vóór 1 mei); belastingrente "6,5% in 2026" op twee Engelse blogs (is 5%);
  AOW-tarief "19% tot ca. €40.500" (is 17,85% tot €38.883, NL en EN); "veel senioren in Zaanstad
  kiezen hiervoor"; accountantsprijzen "€150–€300" zonder bron.
- Het box 3-tarief staat via een cfg-blok in het FAQ-antwoord "Wat kost het mij?" (NL en EN) en in de
  tarieventabel; config-sync werkt dan ook het FAQ-schema bij.
- Bron belastingrente: `data/fiscale-cijfers.json` (5% vanaf 1 januari 2026); de Engelse
  schrijfwijzen van 6,5% staan nu in "verouderd", zodat de check ze tegenhoudt.

### Rekentools (fase 6)
- Nieuw: `/rekentools/` (overzicht), `/rekentools/voorlopige-teruggave/` en `/rekentools/ouderenkorting/`.
  De huurtoeslagtool is de bestaande op `/blog/huurtoeslag-berekenen/`.
- `js/rekenhulp.js` rekent met `data/fiscale-cijfers.json` (nieuwe sleutel `box1_schijf1_grens`
  €38.883), dus de tools volgen de jaarlijkse update vanzelf. Getest: €339–€357 per maand bij
  €340.000 tegen 3,7% (gelijk aan het rekenvoorbeeld), ouderenkorting €2.067 / €1.467 bij
  €50.000 / €0 bij €60.000, plus €540 alleenstaand.
- Leadformulier "Gratis laten narekenen" onder elke tool, ook onder de twee bestaande rekentools op
  de blogs: naam, telefoon, e-mail (niet verplicht), toestemming. De invoer en de uitkomst gaan
  automatisch mee in een verborgen veld, zodat Stan bij het terugbellen weet waar het over gaat.
  De uitkomst zelf is zonder formulier te zien: een tool die pas na het invullen van gegevens iets
  laat zien, botst met "vrije toestemming" uit de AVG en kost vertrouwen.
- Privacybeleid (NL en EN): de berekening gebeurt op het eigen apparaat; pas bij versturen gaan
  gegevens en uitkomst via Formspree naar ons.
- Vindbaar via de footer (alle NL-pagina's), "Meer diensten" op de homepage, /senioren/, de
  dienstpagina voorlopige teruggave, de ouderenkortingblog en `llms.txt`.
- Formulierstijl staat nu in de gedeelde stylesheet; een open FAQ-antwoord was afgekapt op 300 px.

### Lighthouse mobiel, nieuwe pagina's
Toegankelijkheid 100 en SEO 100 op `/rekentools/`, beide tools, `/blog/huurtoeslag-berekenen/`
(oranje disclaimerlink gerepareerd: contrast 4,48:1) en `/blog/hypotheekrenteaftrek-berekenen/`.
Prestaties schommelden op deze meetmachine (ook ongewijzigde pagina's zakten); met en zonder de
nieuwe scripts was de blokkeertijd gelijk.

---

## 2026-10-21 (2) — Over ons en technische SEO

### Over ons
- Achtergrond van Stan: acht jaar aangiften inkomstenbelasting, meer dan honderd gedaan (bron: de
  eigenaar). Op /over-ons/, /en/about-us/, de homepage, in het Person-schema en in `llms.txt`.
- Beroepsaansprakelijkheidsverzekering weg (placeholders, waarschuwing, footer, TODO's), op verzoek.
- Engelse belofte "niet tevreden, geen factuur" vervangen door de afspraak uit de algemene voorwaarden.

### Technische SEO
| Wat | Waarom |
|---|---|
| `image` (ImageObject, de og-afbeelding) in het Article-schema van alle 50 artikelen | Google raadt een afbeelding aan voor artikelen in de zoekresultaten; die ontbrak overal |
| `Offer` op de Engelse box 3- en erfbelastingpagina, gelijk aan de Nederlandse | Schema-gat uit crawl-audit |
| Meta descriptions van 11 pagina's aangevuld (9 plaatspagina's, tips, zorgkosten) | Onder 120 tekens; plaatspagina's noemen nu ook de voorlopige teruggave. De zorgkosten-description noemt geen losse posten meer |
| Links naar de rekentools vanaf 9 plaatspagina's (bij het rekenvoorbeeld) en 4 blogs | De tools hadden 2 en 3 interne links; nu geen enkele pagina meer onder de 5 |
| Rekentools-overzicht aangevuld met uitleg | Dunne pagina (254 woorden) |
| Eigen 404-pagina (`/404/index.html`, noindex) en `error_page 404` in het nginx-server-blok | nginx toonde een kale foutpagina; bezoekers en verloren links komen nu op een pagina met navigatie, telefoon en WhatsApp. Server-blok handmatig uitrollen, zie DEPLOY.md §4b |
| Ook het tekstlettertype (Nunito Sans, 31 KB) vooraf laden | Het wisselen van lettertype gaf op /tarieven/ een verschuiving van 0,062; nu 0 |

Gecontroleerd en in orde: canonical en og:url op elke indexeerbare pagina, og-afbeeldingen bestaan,
hreflang met x-default, robots.txt met sitemap, sitemap zonder noindex-pagina's, 301's voor de drie
samengevoegde pagina's in nginx, één h1 per pagina, titles en descriptions binnen de grenzen,
alt-tekst en afmetingen bij alle afbeeldingen, geen http-bronnen, html lang klopt.

Lighthouse: toegankelijkheid, best practices (met gtag geblokkeerd) en SEO 100 op de gemeten pagina's.
De prestatiescore is op deze meetmachine onbetrouwbaar: de werkelijk gemeten LCP is 0,2-0,7 s, maar de
simulatie geeft willekeurig een vaste 9,3 s, ook bij de oude versie van de site. Na de uitrol geeft
PageSpeed Insights de echte cijfers.

---

## 2026-10-22 — Meer klikken uit Google (branch `ctr-snippets-2026-10`)

Aanleiding: de site wordt veel vertoond maar weinig aangeklikt. Uit Search Console bleek dat het
meeste verkeer op pagina 2 tot 4 staat, waar bijna niemand klikt, en dat een deel van de vertoningen
over diensten gaat die wij niet leveren (taxatie, bewindvoering, schuldhulp). De cijfers zelf staan
lokaal in `docs/ctr-analyse-2026-10.md`, niet in git.

### Zoekopdrachten waar we al op pagina 1 stonden zonder klikken
| Pagina | Wat er veranderd is |
|---|---|
| `/blog/kwijtschelding-gemeentelijke-belasting/` | Titel en kop op "gemeentelijke belastingen Zaanstad"; blok "Zoekt u de gemeente zelf?" met Mijn Zaanstad en 14 075 |
| `/blog/zorgtoeslag-aanvragen/` | Titel, kop en een eigen sectie over 18 worden (ingangsdatum, eerst de verzekering, één keer aanvragen), plus FAQ |
| `/blog/belastingaangifte-voor-1-april/` | Naar het seizoen 2026 (aangifte van 1 maart tot 1 mei 2027); de snippet noemde nog de deadline van mei 2026 |
| Homepage | Titel en omschrijving op "belastinghulp Zaandam"; FAQ "Zijn jullie de Belastingdienst?" met de BelastingTelefoon |
| `/blog/belastingteruggave/` | FAQ "Waarom krijg ik geen belasting terug?" |
| `/blog/zorgtoeslag-grens/` | Titel op "maximaal inkomen zorgtoeslag"; FAQ "Hoe zet ik mijn zorgtoeslag stop?" (route volgens belastingdienst.nl) |
| `/en/blog/elderly-tax-credit/` | "single elderly person's tax credit" in titel en omschrijving |

### Titels en omschrijvingen
Ongeveer 75 pagina's kregen een nieuwe titel en/of omschrijving: zoekwoord vooraan, een concrete
belofte (bedrag, rekentool, "wat mag wel en niet"), geen " | Belastinghulp Zaanstad" achter
blogtitels (Google toont de sitenaam al boven het resultaat). og:title en og:description lopen mee,
dus delen via WhatsApp toont dezelfde tekst. De titels van de negen Nederlandse plaatspagina's zijn
bewust niet aangeraakt: daar loopt de meting van 30 augustus (beslismoment 1 juni 2027).

### Feiten rechtgezet
- **Verzonnen gemiddelden weg**, Nederlands en Engels: "senioren laten gemiddeld €350–€700 liggen",
  "gepensioneerden krijgen gemiddeld €400–€1.200 terug", "de gemiddelde huurder loopt €3.000–€5.000
  mis", "€300–€1.500 extra", "average €800–€1,200", "seniors leave €600 on the table", "correctie duurt
  gemiddeld 8–12 weken", "tot €1.500 extra" in og-titels.
- **Kwijtschelding Zaanstad** volgens zaanstad.nl: alleen afvalstoffen- en rioolheffing, inkomen op
  bijstandsniveau, auto tot €3.350, aanvragen binnen 3 maanden na de aanslag, waterschap apart bij het
  HHNK. Weg: de inkomens- en spaargrenzen zonder bron, "OZB voor huurders" (huurders betalen geen OZB),
  de belofte "wij helpen u kosteloos met de aanvraag" (geen dienst meer).
- **Huurtoeslag**: de tabel "maximum toetsingsinkomen ± €31.750 …" stond in geen enkele bron; de
  toeslag bouwt af en het nulpunt hangt af van huur en huishouden. Terugwerkende kracht nu over 2026
  (tot 1 september 2027). Dubbele FAQ vervangen door "met terugwerkende kracht". EN: "income limit
  €32,975" weg.
- **Zorgtoeslag**: "met terugwerkende kracht tot 3 jaar terug" was fout; het is tot 1 september van het
  jaar erna.
- **Giften**: omschrijving noemde een drempel van €67; het is 1% van het drempelinkomen, minimaal €60
  (zoals het artikel al zei).
- **Einddatum 2026**: "nog maar enkele weken" weg (aangifte kan pas vanaf 1 maart 2027), "donderdag
  1 mei 2027" was fout (zaterdag; weekdag weggelaten), F-formulier volgt gewoon 1 mei (de "8 maanden"
  is de termijn van de erfbelasting), C-formulierregel weg (niet te bevestigen).
- **Aangiftegids**: deadline naar de aangifte over 2026.

### Samengevoegd (vangnetpagina + 301 in beide nginx-configs)
- `/blog/uitstel-belastingaangifte-2025/` → `/blog/uitstel-belastingaangifte-aanvragen/`
- `/en/blog/tax-return-deadline-2025/` en `/en/blog/tax-return-extension-2025/` → `/en/blog/late-tax-return/`

Alle interne links omgezet, hreflang van de NL-deadlinepagina naar de EN-2025-pagina verwijderd. De
301's werken pas na het uitrollen van het server-blok (DEPLOY.md §4b); tot die tijd stuurt de
meta-refresh bezoekers en Google door.

### Overig
- u-vorm in elf artikelkoppen en alles wat ze overneemt ("Lees ook", kaarten, kruimelpad, schema). Het
  citaat van de Belastingdienst op /diensten/eerste-baan/ blijft letterlijk.
- `favicon.png`: 2048×2048 en 1,4 MB, met veel witruimte en het watermerk van de AI-generator; nu het
  beeldmerk bijgesneden op 192×192, 8 KB. Het origineel staat niet meer in de repo; bewaar het zelf als
  u het nodig heeft (drukwerk, Google-bedrijfsprofiel).
- robots-meta (max-image-preview:large) ook op de drie rekentoolpagina's; WebSite-schema met de
  homepage-URL inclusief slash, gelijk aan de canonical.
- `.gitattributes`: alles LF, ook op Windows. Na de merge op Windows had de werkmap gemengde
  regeleindes, waardoor `bouw.js --check` op elke pagina faalde.

---

## 2026-10-23 — SEO en CTR volgens de takenlijst van de eigenaar (branch `seo-verbeteringen`)

Dertien taken, elk in een eigen commit. Uitgangspunt: het bedrijf heeft nog geen klanten en nog geen
KvK-nummer; /tarieven/ (dus `data/bedrijf.json`) is de bron voor alle prijzen.

### Inhoud
- **Geen klantclaims**: label "Populairst" en "Most popular"/"Most chosen" weg (de kaart blijft
  uitgelicht), "Gemiddelde doorlooptijd" → "1 week, doorgaans geregeld", "Veel klanten komen jaarlijks
  terug" weg, "helpen wij met name senioren"/"we mainly help"/"we see many seniors" neutraal, "Vragen
  die wij vaak krijgen" → "Vragen en antwoorden", "op bezoek bij een klant" → "op een afspraak",
  "Most searched in Zaanstad" en een gemiddelde teruggave zonder bron weg. De vergelijking met een
  genoemde concurrent op de aangiftepagina is ook weg.
- **Box 3-dienstpagina** op "werkelijk rendement opgeven", met "bezwaar" als tweede zoekterm (title
  "Box 3 bezwaar of werkelijk rendement? Gratis check"). Procedure nagekeken op belastingdienst.nl.
- **Hoofdzoekwoord**: homepage op "Belastinghulp Zaanstad" (was "Zaandam en Zaanstad"); H2 op de
  aangiftepagina "in Zaanstad". Zaandam hoort bij /zaandam/.
- **Deadline-artikelen samengevoegd** op `/blog/einddatum-belastingaangifte-2026/` (title
  "Belastingaangifte 2026: deadline 1 mei 2027 (+ uitstel)"); `/blog/belastingaangifte-voor-1-april/`
  is een vangnet met een 301 in beide nginx-configs. Rechtgezet: bericht vóór 1 juli is een belofte
  van de Belastingdienst, geen garantie; de boete volgt na herinnering en aanmaning; belastingrente
  5% (2026) vanaf 1 juli als u na 1 mei aangifte doet en moet bijbetalen.
- **Ouderenkorting**: title "Ouderenkorting 2026: €2.067 + €540 alleenstaand | rekentool".
- **Senioren**: H1 "Belastingaangifte voor senioren, bij u thuis", de oude H1 als subkop; de twee
  prijsvragen in het FAQ samengevoegd.
- **Plaatspagina's** (9): omschrijving met "incl. btw" en "ook ’s avonds en in het weekend".

### Techniek
- **Blogoverzicht**: dubbele kaart weg; `scripts/blog-kaarten-sync.js` zet kaarttitels op /blog/ en
  /en/blog/ én de artikellinks in llms.txt gelijk aan de paginatitel (draait mee in `bouw.js`).
- **Sitemap**: lastmod uit "Laatst bijgewerkt" op de pagina, anders de laatste commit; XML-controle
  na het bouwen. Live gecontroleerd: alle sitemaps geven 200 met text/xml.
- **JSON-LD**: bedrijfsblok ProfessionalService + AccountingService, adres zonder straat en regio,
  sameAs met LinkedIn; provider op dienstpagina's verwijst naar het bedrijfsblok; tweede Offer voor
  het box 3-tarief; Engelse auteur dezelfde Person als de Nederlandse. `check-jsonld.js` eist nu
  BreadcrumbList, bedrijfsblok, Person-auteur, Service met Offer, geen Review/AggregateRating, en
  alleen bestaande schema.org-typen.
- **Hreflang** klopte; de taalknop niet (8 Engelse artikelen wezen met "NL" naar zichzelf, 6
  dienstpagina's met "EN" naar /en/). `check-hreflang.js` controleert nu ook x-default en de knop.
- **KvK**: footer in de vorm "KvK: … · btw: …", alleen als ingevuld; identifier en vatID in de
  JSON-LD. Getest met tijdelijke nummers.
- **btw-vangnet**: config-sync faalt op "incl. btw" in de tekst zodra KOR true wordt.
- **llms.txt** bij; de Engelse pagina's verwezen naar `/en/llms.txt` (bestaat niet), nu `/llms.txt`.
- Nieuw: `scripts/meta-audit.js` (title, meta en H1 per pagina, met markeringen).
