# Audit — belastinghulpzaanstad.nl

**Datum:** 2026-07-23 · **Auditor:** senior web performance & SEO engineer
**Scope:** snelheid / Core Web Vitals · klassieke SEO · GEO (AI-vindbaarheid)

---

## 0. Gecorrigeerde aanname & scope

| In opdracht opgegeven | Werkelijkheid (uit code) |
|---|---|
| Stack: **Next.js** | **Statische HTML** (geen framework, geen build). De Next.js-map in je omgeving is `functioneelbeheer247.nl` (AFAS-site) — een **andere** website. |
| Repo: "deze map" | Geauditeerd: `Desktop\Website belasting` (de statische site achter de Live URL). |

**Site in cijfers:** 78 HTML-pagina's · NL + EN · geen content-afbeeldingen (alleen favicon) · CSS 29,6 KB (geminified) · homepage 97 KB HTML · gedeeld template met veel inline styles.

### Wat ik NIET vanuit code kan vaststellen (meet dit zelf)
Deze punten vereisen de líve site; ik verzin er geen cijfers bij:
- **Echte Core Web Vitals** (LCP/CLS/INP-waarden) → meet met [PageSpeed Insights](https://pagespeed.web.dev/) en Chrome DevTools (Lighthouse), mobiel én desktop.
- **HTTP-headers**: gzip/brotli-compressie, `Cache-Control`, `HSTS`, CDN → check met `curl -I https://belastinghulpzaanstad.nl` of [securityheaders.com](https://securityheaders.com). De nginx-config in `server-setup/` regelt dit, maar of die **live actief** is kan ik niet zien.
- **Redirects & statuscodes**: www→non-www, http→https, redirect chains, 404's → check met [httpstatus.io](https://httpstatus.io) of Screaming Frog.
- **Rankings / posities / CTR** → Google Search Console.

---

## ⭐ Top 10 quick wins (hoge impact, lage effort)

| # | Actie | Impact | Effort | Bestand(en) |
|---|---|---|---|---|
| 1 | **Live server-headers verifiëren/aanzetten** (gzip/brotli, `Cache-Control`, `HSTS`) — nginx-config staat klaar | Hoog | Laag* | `server-setup/nginx-*.conf` |
| 2 | **UTF-8 mojibake fixen** (`â‚¬`→`€`, `Ã©`→`é`) in 9 stadspagina's — raakt zichtbare tekst **én** JSON-LD `priceRange`/`description` | Midden-hoog | Laag | `zaandam/`, `krommenie/`, … (9×) |
| 3 | **llms.txt bijwerken** — mist de 9 nieuwe artikelen, beide rekentools en de EN-pagina's | Midden | Laag | `llms.txt` |
| 4 | **`Sitemap: …/llms.txt` verwijderen** uit robots.txt (llms.txt is geen XML-sitemap) | Laag | Triviaal | `robots.txt:80` |
| 5 | **`datePublished` toevoegen** aan Article-schema (nu slechts 10/40 blogs) | Midden | Laag-mid | `blog/*/index.html` |
| 6 | **WebSite- + Organization-schema (met logo)** op de homepage toevoegen | Midden | Laag | `index.html` |
| 7 | **Interne links naar `/diensten/…`** — nu maar 5 (bijna wees, én conversiepagina) | Midden | Laag | blog- & stadspagina's |
| 8 | **`priceRange` gelijktrekken** (nu 3 waarden: €59-€109 / €0-€149 / €59) | Midden | Laag | stadspagina's, `index.html`, `llms.txt` |
| 9 | **Third-party scripts auditen** — 3 trackers (Clarity + GA4 + Meta Pixel) op elke pagina | Midden | Laag | alle `*.html` |
| 10 | **Google Fonts self-hosten** (render-blocking externe request = LCP-risico) | Hoog | Midden | template head |

\* Effort laag in code; vereist wel serververandering die jij moet toepassen/goedkeuren.

---

## 1. Snelheid / Core Web Vitals

| Punt | Status | Bewijs | Impact |
|---|---|---|---|
| **Content-afbeeldingen** | ✅ OK | Alleen `favicon.svg/png`; geen `<img>` in content | Positief: geen image-LCP, geen CLS door media, geen srcset/lazy-load nodig |
| **Google Fonts** | ⚠️ Probleem | `<link href="fonts.googleapis.com/css2?...Source Serif 4 + Nunito Sans...&display=swap" rel="stylesheet">` op elke pagina | **Render-blocking externe request** → vertraagt LCP (tekst-LCP wacht op font). `display=swap` ✅ en `preconnect` ✅ aanwezig, maar niet self-hosted. Veel gewichten (Serif 400/600/700 + Sans 400/500/600/700/800). Ook AVG: Google Fonts zet een externe call. |
| **CSS** | ✅ OK (te optimaliseren) | `belasting.min.css` 29,6 KB, render-blocking `<link rel="stylesheet">` (lokaal) | Acceptabel. Optioneel: kritieke CSS inlinen voor snellere first paint. Geen "print-trick" meer → geen CLS-hack. |
| **Third-party JS** | ⚠️ Probleem | Microsoft Clarity + GA4 (`G-KCQDYVY2M6`) + Meta Pixel (`connect.facebook.net`) op élke pagina | Op een verder JS-loze site zijn dit de belangrijkste main-thread- en requestkosten. Meta Pixel is alleen nodig bij Facebook-adverteren. `uitstel-belastingaangifte-2025` mist één Clarity-referentie (inconsistent). |
| **LCP** | ❓ Onbekend (meet) | Geen image; LCP-element is vermoedelijk de H1/hero-tekst | Grootste hefboom = de web-font (zie boven). Meet met PSI. |
| **CLS** | ✅ Waarschijnlijk laag (meet) | Geen media zonder dimensies; `display=swap` geeft hooguit lichte FOUT | Meet met PSI. |
| **INP** | ✅ Waarschijnlijk laag (meet) | Alleen lichte handlers (`toggleFaq`, `toggleMenu`, carousel, rekentools) | Prima. |
| **Compressie / caching / HSTS / CDN** | ❓ Onbekend (meet) | `server-setup/nginx-belastinghulpzaanstad.conf` bevat gzip + HSTS + www-redirect | Config klaar; **live status onbekend**. Verifieer headers. |
| **Homepage-HTML-grootte** | ⚠️ Klein probleem | `index.html` = 97 KB (veel inline styles + inline JSON-LD) | Gzip mitigeert grotendeels; lage prioriteit. |

---

## 2. Technische SEO

| Punt | Status | Bewijs | Impact |
|---|---|---|---|
| **robots.txt** | ✅ Sterk (1 fout) | Alle grote AI-bots expliciet `Allow` + XML-sitemap vermeld | Uitstekend. **Fout:** regel 80 `Sitemap: …/llms.txt` — llms.txt is geen sitemap; verwijder die regel. |
| **XML-sitemap** | ✅ OK (verifieer) | 77 `<loc>` (32× `/en/`), bevat over-ons/diensten/calculators | ~compleet (77 vs 78 pagina's; verschil is vermoedelijk de `noindex` einddatum-2025). Verifieer dat niets belangrijks ontbreekt. |
| **Canonicals** | ✅ OK | Self-referencing canonical op elke pagina | Goed. |
| **hreflang / x-default** | ✅ OK | NL-pagina's: `nl` + `x-default`; EN: `en` + `nl` + `x-default` | Correcte tweetalige opzet. |
| **Trailing slashes** | ✅ OK | Consistent `/blog/x/` in URL's + canonicals | Goed. |
| **noindex** | ⚠️ Verifieer | `einddatum-belastingaangifte-2025` staat op `noindex` | Waarschijnlijk bewust (opgevolgd door `-2026`). Bevestig dat er geen andere pagina per ongeluk `noindex` is. |
| **Redirects / www / http→https / 404's** | ❓ Onbekend (meet) | Alleen in nginx-config zichtbaar | Verifieer live (redirect chains, www-consistentie). |
| **Server-side rendering** | ✅ Sterk | Statische HTML | Perfect voor crawlers én AI. |

---

## 3. On-page SEO

| Punt | Status | Bewijs | Impact |
|---|---|---|---|
| **H1** | ✅ OK | **Exact 1 `<h1>` per pagina** (alle 78) | Voorbeeldig. |
| **Titles / meta descriptions** | ✅ OK | Uniek per pagina, met cijfers/hooks (deze sessie aangescherpt) | Goed. |
| **Koppenstructuur** | ✅ OK | Veel H2's als natuurlijke vraag | Goed voor SEO + GEO. |
| **Interne links** | ⚠️ Probleem (deels) | `over-ons` gelinkt vanuit 44 bestanden; **`/diensten/…` slechts 5** | De diensten-/conversiepagina is bijna een wees. Voeg contextuele links toe vanuit relevante blogs/stadspagina's. |
| **Breadcrumbs** | ✅ OK | Visueel + `BreadcrumbList` JSON-LD | Goed. |
| **Alt-teksten** | ✅ n.v.t. | Geen content-afbeeldingen | — |
| **Gestructureerde data** | ✅ Zeer sterk (2 gaten) | Speakable, BreadcrumbList, LocalBusiness (+geo/openingstijden), ProfessionalService, FAQPage, Article | Rijk. **Gaten:** (a) geen `WebSite`- en losstaand `Organization`-schema (met `logo`); (b) `Article` mist `datePublished` op ~30 blogs. |

---

## 4. GEO (AI-vindbaarheid)

| Punt | Status | Bewijs | Impact |
|---|---|---|---|
| **Server-side content** | ✅ Sterk | Statische HTML — AI-crawlers voeren nauwelijks JS uit | Grote plus. |
| **AI-bots in robots.txt** | ✅ Sterk | GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot, Applebot-Extended, meta-externalagent… allemaal `Allow` | Voorbeeldig. |
| **llms.txt** | ⚠️ Aanwezig maar verouderd | Bevat samenvatting, FAQ, prijzen, pagina-/bloglijst — maar **mist** de 9 nieuwe artikelen, beide rekentools en de EN-sectie | Actualiseer; dit is je directe "briefing" voor AI-modellen. |
| **Antwoord-eerst** | ✅ Grotendeels | Veel pagina's openen met featured-snippet-box / direct antwoord | Trek dit door naar álle blogs. |
| **Citeerbare cijfers/tabellen** | ✅ Sterk | Veel concrete bedragen, tabellen, stappenlijsten | Goed citeerbaar. |
| **Entiteitsduidelijkheid** | ⚠️ Inconsistent | Naam/wat/voor wie/waar staan in tekst + schema | **Maar:** `priceRange` verschilt (stad €59-€109, home €0-€149, llms €59) en de NAP is niet overal gelijk. Consistente entiteit = betere AI-attributie. |
| **UTF-8 in structured data** | ⚠️ Bug | `â‚¬`/`Ã©`-mojibake in 9 stadspagina's, óók in JSON-LD (`priceRange`, `description`) | Kapotte valuta/tekens in structured data schaadt zowel AI-parsing als weergave. |
| **E-E-A-T** | ⚠️ Kan sterker | Auteur = Organisatie (geen genoemd persoon met bio); "Bijgewerkt"-datum + `dateModified` zichtbaar; calculators hebben bronvermelding | Overweeg een **genoemde expert-auteur met bio**; voeg `datePublished` toe; citeer vaker externe autoriteiten (Belastingdienst/Rijksoverheid) in blogtekst. |
| **FAQPage-schema** | ✅ Sterk | Op homepage, stadspagina's, diensten, veel blogs | Goed. |
| **Vage marketingtaal** | ✅ Grotendeels feitelijk | Concrete claims/bedragen | Prima. |

---

## 5. Volledige bevindingenlijst (geprioriteerd)

| Prio | Bevinding | Impact | Effort | Bestand(en) |
|---|---|---|---|---|
| P1 | Live server-headers (gzip/brotli, Cache-Control, HSTS) verifiëren/aanzetten | Hoog | Laag* | `server-setup/nginx-*.conf` (server) |
| P1 | Google Fonts self-hosten + gewichten beperken + primaire font preloaden | Hoog | Midden | template `<head>` (alle pagina's) |
| P1 | UTF-8 mojibake (`â‚¬`,`Ã©`) fixen in 9 stadspagina's (tekst + JSON-LD) | Midden-hoog | Laag | 9× `*/index.html` |
| P2 | llms.txt actualiseren (9 artikelen, 2 rekentools, EN-sectie) | Midden | Laag | `llms.txt` |
| P2 | `datePublished` toevoegen aan Article-schema | Midden | Laag-mid | `blog/*/index.html` (~30) |
| P2 | WebSite- + Organization-schema (met `logo`) op homepage | Midden | Laag | `index.html` |
| P2 | Interne links naar `/diensten/belastingaangifte-laten-doen/` uitbreiden | Midden | Laag | blogs/stadspagina's |
| **P1** | **Consent/privacy: trackers laden zonder toestemming (geen CMP), dode Privacybeleid-link, geen privacypagina** — zie §8 | Hoog (AVG) | Midden | alle `*.html`, footer |
| **P1** | **Genoemde expert-auteur + bio + `Person`-schema als `author`** (YMYL) — zie §9 | Hoog (E-E-A-T) | Midden (content) | blogs, `over-ons` |
| **P1** | **Stadspagina-overlap wegwerken** (doorway-risico) — zie §7 | Hoog | Midden (content) | 9× stadspagina's |
| P2 | `priceRange`/NAP gelijktrekken — **of verwijderen als het niet met de zichtbare pagina overeenkomt** | Midden | Laag | stadspagina's, `index.html`, `llms.txt` |
| P2 | Third-party scripts auditen (Meta Pixel nodig? defer/verwijderen) — hangt samen met P1-consent | Midden | Laag | alle `*.html` |
| P3 | `Sitemap: …/llms.txt` uit robots.txt halen | Laag | Triviaal | `robots.txt:80` |
| P3 | Live redirects/statuscodes verifiëren (www, http→https, 404, chains) | Midden | Laag* | server |
| P3 | Sitemap-volledigheid bevestigen (77 vs 78) + `einddatum-2025` noindex bevestigen | Laag | Laag | `sitemap.xml` |
| P3 | Dode footer-link "Privacybeleid" (`href="#"`) fixen | Laag | Triviaal | alle `*.html` |
| P4 | Homepage-HTML verkleinen (inline styles → CSS-klassen) | Laag | Midden | `index.html` |
| P4 | Clarity-inconsistentie op `uitstel-belastingaangifte-2025` | Laag | Triviaal | 1 bestand |
| P4 | Kritieke CSS inlinen voor snellere first paint | Laag | Midden | template |

\* = codewijziging klein, maar toepassing vereist server-toegang/akkoord.

---

## 6. Voorgestelde uitvoervolgorde (Fase 4, na jouw go)

1. **Correctheid/bugs eerst:** mojibake (P1), robots.txt-sitemapregel (P3), datePublished (P2).
2. **GEO/entiteit:** llms.txt (P2), WebSite/Organization-schema (P2), priceRange/NAP gelijktrekken (P2).
3. **Interne links** naar diensten (P2).
4. **Performance:** fonts self-hosten (P1), third-party audit (P2).
5. **Server (jij/akkoord):** headers + redirects verifiëren (P1/P3).
6. **Content-voorstellen** (E-E-A-T) — ik lever tekstvoorstellen, schrijf niets ongevraagd om.

### Werkwijze bij go
- Aparte branch `seo-performance-audit`.
- Eén logische wijziging per commit.
- Ontwerp/merkstem blijven ongemoeid, tenzij expliciet akkoord.
- `CHANGELOG-AUDIT.md` bijhouden (wat + waarom, met voor/na waar meetbaar: bundle/requests).
- Contentwijzigingen als voorstel, niet als fait accompli.

---

## 7. Extra onderzoek — tekstoverlap stadspagina's (doorway-risico)

**Methode:** per pagina de `<body>`-tekst gestript (scripts/styles/tags verwijderd), stadsnamen + "Zaanstad" genormaliseerd naar `STAD`, zinnen ≥40 tekens vergeleken tussen alle 9 pagina's. "% uniek" = zinnen die alléén op die pagina voorkomen.

| Stadspagina | zinnen | uniek | **% uniek** | gedeeld |
|---|---|---|---|---|
| **zaandam** | 74 | 13 | **18%** | 61 |
| **assendelft** | 74 | 13 | **18%** | 61 |
| **krommenie** | 74 | 16 | **22%** | 58 |
| **zaandijk** | 71 | 18 | **25%** | 53 |
| wormerveer | 70 | 28 | 40% | 42 |
| koog-aan-de-zaan | 66 | 32 | 48% | 34 |
| wormerland | 50 | 24 | 48% | 26 |
| oostzaan | 63 | 30 | 48% | 33 |
| westzaan | 61 | 30 | 49% | 31 |

- **20 zinnen zijn letterlijk identiek op álle 9 pagina's** (na normalisatie van de stadsnaam): o.a. het complete "voor woningbezitters"-blok, het rekenvoorbeeld + disclaimer, de "bel/WhatsApp/mail — dezelfde dag"-CTA, "u ontvangt uw teruggave… zelfs maandelijks". Van de 276 zin-typen komen er 72 op ≥2 pagina's voor.
- **Oordeel:** **doorway-/thin-content-risico**, geconcentreerd bij de 4 grote kernen (zaandam, assendelft, krommenie, zaandijk: 75-82% boilerplate) die allemaal naar dezelfde WhatsApp/contact funnelen. De 5 kleinere kernen (40-49% uniek) zijn grensacceptabel maar mogen sterker.

### Prioriteit van uniek maken
1. **Eerst (hoog risico):** zaandam, assendelft, krommenie, zaandijk → naar ≥50% unieke bodytekst.
2. **Daarna (optioneel):** wormerveer, koog, wormerland, oostzaan, westzaan → 1-2 extra lokale haakjes.

### Concrete lokale contentideeën (3-5 per prioriteitspagina — voorstel, geen fabricage)
> Waar een cijfer nodig is, staat **[verifiëren]** — die lever jij aan of ik zoek een bron op; ik verzin niets.

**Zaandam** (grootste kern, relatief veel huur/appartementen)
1. Wijken expliciet benoemen ("aan huis van Poelenburg tot Westerkoog; Peldersveld, Rosmolenwijk, Kogerveld, Zaandam-Zuid") — echte lokale entiteiten.
2. Huurdershoek: relatief veel sociale huur → **huurtoeslag**-insteek + link naar de huurtoeslag-rekentool.
3. Gemiddelde WOZ-waarde Zaandam **[verifiëren]** en wat dat betekent voor eigenwoningforfait/voorlopige teruggave.
4. Station Zaandam / veel forenzen → korte alinea over aftrekbare posten voor werkenden.
5. Gemeentelijke aanslag (Cocensus) → kwijtschelding-insteek voor lage inkomens.

**Assendelft** (veel nieuwbouw: Saendelft, koopwoningen, jonge gezinnen)
1. Wijk **Saendelft** benoemen → starters met hypotheek → hypotheekrenteaftrek/voorlopige teruggave.
2. Jonge gezinnen → **kindgebonden budget / kinderopvangtoeslag**-insteek + links.
3. Onderscheid oud-Assendelft (landelijk) vs nieuwbouw → verschillende doelgroepen.
4. Gemiddelde woningprijs Saendelft **[verifiëren]** → EWF-voorbeeld met dat getal.
5. Praktisch: aan huis in de nieuwbouwwijken.

**Krommenie** (mix koop/huur, vergrijzing)
1. Vergrijzing → **ouderenkorting / AOW-aangifte**-insteek voor senioren + link.
2. Concrete wijken/buurten **[verifiëren welke]**.
3. Oudere koopwoningen → **WOZ-bezwaar**-insteek + link naar woz-bezwaar-zaanstad.
4. Lokaal woningcijfer **[verifiëren]**.
5. Industrieel/forensen-verleden als korte couleur locale.

**Zaandijk** (klein, historisch, Zaanse Schans)
1. Zaanse Schans / monumentale panden → aftrek/onderhoud eigen woning (echte niche).
2. Veel oudere koopwoningen → WOZ-bezwaar-insteek.
3. Kleine hechte kern → nadruk "aan huis, persoonlijk".
4. Demografie/woningtype **[verifiëren]**.
5. Lokaal cijfer **[verifiëren]**.

**Ik wacht op je reactie op deze overlap-analyse voordat ik de stadspagina-content aanraak.** (De mojibake-fix hierop is puur encoding, geen contentwijziging, en zit in de vrijgegeven lijst.)

---

## 8. Consent & privacy (nieuw P1)

| Bevinding | Status | Bewijs |
|---|---|---|
| **Geen consent/CMP** | ⚠️ Probleem (AVG) | 0 treffers op `consent`/`cookiebot`/`usercentrics`/`gtag('consent'`/CMP in de hele codebase |
| **Trackers laden onvoorwaardelijk** | ⚠️ Probleem | Clarity (inline `<head>`), GA4 (`gtag` async), Meta Pixel (`fbq('track','PageView')`) starten bij pageload, vóór enige toestemming |
| **Dode Privacybeleid-link** | ⚠️ Probleem | Footer: `<a href="#">Privacybeleid</a>` (`index.html:2236`) — link gaat nergens heen |
| **Geen privacypagina** | ⚠️ Probleem | Geen `/privacy/` in de site (wel `over-ons`) |

**Impact:** onder AVG/ePrivacy (NL Telecommunicatiewet art. 11.7a) vereisen analytics- én marketingcookies **voorafgaande toestemming**. Meta Pixel en GA4 zijn zonder consent niet toegestaan; Microsoft Clarity (session recording) evenmin. Dit is een juridisch risico én een vertrouwens-/EEAT-signaal.

**Voorgestelde oplossing (nog niet gebouwd — jouw akkoord):**
1. **Lichtgewicht, self-hosted consent-gate** (vanilla JS, geen extra third-party): scripts pas injecteren ná "Accepteren"; standaard geblokkeerd. Houdt de site dependency-vrij en snel.
2. **Google Consent Mode v2** aansluiten op GA4 als je gedeeltelijke meting wilt behouden.
3. **Meta Pixel heroverwegen:** alleen houden als je daadwerkelijk Facebook/Instagram-advertenties draait; anders verwijderen (scheelt ook laadtijd).
4. **Privacypagina schrijven** + de footer-link laten wijzen naar `/privacy/`.

> Dit raakt punt 9 uit de "mag nu"-lijst niet: de trackers blijven ongemoeid tot je akkoord op de consent-aanpak.

---

## 9. E-E-A-T auteur-voorstel (P1, YMYL) — structuur, jij levert de tekst/gegevens

Belastingadvies is **YMYL** ("Your Money or Your Life"); Google weegt aantoonbare expertise zwaar. Nu is de `author` overal de **organisatie**, zonder genoemd persoon. Voorstel:

**Wat ik lever (code/structuur):**
- Een herbruikbaar **auteur-blok** (naam, foto/initialen, functie, korte bio, link naar `over-ons`) onder elk blogartikel.
- `Person`-schema als `author` in de Article-JSON-LD, gekoppeld aan de organisatie:
```json
"author": {
  "@type": "Person",
  "name": "<NAAM>",
  "jobTitle": "<bijv. Belastingadviseur / Fiscalist>",
  "worksFor": { "@type": "Organization", "name": "Belastinghulp Zaanstad" },
  "url": "https://belastinghulpzaanstad.nl/over-ons/",
  "knowsAbout": ["inkomstenbelasting","toeslagen","hypotheekrenteaftrek","box 3"]
}
```
- Optioneel `reviewedBy` als een tweede persoon de inhoud controleert.

**Wat jij aanlevert (ik verzin geen namen/kwalificaties):**
- Naam + functie + eventuele kwalificatie (bijv. lidmaatschap, jaren ervaring, opleiding) + 2-3 zinnen bio + evt. foto.
- Of je één auteur voor alles wilt, of meerdere.

---

## 10. Nieuwe bevinding (tijdens uitvoering) — verouderde huurtoeslag-cijfers in blogcontent

Tijdens de fixes ontdekt: twee blogartikelen bevatten nog **pre-2026 huurtoeslagcijfers** die de deze week gecorrigeerde rekentool (`huurtoeslag-berekenen`, met officiële 2026-cijfers) **tegenspreken**. Interne tegenstrijdigheid + feitelijke staleness.

**`blog/huurtoeslag-grens/`** (bewijs):
- meta + tabel + FAQ: huurgrens **€900,07** → officieel 2026 **€932,93** (regels 10, 127, 247)
- vermogensgrens **€37.395 / €74.790** → officieel 2026 **€36.952 / €73.904** (regels 128-129, 162, 256, en JSON-LD r.446)
- r.137: *"Woont u in een te dure woning, dan heeft u geen recht op huurtoeslag — ook niet gedeeltelijk"* → **onjuist voor 2026**: hoge huur diskwalificeert niet meer, er wordt afgetopt op €932,93.

**`blog/huurtoeslag-aanvragen/`** (bewijs):
- meta/og/twitter: huurgrens/vermogen impliciet oud; "Inkomensgrens €32.975" en "tot €522/mnd" zijn 2025-cijfers (r.10/16/22)
- r.151: huur **€900,07**, vermogen **€37.395**
- r.180: "liberalisatiegrens niet overschrijden" → herzien i.v.m. 2026-aftopregel

**Advies:** deze twee artikelen gelijktrekken met de officiële 2026-cijfers uit de rekentool (huurgrens €932,93; vermogen €36.952/€73.904; aftopping i.p.v. diskwalificatie; servicekosten tellen niet meer mee). **Dit is content — ik lever een voorstel en wacht op je akkoord** (staat niet in de vrijgegeven lijst van deze ronde).

---

**Ik stop de rapportage hier.** De **overlap-analyse (§7)** en het **consent-rapport (§8)** wachten op jouw reactie voordat ik respectievelijk stadspagina-content en de consent-aanpak aanraak. Ik ga nu wél verder met de door jou vrijgegeven punten (mojibake, robots.txt, datePublished, homepage-schema, llms.txt, diensten-links, fonts self-hosten, Clarity-fix) op branch `seo-performance-audit`, elk als aparte commit.
