# CONTENT-VERVALDATA.md — datumgebonden content

Overzicht van teksten/cijfers op de site die op een bekend moment **verlopen** of
herzien moeten worden, zodat niets stilletjes veroudert. Bijgehouden sinds ronde 2
(aangemaakt 2026-07-27).

> Legenda: **AUTO** = wisselt automatisch via JavaScript · **HANDMATIG** = vereist een
> handmatige tekstwijziging op de genoemde datum.

---

## 1. Strip "aangifte 2025 nog niet gedaan" op de Engelse homepage — HANDMATIG
*Bijgewerkt 2026-10-20.* De Nederlandse homepage heeft geen uitstel-strip meer. De
site noemt nergens een Beconregeling: die claim is eerder weggehaald, omdat niet
vaststaat dat Belastinghulp Zaanstad een Beconnummer heeft (open vraag aan de eigenaar).
- **Bestand:** `en/index.html`, sectie `#uitstel-strip` (statische HTML).
- **Nu:** "Not filed your 2025 return yet? You can still file it", late aangifte €69
  (`data-prijs`). De oude tekst "extension until 1 September 2026" is per 2026-10-20 vervangen.
- **Actie — 2027-01:** omzetten naar het aangifteseizoen 2026 (aangifte vóór 1 mei 2027).
- `js/seizoen.js` en `data/seizoen.json` worden op dit moment door geen enkele pagina
  geladen. Zet je ze weer aan, werk dan eerst de periodeteksten bij (jaartallen, prijzen).

## 2. "Uitstel tot 1 september 2026" (bodytekst blogs) — HANDMATIG
- **Bestanden:** ~30 HTML-bestanden noemen "1 september" (uitstel-, deadline- en te-laat-blogs,
  plus de huurtoeslagblogs met "tot 1 september van het jaar erna", die blijven kloppen).
- **Status:** de teksten over uitstel voor de aangifte 2025 zijn per 1 september 2026 verlopen,
  maar noemen steeds "vóór 1 mei" en "bent u al te laat, dien dan zo snel mogelijk in".
- **Bijgewerkt 2026-10-22:** `blog/uitstel-belastingaangifte-2025/` is samengevoegd met de tijdloze
  pagina `blog/uitstel-belastingaangifte-aanvragen/` (vangnet + 301), die geen jaartallen noemt. Over:
  `blog/te-laat-belastingaangifte/` (noemt de deadline van 1 mei 2026; klopt voor wie nu te laat is).
- **Actie — Q1 2027:** actualiseren naar de cyclus van belastingjaar 2026
  (uitstel aanvragen vóór 1 mei 2027, uitstel tot 1 september 2027). Zie `docs/seizoen-2027.md`.

## 2a. Startkorting €20 — HANDMATIG, verloopt **2026-12-31**
- **Bron:** `data/bedrijf.json` → `startkorting` (`actief`, `bedrag`, `geldig_tot`), en
  `startkorting_eerste_klanten` in `data/fiscale-cijfers.json`.
- **Tekst:** "nieuwe klanten krijgen in 2026 €20 korting op een aangifte of voorlopige
  teruggave, met of zonder review".
- **Bestanden (22):** `tarieven/`, `over-ons/`, de negen NL-plaatspagina's, `en/`,
  `en/about-us/` en de negen EN-plaatspagina's; plus `llms.txt`.
- **Actie — 2026-12-31:** loopt de actie af, zet `actief` op `false` (haalt de regel op
  `/tarieven/` weg) en haal de overige vermeldingen met de hand weg. Verlengen: pas
  `geldig_tot` en de jaartallen in de tekst aan.

## 2b. "In 2026 kunt u nog aftrekposten uit 2021 terugvragen" — HANDMATIG, verloopt eind 2026
- **Bestand:** `diensten/correctie-late-aangifte/` (urgentieblok), placeholder
  `EINDDATUM_CORRECTIE_2021` in `data/bedrijf.json`: **31 december 2026** (ingevuld 2026-10-21;
  een verzoek om vermindering moet binnen 5 jaar na het einde van het belastingjaar binnen zijn,
  ontvangst telt). Ook in `llms.txt`.
- **Let op:** de meta description van `diensten/correctie-late-aangifte/` noemt het ook ("over 2021
  kan dat nog tot 31 december 2026"). Die staat niet in de config: met de hand aanpassen.
- **Actie — 2027-01:** het jaartal één jaar opschuiven (2022) en de placeholder leegmaken.

## 2c. Rekentools — deels AUTO
- `/rekentools/voorlopige-teruggave/` en `/rekentools/ouderenkorting/` rekenen met
  `data/fiscale-cijfers.json` (via `js/rekenhulp.js`) en volgen de jaarlijkse update vanzelf.
  De uitlegteksten op die pagina's (35,75%, €38.883, €2.067 enz.) vervangt `set-fiscale-cijfers.js`.
- **HANDMATIG:** de oudere rekentools in `blog/hypotheekrenteaftrek-berekenen/` en
  `blog/huurtoeslag-berekenen/` hebben hun cijfers in het paginascript staan. Werk die bij
  elke jaarupdate met de hand bij (zie `docs/jaarlijkse-update.md`).

## 3. "Aangifte 2025" / belastingjaar-framing — HANDMATIG
- **Bestanden:** ~14 HTML-bestanden noemen "aangifte 2025" (o.a. homepage-hero, uitstel-strip,
  te-laat-/uitstel-blogs).
- **Actie — vanaf 2027-01 (start aangifteseizoen 2026):** verschuif naar "aangifte 2026".
  Let ook op de hero-subtekst "…uw aangifte 2025 nog niet deed…".
- **Al gedaan 2026-10-22:** `blog/einddatum-belastingaangifte-2026/` (sinds 2026-10-23 samen met het
  voormalige `belastingaangifte-voor-1-april`) en `blog/aangifte-inkomstenbelasting/` staan op de aangifte over 2026 (aangifte van 1 maart tot 1 mei 2027). Over: de homepage-FAQ
  "Ik heb mijn aangifte 2025 niet gedaan", de te-laat-blog en de strip op de Engelse homepage.

## 4. Deadline-artikelen — HANDMATIG
- `blog/einddatum-belastingaangifte-2025/` = **noindex redirect** naar de 2026-versie (OK, laten staan).
- `blog/einddatum-belastingaangifte-2026/` = live, **deadline 1 mei 2027**. Deze pagina is het hele
  seizoen 2026 actueel (tot 1 mei 2027, met uitstel 1 september 2027).
  **Actie — na 1 mei 2027:** werk dezelfde pagina bij naar het seizoen 2027 (titel, H1, tabellen, FAQ,
  `dateModified`). Het jaartal in het adres blijft dan staan; een nieuwe URL per jaar kost telkens
  de opgebouwde positie.
- `blog/belastingaangifte-voor-1-april/` = **samengevoegd** op 2026-10-23 met de einddatum-pagina
  (vangnet + 301 in nginx). De tabel met 1 maart / 1 april / 1 mei / 1 september en de uitleg over
  "vóór 1 april = vóór 1 juli bericht" staan nu daar.
- `en/blog/tax-return-deadline-2025/` en `en/blog/tax-return-extension-2025/`: **samengevoegd**
  op 2026-10-22 met `en/blog/late-tax-return/` (vangnet + 301). Er is geen Engelse deadlinepagina
  voor 2026; maak die alleen als er Engelse vraag naar blijkt.

## 5. Toeslag- en tariefcijfers (jaarlijks) — HANDMATIG
- **Bestanden/onderwerpen:** huurtoeslag (grens €932,93 / vermogens­grenzen), zorgtoeslag,
  heffingskortingen, ouderenkorting, box 3-forfaits, eigenwoningforfait (0,35%),
  rekentools `blog/huurtoeslag-berekenen/` en `blog/hypotheekrenteaftrek-berekenen/`.
- **Actie — Q4 2026 / Q1 2027:** zodra de **2027-cijfers** van de Belastingdienst bekend zijn,
  bijwerken en `dateModified` + zichtbare "Laatst bijgewerkt" ophogen.

## 6. Jaarlijks terugkerende data in titels en FAQ — HANDMATIG
*Toegevoegd 2026-10-22.*
- **Terugwerkende kracht toeslagen:** `blog/huurtoeslag-aanvragen/`, `en/blog/rent-benefit/`,
  `blog/zorgtoeslag-grens/` noemen "over 2026 tot 1 september 2027". **Actie — na 1 september
  2027:** een jaar opschuiven.
- **Seizoensdata:** `blog/einddatum-belastingaangifte-2026/` (tabel 1 maart / 1 april / 1 mei /
  1 september 2027, titel "Belastingaangifte 2026: deadline 1 mei 2027 (+ uitstel)"). **Actie — na 1 mei 2027:** naar het seizoen 2027.
- **Gemeentebelastingen:** titel en kop van `blog/kwijtschelding-gemeentelijke-belasting/` en
  `en/blog/municipal-tax-waiver/` noemen 2026. **Actie — februari 2027**, als de nieuwe aanslag komt:
  naar 2027, en controleer de voorwaarden op zaanstad.nl (autogrens €3.350, termijn 3 maanden).

## ✅ OPGELOST (2026-07-27) — box 1-tarief "36,93%" sitebreed geactualiseerd

De site gebruikte overal **36,93%** (= 2023-tarief). Nu sitebreed vervangen door de
geverifieerde 2026-tarieven; **0 resterende treffers** van 36,93%. Per context toegepast:
hypotheek-/schijf 2-voorbeelden → 37,56% (incl. homepage-hero, nu **€295/maand**, en de
9 kernpaginas met elk hun eigen herrekende bedragen); algemene aftrek/eerste schijf →
35,75% (giften, zorgkosten, belastingaangifte-tips); AOW-tarieventabel herbouwd naar de
2026-schijven (€38.883 / €78.426; AOW-er ca. 17,85% / 37,56% / 49,50%). Blijft jaarlijks
te controleren — zie de 2026-referentiewaarden hieronder.

De **2026**-tarieven (beneden AOW) zijn:

| Schijf | Grens 2026 | Tarief 2026 |
|---|---|---|
| Schijf 1 | tot € 38.883 | **35,75%** |
| Schijf 2 | € 38.883 – € 78.426 | **37,56%** |
| Schijf 3 | boven € 78.426 | 49,50% |

Het **maximale aftrektarief eigen woning** (tariefsaanpassing) 2026 = **37,56%**.

## 6. Box 3: Opgaaf werkelijk rendement 2021–2024 — HANDMATIG
- **Bestanden:** `diensten/box-3-bezwaar/` (en de EN-versie), `tarieven/`, `blog/box-3-bezwaar-2026/`,
  `blog/box-3-sparen/`, `blog/hoeveel-spaargeld-belastingvrij/`, `en/blog/box-3-savings/`.
- **Sinds 2026-10:** de dienst is hulp bij de Opgaaf werkelijk rendement (geen bezwaar), zelf doen
  kan gratis, wij werken op no cure no pay. Tarief: placeholder `FEE_BOX3` (zie `docs/TODO-no-cure-no-pay.md`).
- **Actie:** bij elke nieuwe stap van de Belastingdienst (termijnen, aanslag 2025, Wet werkelijk
  rendement box 3) de jaren en de uitleg nalopen op belastingdienst.nl.

### ✅ Volledige cijferaudit uitgevoerd (2026-07-27) — geverifieerde 2026-referentiewaarden
Alle onderstaande waarden zijn geverifieerd bij belastingdienst.nl / rijksoverheid.nl en
sitebreed doorgevoerd (NL + EN). Gebruik ze als ijkpunt bij de volgende jaarupdate:

| Onderwerp | 2026-waarde |
|---|---|
| Box 1 schijven (< AOW) | 35,75% (tot €38.883) · 37,56% (–€78.426) · 49,50% |
| Max. aftrektarief eigen woning | 37,56% · eigenwoningforfait 0,35% (WOZ ≤ €1.350.000) |
| Algemene heffingskorting | max €3.115 · afbouw €29.736→€78.426 (6,398%) |
| Arbeidskorting | max €5.685 · IACK max €3.032 · jonggehandicapten €923 |
| Ouderenkorting | €2.067 (grens €46.002, afbouw 15% tot €59.782) · alleenstaand €540 |
| AOW-er box 1 schijf 1 | ca. 17,85% |
| Zorgtoeslag | inkomensgrens €40.857 / €51.142 · vermogensgrens €146.011 / €184.633 |
| Huurtoeslag | rekenhuur €932,93 · vermogen €38.479 / €76.958 |
| Kinderopvangtoeslag max uurtarief | dagopvang €11,23 · bso €9,98 · gastouder €8,49 |
| Kindgebonden budget vermogensgrens | €146.011 / €184.633 |
| Box 3 | heffingvrij €59.357 / €118.714 · forfait spaargeld 1,28% · beleggingen 6,00% · schulden 2,70% · schuldendrempel €3.800 / €7.600 · tarief 36% |

## 7. Vaste bedragen die kunnen wijzigen — HANDMATIG
- **Verzuimboete €469** (eerste keer; maximum €6.709) in de te-laat-blogs, `llms.txt` en de EN-homepage —
  staat in `data/fiscale-cijfers.json`.
- **Prijzen** (€59/€89 aangifte, €49 eerste baan, €69/€99 correctie, €109/€149 voorlopige teruggave,
  €30 toeslagen, +€25 spoed): wijzig ze in `data/bedrijf.json` en draai `node scripts/bouw.js`. Titles,
  meta-descriptions, `llms.txt`, `data/seizoen.json` en og-images gaan met de hand; `config-sync.js`
  waarschuwt als daar een bedrag staat dat geen prijs meer is.

---

### Aanbevolen vaste controlemomenten
| Wanneer | Wat nalopen |
|---|---|
| **2026-12** | 2027-toeslag-/tariefcijfers (§5); prijzen (§7) |
| **2026-12-31** | startkorting afgelopen of verlengd (§2a); 2021-correctietekst (§2b) |
| **2027-01** | belastingjaar-framing 2025→2026 (§3); deadline-2027-artikel aanmaken (§4); EN-strip naar aangifteseizoen 2026 (§1); uitstelteksten naar 2027 (§2); 2021 → 2022 (§2b) |
| **jaarlijks mei** | na afloop aangifteseizoen: hero/strip/blogs herijken |


---

## Eén bron van waarheid voor fiscale cijfers (Taak 3)
- **data/fiscale-cijfers.json** — alle 2026-cijfers met bron + 'verouderd'-lijst.
- **data/bedrijf.json** — prijzen, bedrijfsgegevens en placeholders (KvK, btw of KOR, reviewlink); `scripts/config-sync.js` zet ze in de HTML.
- **data/plaatsen.json** — inwoners (2026), gemiddelde WOZ-waarde (2025) en % koop/huur per kern (bron CBS/AlleCijfers.nl); gelijk aan de statistiekblokken op de NL- en EN-plaatspagina's.
- **scripts/check-fiscale-cijfers.js** — `node scripts/check-fiscale-cijfers.js`; faalt (exit 1) als een verouderde waarde weer in de HTML staat. Draai vóór elke push `node scripts/bouw.js`; dat draait dit script mee.
- Let op: de site is statische HTML zonder build, dus cijfers worden NIET automatisch uit de JSON gegenereerd. Wijzig je een cijfer: pas het aan in de JSON én in de HTML, en zet de oude waarde in 'verouderd'.
