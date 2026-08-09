# CONTENT-VERVALDATA.md — datumgebonden content

Overzicht van teksten/cijfers op de site die op een bekend moment **verlopen** of
herzien moeten worden, zodat niets stilletjes veroudert. Bijgehouden sinds ronde 2
(aangemaakt 2026-07-27).

> Legenda: **AUTO** = wisselt automatisch via JavaScript · **HANDMATIG** = vereist een
> handmatige tekstwijziging op de genoemde datum.

---

## 1. Uitstel-strip op de homepage — AUTO ✅
- **Bestand:** `index.html`, sectie `#uitstel-strip` (elementen `#uitstel-badge/-title/-desc/-chip`)
- **Logica:** vóór **1 september 2026** = persoonlijk-uitstel-boodschap; ná 1 sep 2026
  schakelt het script automatisch naar de **Beconregeling** (uitstel tot **1 mei 2027**).
- **Volgende HANDMATIGE actie — uiterlijk 2027-04-15:** ná 1 mei 2027 is óók de
  Becon-deadline verlopen. De strip moet dan overschakelen naar het **belastingjaar 2026**
  (aangifte voorjaar 2027) of tijdelijk verborgen worden. Werk het script + de standaardtekst bij.

## 2. "Persoonlijk uitstel tot 1 sep 2026 / Beconregeling tot 1 mei 2027" (bodytekst) — HANDMATIG
- **Bestanden:** homepage (`index.html` r. ~1655, 2075, 2178, 2465) + diverse dienst-/blogpagina's
  (~22 HTML-bestanden bevatten "tot 1 september").
- **Geldig tot:** **2027-05-01**. Deze teksten benoemen beide data en blijven correct tot dan.
- **Actie — Q1 2027:** actualiseren naar de cyclus van belastingjaar 2026
  (persoonlijk uitstel tot ~1 sep 2027, Becon tot ~1 mei 2028).

## 3. "Aangifte 2025" / belastingjaar-framing — HANDMATIG
- **Bestanden:** ~14 HTML-bestanden noemen "aangifte 2025" (o.a. homepage-hero, uitstel-strip,
  te-laat-/uitstel-blogs).
- **Actie — vanaf 2027-01 (start aangifteseizoen 2026):** verschuif naar "aangifte 2026".
  Let ook op de hero-subtekst "…uw aangifte 2025 nog niet deed…".

## 4. Deadline-artikelen — HANDMATIG
- `blog/einddatum-belastingaangifte-2025/` = **noindex redirect** naar de 2026-versie (OK, laten staan).
- `blog/einddatum-belastingaangifte-2026/` = live, **deadline 1 mei 2027**.
  **Actie — Q1 2027:** maak `…-2027/`, zet 2026 op noindex+redirect, herhaal het patroon.
- `en/blog/tax-return-deadline-2025/` = **verouderd (nog over 2025)**. hreflang wijst nu naar de
  NL 2026-versie. **Actie — z.s.m. (zie Taak 9):** inhoud verversen naar 2026 of retireren.

## 5. Toeslag- en tariefcijfers (jaarlijks) — HANDMATIG
- **Bestanden/onderwerpen:** huurtoeslag (grens €932,93 / vermogens­grenzen), zorgtoeslag,
  heffingskortingen, ouderenkorting, box 3-forfaits, eigenwoningforfait (0,35%),
  rekentools `blog/huurtoeslag-berekenen/` en `blog/hypotheekrenteaftrek-berekenen/`.
- **Actie — Q4 2026 / Q1 2027:** zodra de **2027-cijfers** van de Belastingdienst bekend zijn,
  bijwerken en `dateModified` + zichtbare "Laatst bijgewerkt" ophogen.

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

## 6. Box 3 / rechtsherstel-jaren — HANDMATIG
- **Bestanden:** `diensten/box-3-bezwaar/`, `blog/box-3-bezwaar-2026/`, `blog/box-3-sparen/`,
  `blog/hoeveel-spaargeld-belastingvrij/`.
- **Verwijzing:** "aanslagen 2021–2024". **Actie:** uitbreiden zodra nieuwe aanslagjaren/uitspraken
  relevant worden (bijv. aanslag 2025).

### ✅ Volledige cijferaudit uitgevoerd (2026-07-27) — geverifieerde 2026-referentiewaarden
Alle onderstaande waarden zijn geverifieerd bij belastingdienst.nl / rijksoverheid.nl en
sitebreed doorgevoerd (NL + EN). Gebruik ze als ijkpunt bij de volgende jaarupdate:

| Onderwerp | 2026-waarde |
|---|---|
| Box 1 schijven (< AOW) | 35,75% (tot €38.883) · 37,56% (–€78.426) · 49,50% |
| Max. aftrektarief eigen woning | 37,56% · eigenwoningforfait 0,35% (WOZ ≤ €1.350.000) |
| Algemene heffingskorting | max €3.115 · afbouw €29.736→€78.426 (6,398%) |
| Arbeidskorting | max €5.685 · IACK max €3.032 · jonggehandicapten €923 |
| Ouderenkorting | €2.067 (grens €46.002, afbouw 15% tot €59.783) · alleenstaand €540 |
| AOW-er box 1 schijf 1 | ca. 17,85% |
| Zorgtoeslag | inkomensgrens €40.857 / €51.142 · vermogensgrens €146.011 / €184.633 |
| Huurtoeslag | rekenhuur €932,93 · vermogen €36.952 / €73.904 |
| Kinderopvangtoeslag max uurtarief | dagopvang €11,23 · bso €9,98 · gastouder €8,49 |
| Kindgebonden budget vermogensgrens | €146.011 / €184.633 |
| Box 3 | heffingvrij €59.357 / €118.714 · forfait spaargeld 1,28% · beleggingen 6,00% · schulden 2,70% · schuldendrempel €3.800 / €7.600 · tarief 36% |

## 7. Vaste bedragen die kunnen wijzigen — HANDMATIG
- **Verzuimboete €385** (uitstel-strip + te-laat-blogs) — controleren bij Belastingdienst-wijziging.
- **"Vaste prijs €59" / tarieven** (€59/€69/€109/€49/€30, spoedtoeslag €25) — bij prijswijziging
  sitebreed + in `llms.txt` + og-image bijwerken.

---

### Aanbevolen vaste controlemomenten
| Wanneer | Wat nalopen |
|---|---|
| **2026-12** | 2027-toeslag-/tariefcijfers (§5); prijzen (§7) |
| **2027-01** | belastingjaar-framing 2025→2026 (§3); deadline-2027-artikel aanmaken (§4) |
| **2027-04-15** | uitstel-strip laten pivoten na afloop Becon-deadline (§1) |
| **jaarlijks mei** | na afloop aangifteseizoen: hero/strip/blogs herijken |


---

## Eén bron van waarheid voor fiscale cijfers (Taak 3)
- **data/fiscale-cijfers.json** — alle 2026-cijfers met bron + 'verouderd'-lijst.
- **data/plaatsen.json** — inwoners + woningprijs per kern (bron nog TODO; sommige pagina's tonen meerdere bedragen).
- **scripts/check-fiscale-cijfers.js** — `node scripts/check-fiscale-cijfers.js`; faalt (exit 1) als een verouderde waarde weer in de HTML staat. Draai dit vóór elke push.
- Let op: de site is statische HTML zonder build, dus cijfers worden NIET automatisch uit de JSON gegenereerd. Wijzig je een cijfer: pas het aan in de JSON én in de HTML, en zet de oude waarde in 'verouderd'.
