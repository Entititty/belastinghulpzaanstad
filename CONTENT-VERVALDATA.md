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
