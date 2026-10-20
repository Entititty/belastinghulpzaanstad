# TODO: het no cure no pay-tarief voor box 3

**Status:** wacht op een percentage van Stan. Aangemaakt 28 augustus 2026,
bijgewerkt 20 oktober 2026.

Sinds oktober 2026 heet de dienst "Hulp bij uw Opgaaf werkelijk rendement
(box 3)" en niet meer "bezwaar box 3": over 2021 tot en met 2024 laat de
Belastingdienst iedereen met box 3-inkomen het werkelijk rendement opgeven met
het formulier Opgaaf werkelijk rendement, ook zonder bezwaar. Zelf doen kan
gratis. Wij rekenen het uit en dienen het in op basis van no cure no pay.

Wat dat kost, staat nog nergens. Op de site staat nu alleen wanneer u betaalt:
*"U betaalt alleen als de Belastingdienst uw box 3-belasting verlaagt. Levert
de opgaaf niets op, dan betaalt u niets. Hoeveel u betaalt, hoort u vooraf, en
u tekent er zelf voor."* Dat is niet fout, wel onvolledig.

---

## Waar het tarief vandaan komt

Eén plek: `data/bedrijf.json`, onder `placeholders`.

| veld | betekenis | voorbeeldvorm |
|---|---|---|
| `FEE_BOX3` | percentage, als getal | `15` betekent 15% |
| `FEE_BOX3_GRONDSLAG` | waarover het percentage gaat | `"van de belasting die u terugkrijgt"` |
| `FEE_BOX3_MIN` | minimumbedrag in euro, of `null` | `50` |
| `FEE_BOX3_MAX` | maximumbedrag in euro, of `null` | `500` |

Daarna:

```bash
node scripts/bouw.js
```

`config-sync.js` (de eerste stap van `bouw.js`) zet de zin in de blokken
`<!-- cfg:box3-tarief -->` en `<!-- cfg:box3-tarief-en -->` op `/tarieven/`,
`/diensten/box-3-bezwaar/` en `/en/services/box-3-objection/`. Zolang
`FEE_BOX3` leeg is, waarschuwt het script bij elke run en blijft de huidige
zin staan. Een percentage van 0 of 100 of meer is een fout en stopt het script.

De overige vermeldingen van no cure no pay (homepage, plaatspagina's, blogs)
noemen geen bedrag en linken naar `/tarieven/` of de dienstpagina. Zo blijft
het, zodat er maar één plek is om bij te werken.

---

## De vragen die beantwoord moeten worden

**1. Het percentage.**

**2. Waarover wordt het gerekend?**
Over de belasting die de Belastingdienst terugbetaalt of verlaagt, over
welke jaren samen, en telt belastingrente mee? Dit wordt `FEE_BOX3_GRONDSLAG`.

**3. Een minimum of maximum?** Ja of nee, en zo ja welk bedrag.

**4. Wanneer betaalt de klant?**
Bij de beslissing van de Belastingdienst, of pas als het geld op de rekening
staat? Zet dit in de opdrachtbevestiging; de site zegt nu alleen "u betaalt
alleen als de Belastingdienst uw box 3-belasting verlaagt".

**5. Wat als het nul oplevert?**
De site belooft: dan betaalt u niets, ook geen dossierkosten of uren. Klopt
dat niet, dan moet de zin in `scripts/config-sync.js` (functie `feeZin`) mee
veranderen.

**6. Gaat de zaak naar de rechter?**
Op `/tarieven/` staat onder "wat er niet bij zit" dat een procedure bij de
rechter niet in de prijs zit en dat we dat vooraf zeggen. Dat moet blijven
kloppen met de afspraak.

---

## JSON-LD

Een percentage is geen prijs in schema.org. De `OfferCatalog` op `/tarieven/`
heeft daarom alleen een `Offer` voor de gratis check (`price: "0"`); het
no cure no pay-deel heeft bewust geen `Offer`. Zet daar geen verzonnen bedrag
in.

---

## Controleren na de wijziging

```bash
node scripts/bouw.js
grep -rn "cfg:box3-tarief" --include=index.html .
```

En met de hand: staat het percentage op `/tarieven/` en op de box 3-pagina
(NL en EN), en zegt de pagina wat er gebeurt als de opgaaf niets oplevert?

---

**Let op:** de rest van `docs/` staat in `.gitignore` en de repo op GitHub is
publiek. Dit bestand is de uitzondering, juist zodat het niet zoekraakt. Zet er
dus geen cijfers, klantgegevens of concurrentieanalyse in; die horen in de
bestanden die genegeerd blijven.

`docs/TODO-kvk-btw.md` staat er met opzet niet bij: dat bestand beschrijft dat
de inschrijving nog niet rond is, en dat hoort niet op een publieke repo. Het
staat alleen lokaal. Maak daar zelf een kopie van buiten deze map.
