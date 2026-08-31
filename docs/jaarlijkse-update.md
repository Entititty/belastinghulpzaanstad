# Jaarlijkse update van de fiscale cijfers

Bedoeld voor januari. Je hoeft geen scripts te kennen om dit uit te voeren; volg
de stappen. Reken op één tot twee uur.

Alles draait om twee bestanden:

- `data/fiscale-cijfers.json` — de enige plek waar de waarden mét bron staan
- `scripts/set-fiscale-cijfers.js` — vervangt een waarde overal in de HTML

De site heeft geen build: wat in git staat, staat op de server. De bedragen
staan dus echt in de pagina's, ruim 600 keer. Daarom vervangt het script tekst;
handmatig zoeken en vervangen is hier niet te doen.

---

## Voorbereiding

```bash
cd "/pad/naar/Website belasting"
git checkout main && git pull
git checkout -b cijfers-2027
node scripts/check-fiscale-cijfers.js     # moet groen zijn vóór je begint
```

Staat er een waarschuwing "langer dan 12 maanden niet gecontroleerd"? Dan is dit
precies het moment.

---

## Volgorde

Werk van breed naar smal. De eerste bron dekt elf waarden in één keer; daarna
wordt het losse werk.

### Stap 1. Tarieven, heffingskortingen en box 3 (11 waarden)

Bron: [voorlopige aanslag 2027: gebruikte tarieven en heffingskortingen](https://www.belastingdienst.nl/wps/wcm/connect/nl/voorlopige-aanslag/content/voorlopige-aanslag-tarieven-en-heffingskortingen)

Deze pagina noemt in één tabel: het tarief van de eerste, tweede en derde schijf,
de algemene heffingskorting, de arbeidskorting, de IACK, de ouderenkorting, de
alleenstaande ouderenkorting, het heffingsvrij vermogen alleen en met partner, en
het box 3-tarief.

| Sleutel | Waarde 2026 | Vermeldingen op de site |
| --- | --- | ---: |
| `box1_schijf1_tarief` | 35,75% | 14 |
| `box1_schijf2_tarief` | 37,56% | 64 |
| `box1_schijf3_tarief` | 49,50% | 10 |
| `algemene_heffingskorting_max` | €3.115 | 20 |
| `arbeidskorting_max` | €5.685 | 10 |
| `iack_max` | €3.032 | 2 |
| `ouderenkorting_max` | €2.067 | 52 |
| `ouderenkorting_alleenstaande` | €540 | 30 |
| `box3_heffingvrij_alleenstaand` | €59.357 | 39 |
| `box3_heffingvrij_partners` | €118.714 | 32 |
| `box3_tarief` | 36% | 15 |

Per waarde:

```bash
node scripts/set-fiscale-cijfers.js --zet ouderenkorting_max "€2.150" \
  --bron-url "https://www.belastingdienst.nl/wps/wcm/connect/nl/voorlopige-aanslag/content/voorlopige-aanslag-tarieven-en-heffingskortingen"
```

Dat toont eerst wat er zou gebeuren, regel voor regel. Klopt het? Zelfde commando
met `--schrijf` erachter.

**Let op bij `box1_schijf2_tarief` en `max_aftrektarief_eigen_woning`.** Die zijn
in 2026 allebei 37,56%, maar het zijn twee verschillende dingen: het tarief van
de tweede schijf en het maximale tarief waartegen je aftrekposten mag aftrekken.
Ze kunnen uit elkaar lopen. Controleer ze apart, en zet ze apart.

### Stap 2. Aftrektarief (1 waarde, 64 vermeldingen samen met stap 1)

Bron: [tariefsaanpassing aftrekposten bij een hoog inkomen](https://www.belastingdienst.nl/wps/wcm/connect/nl/aftrek-en-kortingen/content/afbouw-tarief-aftrekposten-bij-hoog-inkomen)

`max_aftrektarief_eigen_woning`. Geldt voor alle aftrekposten, niet alleen de
eigen woning: persoonsgebonden aftrek, kosten eigen woning,
ondernemersfaciliteiten. De naam van de sleutel is historisch.

### Stap 3. Eigenwoningforfait (1 waarde, 48 vermeldingen)

Bron: [hoe werkt het eigenwoningforfait](https://www.belastingdienst.nl/wps/wcm/connect/nl/koopwoning/content/hoe-werkt-eigenwoningforfait)

`eigenwoningforfait_pct`. Wijzigt dit percentage, dan kloppen ook alle
**rekenvoorbeelden** op de negen plaatspagina's en de homepage niet meer. Zie
"Rekenvoorbeelden" onderaan.

### Stap 4. Box 3-forfaits (4 waarden)

Bron: [berekening box 3-inkomen](https://www.belastingdienst.nl/wps/wcm/connect/nl/box-3/content/berekening-box-3-inkomen-2026) — pas het jaartal in de URL aan.

`box3_forfait_spaargeld`, `box3_forfait_beleggingen`, `box3_forfait_schulden`,
`box3_schuldendrempel_alleenstaand`.

**Dit is de enige stap die twee keer moet.** De percentages voor banktegoeden en
schulden zijn in januari nog voorlopig; ze worden pas begin van het volgende jaar
definitief vastgesteld. Zet in januari de voorlopige waarde, en zet een
herinnering voor februari van het jaar daarna om ze definitief te maken.

### Stap 5. Toeslagen (10 waarden)

| Wat | Bron |
| --- | --- |
| Zorgtoeslag: inkomens- en vermogensgrenzen (4) | [kan ik zorgtoeslag krijgen](https://www.belastingdienst.nl/wps/wcm/connect/nl/zorgtoeslag/content/kan-ik-zorgtoeslag-krijgen) |
| Kindgebonden budget: vermogensgrens (1) | [kan ik kindgebonden budget krijgen](https://www.belastingdienst.nl/wps/wcm/connect/nl/kindgebonden-budget/content/kan-ik-kindgebonden-budget-krijgen) |
| Huurtoeslag: maximale rekenhuur (1) | [berekening huurtoeslag](https://www.belastingdienst.nl/wps/wcm/connect/bldcontentnl/themaoverstijgend/brochures_en_publicaties/berekening-huurtoeslag-2026) |
| Huurtoeslag: vermogensgrenzen (2) | [maximaal vermogen huurtoeslag](https://www.belastingdienst.nl/wps/wcm/connect/nl/huurtoeslag/content/maximaal-vermogen-huurtoeslag) |
| Kinderopvang: drie uurtarieven (3) | [maximumuurprijs kinderopvangtoeslag](https://www.belastingdienst.nl/wps/wcm/connect/bldcontentnl/belastingdienst/prive/toeslagen/kinderopvangtoeslag/hoeveel-kinderopvangtoeslag-kan-ik-krijgen/maximaal-uurtarief-voor-de-kinderopvang) |

De vermogensgrens van de huurtoeslag is een **eigen** grens; die is niet gelijk
aan het heffingsvrij vermogen in box 3. Dat is in 2026 fout gegaan.

### Stap 6. Boete en rente (3 waarden)

| Sleutel | Bron |
| --- | --- |
| `verzuimboete_eerste`, `verzuimboete_maximum` | [belastingdienst.nl, Boete](https://www.belastingdienst.nl/wps/wcm/connect/bldcontentnl/standaard_functies/prive/contact/rechten_en_plichten_bij_de_belastingdienst/boete) |
| `belastingrente_ib` | [overzicht percentages belastingrente](https://www.belastingdienst.nl/wps/wcm/connect/bldcontentnl/standaard_functies/prive/contact/rechten_en_plichten_bij_de_belastingdienst/belastingrente/overzicht_percentages_belastingrente) |

De eerste verzuimboete is 7% van het wettelijk maximum van artikel 67a AWR
(§ 21 lid 2 van het [Besluit Bestuurlijke Boeten Belastingdienst](https://wetten.overheid.nl/BWBR0038145/)).
Wijzigt het maximum, dan wijzigt de boete mee. Controleer of 7% × maximum nog
uitkomt op het bedrag dat de Belastingdienst noemt; loopt dat uiteen, dan is er
iets veranderd in de regeling en moet je verder kijken dan dit lijstje.

### Stap 7. Startkorting (1 waarde, 90 vermeldingen)

`startkorting_eerste_klanten` is geen fiscaal cijfer maar een eigen actie. Loopt
die af, gebruik dan niet dit script maar verwijder de teksten; een korting van
€0 is geen korting.

---

## Na afloop, altijd

```bash
node scripts/check-fiscale-cijfers.js   # geen verouderde waarden, alle bronnen en data aanwezig
node scripts/check-html.js              # geen kapotte tags door de vervangingen
node scripts/crawl-audit.js             # 95 pagina's, 404:0, dupTitle:0
node scripts/build-sitemap.js           # na het committen
```

`check-fiscale-cijfers.js` doet drie dingen: het weigert een waarde zonder bron
of datum, het waarschuwt bij waarden ouder dan twaalf maanden, en het vergelijkt
elk bedrag in JSON-LD met de zichtbare tekst op dezelfde pagina. Die laatste
controle is er omdat schema en tekst eerder uit elkaar zijn gelopen.

Loop daarna met het oog langs:

- de homepage, één plaatspagina en `/tarieven/`
- `llms.txt`: die noemt bedragen die niet uit het script komen
- `docs/beweringen-controle.md`: uitspraken **over** bedragen ("gelijk aan",
  "meer dan") worden door geen enkel script bewaakt

---

## Rekenvoorbeelden: het script raakt ze niet aan

Op de homepage, negen plaatspagina's en `/diensten/voorlopige-teruggave/` staat
een rekenvoorbeeld eigen woning. De methode is:

```
(hypotheekrente − eigenwoningforfait) × aftrektarief = jaarvoordeel
jaarvoordeel ÷ 12 = maandbedrag
```

Wijzigt het aftrektarief of het forfaitpercentage, dan kloppen het jaarvoordeel
en het maandbedrag niet meer, terwijl er geen enkel "verouderd" bedrag in de
HTML staat. Geen script dat dat merkt. Reken ze met de hand na, per pagina:

| Pagina | Rente | Forfait |
| --- | ---: | ---: |
| homepage, `/wormerland/`, `/diensten/voorlopige-teruggave/` | €12.580 | €1.190 |
| `/koog-aan-de-zaan/` | €11.470 | €1.085 |
| `/wormerveer/` | €10.360 | €980 |
| `/assendelft/` | €14.245 | €1.348 |
| `/zaandijk/` | €12.210 | €1.155 |
| `/westzaan/` | €12.950 | €1.225 |
| `/krommenie/` | €11.285 | €1.068 |
| `/oostzaan/` | €13.875 | €1.313 |

De Engelse tegenhangers `/en/`, `/en/zaandam/` en `/en/wormerland/` gebruiken
dezelfde bedragen met een komma als duizendscheiding.

---

## Als een waarde verdwijnt of nieuw is

Een nieuwe waarde zet je met de hand in `data/fiscale-cijfers.json`:

```json
"nieuwe_sleutel": {
  "waarde": "€1.234",
  "geverifieerd": true,
  "bron": "korte omschrijving van wat de bron letterlijk zegt",
  "bron_url": "https://www.belastingdienst.nl/...",
  "gecontroleerd_op": "2027-01-15",
  "verouderd": []
}
```

Is de waarde kort (drie tekens of minder, zoals "36%" of "€20"), zet er dan een
`"context"` bij: een lijst woorden waarvan er één op dezelfde regel moet staan.
Zonder die lijst weigert het script te vervangen, en terecht: "36%" staat ook in
zinnen die niets met box 3 te maken hebben.
