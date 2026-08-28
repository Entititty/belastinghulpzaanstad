# TODO: het no cure no pay-tarief staat nergens

**Status:** wacht op een bedrag of percentage van Stan. Aangemaakt 28 augustus 2026.

Op de site staat 50 keer, verspreid over 15 pagina's, dat het hoofdbezwaar
box 3 op basis van no cure no pay gaat. Wat dat kost staat er nergens bij.
Dat is de enige echt verborgen kostenpost op de site: elk ander bedrag staat
op `/tarieven/`.

Zolang het bedrag er niet is, verandert er niets op de site. Geen
"vanaf"-bedrag, geen "neem contact op voor de voorwaarden", geen placeholder.
Zelfde regel als bij het KvK-nummer: liever niets dan iets wat niet klopt.
De huidige tekst is niet fout, hij is alleen onvolledig.

---

## De vier vragen die beantwoord moeten worden

**1. Het percentage of het bedrag.**
Bijvoorbeeld: 20 % van de teruggave, of een vast bedrag per geslaagd bezwaar.

**2. Waarover wordt het gerekend?**
Over het bedrag dat de Belastingdienst terugbetaalt, of over het verschil
tussen de oorspronkelijke aanslag en de nieuwe? Die twee zijn niet hetzelfde
zodra er al een voorlopige aanslag is geweest.

**3. Wat gebeurt er als er geen resultaat is?**
Aanname: u betaalt niets, ook geen dossierkosten en ook geen uren. Bevestigen.
Dit is de zin die op de pagina moet komen, want het is precies de vraag die
iemand tegenhoudt.

**4. Zit er een minimum of maximum aan, en waar houdt het op?**
- Een minimumvergoeding bij een kleine teruggave, ja of nee?
- Een maximum, ja of nee?
- Gaat de zaak naar de rechter: zit dat erbij, of is dat een aparte afspraak?
  Op `/tarieven/` staat nu al onder "wat er niet bij zit": *"Een
  bezwaarprocedure bij de rechter. Loopt het zo ver, dan zeggen wij dat
  vooraf."* Dat moet kloppen met het antwoord hier.

---

## Wat er daarna gebeurt

### 1. `/tarieven/`

Regel 274 tot 275 zegt nu:

> Bij bezwaar box 3 dienen wij het pro forma bezwaar kosteloos in. Gaat het
> hoofdbezwaar door, dan spreken wij vooraf een vergoeding af die u alleen
> betaalt als het bezwaar geld oplevert.

Daar moet het bedrag in, plus de nul-resultaat-regel. In de tarieventabel
staat "Pro forma bezwaar box 3" met €0; daar hoort een tweede regel bij voor
het hoofdbezwaar.

Let ook op de JSON-LD op die pagina: de `OfferCatalog` heeft nu alleen een
`Offer` met `price: "0"` voor het pro forma bezwaar. Komt er een percentage,
dan hoort daar geen `price` bij (een percentage is geen prijs in schema.org);
laat dat aanbod dan uit de catalogus in plaats van er een verzonnen bedrag in
te zetten.

### 2. `/diensten/box-3-bezwaar/`

Elf vermeldingen. De belangrijkste plekken:

| regel | wat er staat |
|---|---|
| 219 | `* No cure no pay: u betaalt alleen een vergoeding als het bezwaar daadwerkelijk geld oplevert.` |
| 302 | dezelfde belofte, in de prijssectie |
| 330 | `pro forma kosteloos · hoofdbezwaar op no cure no pay` |
| 412 | het FAQ-antwoord "Wat kost het mij?" |
| 513 | hetzelfde antwoord in de `FAQPage` JSON-LD |

Regel 412 en 513 moeten **gelijk blijven aan elkaar**. Google leest de
JSON-LD; staat daar een ander antwoord dan op de pagina, dan is dat een
overtreding van de richtlijnen voor gestructureerde data.

### 3. De rest

De overige 38 vermeldingen staan op de plaatspagina's, de homepage, twee
blogartikelen en de Engelse pagina's. Die hoeven het bedrag niet te herhalen —
dat is precies de fout die met `/tarieven/` is opgelost. Ze moeten wel naar
`/tarieven/` of naar `/diensten/box-3-bezwaar/` linken.

Vergeet de Engelse kant niet: `en/index.html`, `en/services/box-3-objection/`
en `en/zaandam/`.

---

## Controleren na de wijziging

```bash
node scripts/crawl-audit.js        # 95 pagina's, 404:0
node scripts/check-contrast.js
grep -rc "no cure no pay" --include=index.html . | grep -v ":0$"
```

En met de hand: staat het bedrag op `/tarieven/` en op
`/diensten/box-3-bezwaar/`, en zegt allebei wat er gebeurt als er geen
resultaat is?

---

**Let op:** de rest van `docs/` staat in `.gitignore` en de repo op GitHub is
publiek. Dit bestand is de uitzondering, juist zodat het niet zoekraakt. Zet er
dus geen cijfers, klantgegevens of concurrentieanalyse in; die horen in de
bestanden die genegeerd blijven.

`docs/TODO-kvk-btw.md` staat er met opzet niet bij: dat bestand beschrijft dat
de inschrijving nog niet rond is, en dat hoort niet op een publieke repo. Het
staat alleen lokaal. Maak daar zelf een kopie van buiten deze map.
