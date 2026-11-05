# Reviewverzoek na afronding

Stuur dit bericht pas als de klus klaar is: de aangifte is ingediend of de
voorlopige teruggave is aangevraagd. Eén keer sturen, niet herinneren.

De link is het korte adres `belastinghulpzaanstad.nl/review`. Dat stuurt
door:

- zolang `GOOGLE_REVIEW_URL` in `data/bedrijf.json` leeg is: naar
  `/beoordeling/`, met een uitnodiging om via WhatsApp of e-mail te laten
  weten hoe het ging;
- zodra de link is ingevuld: rechtstreeks naar het reviewformulier van
  Google. `/beoordeling/` krijgt dan ook een knop naar Google.

Invullen: zet de link in `GOOGLE_REVIEW_URL` en draai `node scripts/bouw.js`.
U hoeft het bericht hieronder daarna niet aan te passen.

Zo vindt u de link: in uw Google-bedrijfsprofiel, onder "Reviews vragen" of
"Profiel delen". Hij ziet eruit als `https://g.page/r/.../review`.

## Het bericht (WhatsApp)

```
Beste [naam],

Dank u wel dat ik u mocht helpen met [uw aangifte / uw voorlopige
teruggave / uw toeslag].

Ik ben dit jaar begonnen en bouw alleen echte reviews op. Wilt u in een
paar zinnen vertellen hoe het ging? Dat kan hier:
belastinghulpzaanstad.nl/review

Het is vrijwillig, en kritiek mag ook.

Met vriendelijke groet,
Stan van der Hoeven
Belastinghulp Zaanstad
```

## Wat wel en niet mag

- Vraag het iedere klant op dezelfde manier, ook als u twijfelt of die
  tevreden is. Alleen tevreden klanten vragen heet review gating; Google
  staat dat niet toe.
- Geef niets in ruil voor een review: geen korting, geen cadeaubon. De
  startkorting staat daar los van en geldt voor iedere nieuwe klant, met of
  zonder review.
- Schrijf nooit zelf een review en laat geen familie of vrienden reviews
  schrijven over werk dat ze niet hebben afgenomen.
- Reageer op elke review, ook op een kritische, kort en vriendelijk.
- Pas als er echte reviews zijn, kan er op de site een `AggregateRating`
  in de JSON-LD komen. Niet eerder, en alleen met de echte aantallen.
