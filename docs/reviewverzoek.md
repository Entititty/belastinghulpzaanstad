# Reviewverzoek na afronding

Stuur dit bericht pas als de klus klaar is: de aangifte is ingediend of de
voorlopige teruggave is aangevraagd. Eén keer sturen, niet herinneren.

De link wijst naar `/beoordeling/`. Die pagina staat niet in het menu en
niet in Google (noindex). Zolang `GOOGLE_REVIEW_URL` in `data/bedrijf.json`
leeg is, staat daar geen knop naar Google maar een uitnodiging om via
WhatsApp of e-mail te laten weten hoe het ging. Vul de link in en draai
`node scripts/config-sync.js`; dan verschijnt de knop.

Zo vind je de link: in je Google Bedrijfsprofiel, onder "Reviews vragen" of
"Profiel delen". Hij ziet eruit als `https://g.page/r/.../review`.

## Het bericht

```
Beste [naam],

Dank u wel dat ik u mocht helpen met [uw aangifte / uw voorlopige
teruggave / uw toeslag]. Ik ben dit jaar begonnen en bouw alleen echte
reviews op. Zou u in een paar zinnen willen vertellen hoe het ging?
Dat kan via deze link:

https://belastinghulpzaanstad.nl/beoordeling/

Het is natuurlijk vrijwillig, en kritiek mag ook.

Met vriendelijke groet,
Stan van der Hoeven
Belastinghulp Zaanstad
```

## Wat wel en niet mag

- Vraag het iedere klant op dezelfde manier, ook als je twijfelt of die
  tevreden is. Alleen tevreden klanten vragen heet review gating; Google
  staat dat niet toe.
- Geef niets in ruil voor een review: geen korting, geen cadeaubon. De
  €20-startkorting staat daar los van en geldt voor iedere nieuwe klant
  in 2026, met of zonder review.
- Schrijf nooit zelf een review en laat geen familie of vrienden reviews
  schrijven over werk dat ze niet hebben afgenomen.
- Reageer op elke review, ook op een kritische, kort en vriendelijk.
- Pas als er echte reviews zijn, kan er op de site een `AggregateRating`
  in de JSON-LD komen. Niet eerder, en alleen met de echte aantallen.
