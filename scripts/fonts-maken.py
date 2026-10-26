#!/usr/bin/env python3
"""
fonts-maken.py
Maakt de twee webfonts van de site uit de originelen van Google Fonts.

WAAROM
De originelen bevatten meer dan de site gebruikt. Source Serif 4 (122 KB) had
gewicht 200-900, maar de site vraagt nooit minder dan 400; die lichte
gewichten gaan eruit. Bij beide lettertypen gaan ook de breuk- en tabelcijfers
eruit (dnom, frac, numr, pnum, tnum), die de CSS nergens aanzet. Resultaat:
107 KB in plaats van 153 KB, bij elk eerste bezoek.

WAAROM NIET KLEINER
Het kan tot 97 KB: de serif op 400-700 en optische grootte 18-60, Nunito Sans
op 400-800. Dan moet fontTools de overgebleven variatiedata herschalen, en dat
rondt af. Het verschil is klein (hooguit 1,44 van 1000 eenheden per em), maar
in de browser genoeg om op 2 van de 210 gemeten pagina-breedtes een regel
anders af te breken. Deze versie snijdt alleen weg wat aan de onderkant van
een as ligt, waar de standaard ook ligt: niets wordt herschaald, de letters en
hun breedtes blijven precies gelijk. Gecontroleerd met schermafbeeldingen en
met de berekende stijl van elk element op alle pagina's.

NAAM
Source Serif 4 valt onder de SIL Open Font License met "Source" als Reserved
Font Name van Adobe. Een aangepaste versie mag die naam niet dragen, dus heet
hij BHZ Serif, ook in de CSS. Het copyright van Adobe blijft in het bestand.
Nunito Sans heeft geen Reserved Font Name en houdt zijn naam. De licentie
staat in fonts/OFL.txt.

GEBRUIK (alleen nodig als er een gewicht of teken bij moet)
  pip install fonttools brotli
  git show 6fcac8d:fonts/source-serif-4.woff2 > source-serif-4.woff2
  git show 6fcac8d:fonts/nunito-sans.woff2 > nunito-sans.woff2
  python scripts/fonts-maken.py source-serif-4.woff2 nunito-sans.woff2 fonts

Verander je de inhoud, geef het bestand dan een nieuwe naam (nginx laat
lettertypen een jaar cachen, zie server-setup/nginx-cache-map.conf): pas NAAM
hieronder aan, en daarna de @font-face en de preload-regels op alle pagina's.
"""
import io
import os
import sys

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer


NAAM = {'serif': 'bhz-serif-2026-10.woff2', 'sans': 'nunito-sans-2026-10.woff2'}


def verklein(pad, limieten, features):
    f = TTFont(pad)
    if limieten:
        # Alleen de onderkant van een as afsnijden, tot aan de standaard: dan
        # hoeft niets herschaald te worden (zie WAAROM NIET KLEINER).
        # optimize=False: de deltas blijven per punt, zonder IUP-benadering.
        f = instancer.instantiateVariableFont(f, limieten, inplace=False, updateFontNames=False, optimize=False)
        # Opslaan en opnieuw inlezen: de subsetter struikelt anders over tabellen
        # die nog half in het geheugen staan (KeyError op een glyphnaam).
        tussen = io.BytesIO()
        f.flavor = None
        f.save(tussen)
        tussen.seek(0)
        f = TTFont(tussen)
    opties = subset.Options()
    opties.layout_features = features
    opties.name_IDs = ['*']
    opties.name_languages = ['*']
    opties.name_legacy = True
    opties.notdef_outline = True
    opties.glyph_names = False
    opties.hinting = True
    opties.legacy_kern = False
    opties.drop_tables = []
    s = subset.Subsetter(opties)
    s.populate(unicodes=f.getBestCmap().keys())
    s.subset(f)
    return f


def zet_namen(f, namen):
    tabel = f['name']
    for plat, enc, taal in {(r.platformID, r.platEncID, r.langID) for r in tabel.names if r.nameID == 1}:
        for naam_id, tekst in namen.items():
            tabel.setName(tekst, naam_id, plat, enc, taal)


def main(bron_serif, bron_sans, doel):
    # De standaard van de serif is gewicht 400; 200-399 gebruikt de site niet.
    serif = verklein(bron_serif, {'wght': (400, 900)},
                     ['ccmp', 'liga', 'locl', 'kern', 'mark', 'mkmk'])
    for r in serif['name'].names:
        if r.nameID in (0, 7, 13, 14):
            continue
        oud = r.toUnicode()
        nieuw = (oud.replace('Source Serif 4', 'BHZ Serif')
                 .replace('SourceSerif4Roman', 'BHZSerif').replace('SourceSerif4', 'BHZSerif'))
        if nieuw != oud:
            r.string = nieuw
    zet_namen(serif, {
        3: '4.004;BHZ;BHZSerif-Regular',
        5: 'Version 4.004;BHZ webfont 2026-10-26',
        13: 'BHZ Serif is een aangepaste versie van Source Serif 4 (Adobe): zonder de gewichten onder 400 '
            'en zonder breuk- en tabelcijfers. Gemaakt voor belastinghulpzaanstad.nl. '
            'This Font Software is licensed under the SIL Open Font License, Version 1.1.',
        14: 'https://openfontlicense.org',
    })
    serif.flavor = 'woff2'
    serif.save(os.path.join(doel, NAAM['serif']))

    # Nunito Sans: de standaard is gewicht 200 en de site gebruikt 400-800, dus
    # elke inperking van de as zou herschalen. Alleen de features gaan eruit.
    sans = verklein(bron_sans, None, ['calt', 'ccmp', 'liga', 'locl', 'kern', 'mark', 'mkmk'])
    zet_namen(sans, {
        13: 'Aangepaste versie van Nunito Sans: zonder breukcijfers. Gemaakt voor belastinghulpzaanstad.nl. '
            'This Font Software is licensed under the SIL Open Font License, Version 1.1.',
        14: 'https://openfontlicense.org',
    })
    sans.flavor = 'woff2'
    sans.save(os.path.join(doel, NAAM['sans']))

    for naam in NAAM.values():
        print('%-28s %6d bytes' % (naam, os.path.getsize(os.path.join(doel, naam))))


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit('gebruik: python scripts/fonts-maken.py <source-serif-4.woff2> <nunito-sans.woff2> <doelmap>')
    main(*sys.argv[1:])
