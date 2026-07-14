# Publicatieschema nieuwe SEO-artikelen (juli 2026)

9 artikelen zijn geschreven. **Artikel 1 staat live.** De andere 8 staan klaar als
concept: het bestand bestaat, maar het is **niet vindbaar** (staat op `noindex`, niet
in de blogindex en niet in de sitemap). Zet er **1 per dag** live volgens onderstaand
schema.

## Wat betekent "live zetten"? (3 handelingen per artikel)

1. **Zet op index** in `blog/<slug>/index.html`:
   - `<meta name="googlebot" content="noindex, follow, max-image-preview:large">`
     → `<meta name="googlebot" content="index, follow, max-snippet:-1, max-image-preview:large">`
   - `<meta name="robots" content="noindex, follow, max-image-preview:large">`
     → `<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1">`
2. **Voeg de kaart toe** aan `blog/index.html` (zie kaart-snippet per artikel hieronder).
3. **Voeg de URL toe** aan `sitemap.xml` (zie sitemap-snippet hieronder) en werk de
   `<lastmod>` van de `/blog/`-regel bij naar de publicatiedatum.

Daarna committen en de site opnieuw deployen.

## Schema

| Dag | Datum | Artikel | Slug | Status |
|-----|-------|---------|------|--------|
| 1 | 2026-07-12 | Hoeveel spaargeld belastingvrij | `hoeveel-spaargeld-belastingvrij` | ✅ LIVE |
| 2 | 2026-07-13 | Belastingaangifte voor 1 april (deadline) | `belastingaangifte-voor-1-april` | ✅ LIVE |
| 3 | 2026-07-14 | Aangifte inkomstenbelasting (complete gids) | `aangifte-inkomstenbelasting` | ✅ LIVE |
| 4 | 2026-07-15 | Uitstel belastingaangifte aanvragen | `uitstel-belastingaangifte-aanvragen` | concept |
| 5 | 2026-07-16 | Huurtoeslag grens 2026 | `huurtoeslag-grens` | concept |
| 6 | 2026-07-17 | Kindgebonden budget | `kindgebonden-budget` | concept |
| 7 | 2026-07-18 | Zorgtoeslag aanvragen (wanneer/hoeveel) | `zorgtoeslag-aanvragen` | concept |
| 8 | 2026-07-19 | Box 3 bezwaar 2026 | `box-3-bezwaar-2026` | concept |
| 9 | 2026-07-20 | Belastingaangifte laten doen (kosten) | `belastingaangifte-laten-doen-kosten` | concept |

---

## Kaart-snippets voor blog/index.html

Plaats elke kaart binnen de aangegeven sectie, in een bestaande `<div class="blog-grid">`.

### Dag 2 — sectie "Deadlines & uitstel 2025"
```html
    <a href="belastingaangifte-voor-1-april/" class="blog-card">
      <div class="blog-card-tag" style="color:#d97706;">Deadline</div>
      <h3>Belastingaangifte 2025: voor wanneer moet het binnen zijn?</h3>
      <p>Uiterlijk 1 mei 2026. Vóór 1 april aangifte = vóór 1 juli bericht. Alle data op een rij.</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

### Dag 3 — sectie "Aftrekposten & aangifte"
```html
    <a href="aangifte-inkomstenbelasting/" class="blog-card">
      <div class="blog-card-tag">Aangifte</div>
      <h3>Aangifte inkomstenbelasting doen: complete gids</h3>
      <p>Wie moet aangifte doen, hoe werkt het stap voor stap en wat zijn box 1, 2 en 3?</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

### Dag 4 — sectie "Deadlines & uitstel 2025"
```html
    <a href="uitstel-belastingaangifte-aanvragen/" class="blog-card">
      <div class="blog-card-tag" style="color:#d97706;">Uitstel</div>
      <h3>Uitstel belastingaangifte aanvragen: zo werkt het</h3>
      <p>Gratis uitstel tot 1 september, of via een adviseur nog langer. Zo regelt u het.</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

### Dag 5 — sectie "Toeslagen & kortingen"
```html
    <a href="huurtoeslag-grens/" class="blog-card">
      <div class="blog-card-tag">Toeslagen</div>
      <h3>Huurtoeslag grens 2026 – inkomen, huur en vermogen</h3>
      <p>De inkomensgrens, huurgrens en vermogensgrens voor huurtoeslag uitgelegd.</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

### Dag 6 — sectie "Toeslagen & kortingen"
```html
    <a href="kindgebonden-budget/" class="blog-card">
      <div class="blog-card-tag">Toeslagen</div>
      <h3>Kindgebonden budget: wat is het en heb je er recht op?</h3>
      <p>Bijdrage in de kosten van kinderen tot 18 jaar. Bedragen 2026 en voorwaarden.</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

### Dag 7 — sectie "Toeslagen & kortingen"
```html
    <a href="zorgtoeslag-aanvragen/" class="blog-card">
      <div class="blog-card-tag">Toeslagen</div>
      <h3>Zorgtoeslag aanvragen: wanneer en hoeveel?</h3>
      <p>Wanneer u zorgtoeslag kunt aanvragen en hoeveel u in 2026 krijgt.</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

### Dag 8 — sectie "Aftrekposten & aangifte"
```html
    <a href="box-3-bezwaar-2026/" class="blog-card">
      <div class="blog-card-tag">Box 3</div>
      <h3>Box 3 bezwaar maken in 2026: hoe en wanneer?</h3>
      <p>Te veel betaald over spaargeld of beleggingen? Zo maakt u bezwaar binnen de termijn.</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

### Dag 9 — sectie "Aftrekposten & aangifte"
```html
    <a href="belastingaangifte-laten-doen-kosten/" class="blog-card">
      <div class="blog-card-tag">Aangifte</div>
      <h3>Belastingaangifte laten doen: wat kost het?</h3>
      <p>Wat het kost, wat u ervoor krijgt en waarom het zich vaak terugverdient.</p>
      <span class="blog-card-link">Lees meer →</span>
    </a>
```

---

## Sitemap-snippets voor sitemap.xml

Plaats bij de andere `/blog/`-regels (vóór de "ENGLISH PAGES"-comment). Gebruik de
publicatiedatum als `<lastmod>`.

```xml
  <url><loc>https://belastinghulpzaanstad.nl/blog/belastingaangifte-voor-1-april/</loc><lastmod>2026-07-13</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://belastinghulpzaanstad.nl/blog/aangifte-inkomstenbelasting/</loc><lastmod>2026-07-14</lastmod><changefreq>yearly</changefreq><priority>0.8</priority></url>
  <url><loc>https://belastinghulpzaanstad.nl/blog/uitstel-belastingaangifte-aanvragen/</loc><lastmod>2026-07-15</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>https://belastinghulpzaanstad.nl/blog/huurtoeslag-grens/</loc><lastmod>2026-07-16</lastmod><changefreq>yearly</changefreq><priority>0.7</priority></url>
  <url><loc>https://belastinghulpzaanstad.nl/blog/kindgebonden-budget/</loc><lastmod>2026-07-17</lastmod><changefreq>yearly</changefreq><priority>0.7</priority></url>
  <url><loc>https://belastinghulpzaanstad.nl/blog/zorgtoeslag-aanvragen/</loc><lastmod>2026-07-18</lastmod><changefreq>yearly</changefreq><priority>0.7</priority></url>
  <url><loc>https://belastinghulpzaanstad.nl/blog/box-3-bezwaar-2026/</loc><lastmod>2026-07-19</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>https://belastinghulpzaanstad.nl/blog/belastingaangifte-laten-doen-kosten/</loc><lastmod>2026-07-20</lastmod><changefreq>yearly</changefreq><priority>0.7</priority></url>
```

---

## Aandachtspunten

- **Bedragen controleren.** De genoemde grenzen/bedragen (heffingsvrij vermogen, toeslaggrenzen,
  huurgrens, box 3-percentages) zijn indicatief voor 2026. Controleer ze vóór publicatie tegen
  belastingdienst.nl / toeslagen.nl en pas zo nodig aan.
- **Nog geen EN-vertaling.** Deze artikelen hebben (nog) geen Engelse versie. De hreflang verwijst
  daarom alleen naar zichzelf (nl + x-default). Maak je later een EN-versie, voeg dan de hreflang-
  `alternate` toe in beide bestanden.
- **Interne links.** De artikelen linken al onderling en naar bestaande artikelen. Als je een concept
  live zet dat naar een nóg niet-live concept linkt, werkt de link pas zodra dat andere artikel ook
  live staat (het bestand bestaat wel, dus de link geeft geen 404).
