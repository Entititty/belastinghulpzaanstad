# og-toeslagen.ps1
# Genereert og/og-toeslagen.png, 1200x630, in dezelfde stijl als de andere
# og-afbeeldingen. Alle maten en kleuren zijn uit og-huurtoeslag-berekenen.png
# gemeten, niet geraden.
#
# Lettertypen: de site gebruikt Source Serif 4 en Nunito Sans, maar die zijn
# alleen als woff2 aanwezig en System.Drawing kan die niet laden. Georgia is
# de fallback die de site zelf declareert (--font-display: 'Source Serif 4',
# Georgia, serif), dus dat is de dichtstbijzijnde keuze die hier kan.

Add-Type -AssemblyName System.Drawing

$W = 1200
$H = 630

# --- gemeten kleuren ---
$cCreme   = [System.Drawing.Color]::FromArgb(255, 0xfa, 0xf8, 0xf4)
$cGloed   = [System.Drawing.Color]::FromArgb(255, 0xeb, 0xf1, 0xec)
$cGloed0  = [System.Drawing.Color]::FromArgb(0,   0xfa, 0xf8, 0xf4)
$cTeal    = [System.Drawing.Color]::FromArgb(255, 0x1a, 0x8a, 0x7d)
$cOranje  = [System.Drawing.Color]::FromArgb(255, 0xe0, 0x7a, 0x2f)
$cPilLicht= [System.Drawing.Color]::FromArgb(255, 0xe6, 0xf5, 0xf3)
$cDonker  = [System.Drawing.Color]::FromArgb(255, 0x2c, 0x25, 0x20)
$cBark    = [System.Drawing.Color]::FromArgb(255, 0x6b, 0x5e, 0x50)
$cWit     = [System.Drawing.Color]::White

$bmp = New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

# --- achtergrond ---
$g.Clear($cCreme)

# radiale gloed uit de rechterbovenhoek
$r = 560
$pad = New-Object System.Drawing.Drawing2D.GraphicsPath
$pad.AddEllipse(($W - $r), (-$r), ($r * 2), ($r * 2))
$gloed = New-Object System.Drawing.Drawing2D.PathGradientBrush($pad)
$gloed.CenterColor = $cGloed
$gloed.SurroundColors = @($cGloed0)
$gloed.FocusScales = New-Object System.Drawing.PointF(0.5, 0.5)
$g.FillPath($gloed, $pad)
$gloed.Dispose(); $pad.Dispose()

# linkerbalk, 14px
$brTeal = New-Object System.Drawing.SolidBrush($cTeal)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::None
$g.FillRectangle($brTeal, 0, 0, 14, $H)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# --- hulpfunctie: afgeronde rechthoek ---
function New-RoundedPath([int]$x, [int]$y, [int]$w, [int]$h, [int]$rad) {
  $p = New-Object System.Drawing.Drawing2D.GraphicsPath
  $d = $rad * 2
  $p.AddArc($x, $y, $d, $d, 180, 90)
  $p.AddArc(($x + $w - $d), $y, $d, $d, 270, 90)
  $p.AddArc(($x + $w - $d), ($y + $h - $d), $d, $d, 0, 90)
  $p.AddArc($x, ($y + $h - $d), $d, $d, 90, 90)
  $p.CloseFigure()
  return $p
}

# --- lettertypen ---
$fSerifKop   = New-Object System.Drawing.Font('Georgia', 62, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fSerifMerk  = New-Object System.Drawing.Font('Georgia', 33, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fLogo       = New-Object System.Drawing.Font('Georgia', 30, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fEyebrow    = New-Object System.Drawing.Font('Segoe UI', 23, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fSub        = New-Object System.Drawing.Font('Segoe UI', 25, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$fPil        = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fUrl        = New-Object System.Drawing.Font('Segoe UI', 23, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
$fPilOranje  = New-Object System.Drawing.Font('Segoe UI', 26, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)

$brDonker = New-Object System.Drawing.SolidBrush($cDonker)
$brBark   = New-Object System.Drawing.SolidBrush($cBark)
$brWit    = New-Object System.Drawing.SolidBrush($cWit)
$brOranje = New-Object System.Drawing.SolidBrush($cOranje)
$brPil    = New-Object System.Drawing.SolidBrush($cPilLicht)

$sf = New-Object System.Drawing.StringFormat
$sf.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap
$sfMidden = New-Object System.Drawing.StringFormat
$sfMidden.Alignment = [System.Drawing.StringAlignment]::Center
$sfMidden.LineAlignment = [System.Drawing.StringAlignment]::Center

# --- logo-vierkant + BZ ---
$logo = New-RoundedPath 82 70 71 74 16
$g.FillPath($brTeal, $logo); $logo.Dispose()
$g.DrawString('BZ', $fLogo, $brWit, (New-Object System.Drawing.RectangleF(82, 70, 71, 74)), $sfMidden)

# --- merknaam ---
$g.DrawString('Belastinghulp Zaanstad', $fSerifMerk, $brDonker, 168, 89, $sf)

# --- oranje pil rechtsboven ---
$pilTekst = 'vanaf 30'
$pilTekst = [char]0x20AC + '30'   # euro-teken + 30
$maat = $g.MeasureString($pilTekst, $fPilOranje)
$pilW = [int]$maat.Width + 56
if ($pilW -lt 110) { $pilW = 110 }
$pilX = 1129 - $pilW
$pilPad = New-RoundedPath $pilX 64 $pilW 66 33
$g.FillPath($brOranje, $pilPad); $pilPad.Dispose()
$g.DrawString($pilTekst, $fPilOranje, $brWit, (New-Object System.Drawing.RectangleF($pilX, 64, $pilW, 66)), $sfMidden)

# --- eyebrow met letterspatiering ---
$eyebrow = 'TOESLAGEN 2026'
$brTealTekst = New-Object System.Drawing.SolidBrush($cTeal)
$x = 80.0
foreach ($ch in $eyebrow.ToCharArray()) {
  $s = [string]$ch
  $g.DrawString($s, $fEyebrow, $brTealTekst, $x, 212, $sf)
  $w = $g.MeasureString($s, $fEyebrow, 0, $sf).Width
  if ($s -eq ' ') { $x += 10 } else { $x += $w - 4.0 }
}

# --- kop: donker deel + teal deel ---
$kop1 = 'Toeslagen '
$kop2 = 'aanvragen'
$g.DrawString($kop1, $fSerifKop, $brDonker, 80, 265, $sf)
$w1 = $g.MeasureString($kop1, $fSerifKop, 0, $sf).Width
$g.DrawString($kop2, $fSerifKop, $brTealTekst, (80 + $w1 - 10), 265, $sf)

# --- subtekst, twee regels ---
$g.DrawString('Zorgtoeslag, huurtoeslag en kindregelingen. Wij controleren', $fSub, $brBark, 80, 360, $sf)
$g.DrawString('gratis of u iets misloopt.', $fSub, $brBark, 80, 398, $sf)

# --- drie pillen linksonder ---
$pillen = @(('Gratis check'), ('Aanvraag vanaf ' + [char]0x20AC + '30'), ('Aan huis in Zaanstad'))
$px = 80
foreach ($p in $pillen) {
  $tekst = [char]0x2713 + ' ' + $p
  $m = $g.MeasureString($tekst, $fPil, 0, $sf)
  $w = [int]$m.Width + 40
  $pad = New-RoundedPath $px 508 $w 52 26
  $g.FillPath($brPil, $pad); $pad.Dispose()
  $g.DrawString($tekst, $fPil, $brTealTekst, (New-Object System.Drawing.RectangleF($px, 508, $w, 52)), $sfMidden)
  $px += $w + 22
}

# --- url rechtsonder ---
$sfRechts = New-Object System.Drawing.StringFormat
$sfRechts.Alignment = [System.Drawing.StringAlignment]::Far
$sfRechts.LineAlignment = [System.Drawing.StringAlignment]::Center
$g.DrawString('belastinghulpzaanstad.nl', $fUrl, $brDonker, (New-Object System.Drawing.RectangleF(700, 508, 420, 52)), $sfRechts)

# --- opslaan ---
$uit = Join-Path (Get-Location) 'og\og-toeslagen.png'
$g.Dispose()
$bmp.Save($uit, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

$fi = Get-Item $uit
Write-Output ("geschreven: " + $fi.FullName)
Write-Output ("grootte   : " + [math]::Round($fi.Length / 1024, 1) + " KB")
