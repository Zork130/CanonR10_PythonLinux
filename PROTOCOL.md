# Canon imageFORMULA R10 protocol notes

Sources: `CaptureOnTouch Lite Launcher` (Mac, from the HFS+ LUN) and
`R10Lite.ds` (Mac TWAIN source, symbols intact), downloaded from the scanner
with `canon_r10.py appfiles`. Decompiled with Ghidra (`tools/DecompileFuncs.java`).

## Transport: files on the FAT LUN
USB 1083:167f exposes LUN0 (vfat "ONTOUCHLITE") and LUN1 (HFS+ Mac launcher).
LUN0 has two 2 MiB files the firmware intercepts:

| file | use |
|---|---|
| `TRANSFER.dat` | command packet @0, status word @24, data-out packet @28 |
| `INDATA.dat`   | data-in, read from offset 0 |

All I/O bypasses the page cache (macOS `F_NOCACHE`, Linux `O_DIRECT`, 512-byte aligned RMW).

Session open: write 2 MiB of zeros to INDATA.dat. Session close: write 512 zero bytes at TRANSFER.dat@0.

Per command:
1. Write the 24-byte command packet at TRANSFER@0:
   `00 00 00 14 | 00 01 90 00 | 00 00 00 00 | CDB padded to 12`
   (the same USB framing SANE `canon_dr` uses).
2. Data-out commands (0x15, 0x1B, 0x24, 0x2A, 0xD6, 0xE1): write the data packet at TRANSFER@28:
   `BE32(len+8) | 00 02 b0 00 | 00 00 00 00 | data`.
3. Write `FF FF FF FF` at TRANSFER@24, then poll it every 100 ms (default timeout 90 s) until it changes.
   The value is a big-endian SCSI status: 0 = good, 2 = CHECK CONDITION, which means send REQUEST SENSE (03, 14 bytes).
4. Data-in: read the requested length from INDATA@0 (max 2 MiB; the driver uses 1 MiB).

## Commands seen (CCanoDR)
| op | name | notes |
|---|---|---|
| 00 | TEST UNIT READY | |
| 03 | REQUEST SENSE | 14 bytes; ILI bit (byte2&0x20) puts the residue in bytes 3–6 |
| 12 | INQUIRY | `12 00 00 00 60 00` gives "CANON R10 2.02", type 0x06 |
| 12 | INQUIRY EVPD F0 | `12 01 f0 00 30 00`: base res @5/@7 (600), max width @20 (5104 px), max length @24 |
| 1B | SCAN | data = list of window IDs (0 / 1; 0xFF/0xFE used during calibration) |
| 24 | SET WINDOW | 8-byte header (bytes 6–7 = 0x002C) + 44-byte descriptor: id, xres@2, yres@4, ulx@6, uly@10, width@14, length@18 (1/1200"), composition@25 (2 gray, 5 RGB), bpp@26 (8), @29 = 0x10 |
| 28 | READ | `28 00 DTC 00 Q4 Q5 LEN24 00`; DTC 00 image, 8B doc status (1 byte, 0/1), 8C counters + serial (0x80), A1 1-byte wait flag |
| 2A | SEND | DTC 8C |
| 31 | OBJECT POSITION | byte1: 1 = load, 0 = unload |
| 3B | READ BUFFER (Canon) | BE32 address @2, BE24 length @6. Memory 0x10700000 holds the app archives; 0x10080000 holds factory shading data (0x80000) |
| C5 | GET SCANNER STATUS | 8 bytes |
| C7 | ERROR CLEAR | |
| D6 | DEFINE SCAN MODE | `d6 10 00 00 14 00` + 20 bytes: [4] page, [5] = 0x0E. Pages: 0x30 double-feed, 0x32 side/buffer ([6] side mode, [7] = 1, [10] flags), 0x36 dropout |
| E1 | SET ADJUST DATA | analog gain/offset during calibration (AdjustLight) |

See [Error codes](#error-codes) for the sense mapping.

## Image data
- DEFINE SCAN MODE 0x32 byte 6 + SCAN ids: `0`+[0] = side A only, `1`+[1] = side B only, `2`+[0,1] = duplex.
  Other combinations give sense 5/1A00.
- Gray 300 dpi: 8-bit, 2552 px/line per side (8.5").
- Duplex: lines hold both sides **pixel-interleaved** (A0 B0 A1 B1 ..., 5104 bytes/line).
- Orientation as received: side A (window 0) is upside down (flip vertically); side B (window 1) is rotated 180°.
  Side B was the first page of the test document fed face-up.
- Duplex returned 3583 lines for an 11.7" request (simplex: exactly 3510).
- Colour (composition 5): 3 bytes/px, line-planar (R row, G row, B row); needs calibration (without it the values are 0–7).
- End of page = READ returns CHECK CONDITION with sense key 0 + ILI, and the residue gives the short count.

## Calibration (ported in canon_r10.py `Calibrator`)
Source: `CCanoDR::AdjustLight` (R10Lite.ds) and `Cei::LLiPm::DRHachi::CAdjustLight` / `CShading` (LLiPmDRP215).
The device scans only at 300 or 600 dpi; the vendor driver rescales other resolutions in software.

Every step is: SET ADJUST DATA (E1, except before the final dark scan), then SET WINDOW per side
(bpp 12, length 9600/dpi in 1/1200" = 8 lines), DEFINE SCAN MODE 0x32 and 0x36, then SCAN with the ids,
then READ (planes × rowbytes × 8, with rowbytes = ((12·W)>>3)+1 & ~1), then OBJECT POSITION 0.
- 12-bit packing: `p0 = b0 | (b1&0xF)<<8`, `p1 = b1>>4 | b2<<4`. Colour is line-planar (R, G, B rows). Duplex pixels are A/B interleaved.
- Window ids: 0xFF = LEDs off (dark), 0xFE = white reference. No paper moves.
- E1 data, 40 bytes = 2 × [gain R,G,B, 0, offset R,G,B, 0, BE16 exposure R,G,B, 6 × 0] (front, back);
  CDB `e1 00 00 00 00 03 00 00 28 00`.

State machine (8 lines averaged to one line, values 0–4095):
0. ids FF, gain 0, offset 0x80: offset -= (0x4F−gain)·(min−96)·1980/(4096·150.48); exposure 0; ids FE
1. record dark levels at exposure 0 (always RGB), then exposure 8191
2. record saturation at 8191, then exposure 200
3. record at 200, then exposure 1500 (300 dpi) or 3500 (600 dpi)
4. record at 1500. T = min(darkmax + (satmin − darkmax)·rate/100, 2593), rate 95 colour / 31 gray.
   Per-colour exposure by linear interpolation between (200, max@200) and (1500, max@1500) to hit T;
   scale down if exposure R > 2500 or G/B > 3000 (doubled at 600 dpi)
5. gain = 0x4F − (0x4F−gain)·max/2730; ids FF
6. offset again; done.
Then a white reference (ids FE) and a dark reference (ids FF) build the shading:
`coef = (T<<12)/(white−black)` (T = 4316 gray; 4306/4317/4349 R/G/B), `out = clamp((pix − black>>4)·coef >> 12)`.

## Card scanning (front card slot) — verified live
Cards go into the front card slot: the clear flap on the right of the paper exit. The scanner pulls the card in slightly and holds it.
After a SCAN it pulls the card through, scans both sides and pushes it back out of the same slot. Paper goes in at the top.
- **Detection:** READ dtc 8B (document ready). Bit 0 = sheet in the paper feeder (paper sensor). Bit 3 = card in the card slot (IR sensor).
  The vendor driver treats `(v & 9) == 8` as card mode. A card in the slot never sets bit 0, and a card in the paper feeder is not seen at all.
- **Scan mode for a card:** DEFINE SCAN MODE page 0x32 = side mode 2 (duplex). The flags byte (page byte 6, our body offset 4) is
  `0x28` (0x20 | 0x08; the vendor also clears buffering 0x40). The driver swaps the front and back settings in page 0x36.
  SET WINDOW is the same as for paper (the scanner stops at the card's trailing edge).
  With flags 0x60 or 0x00 the scan is still accepted. Without a card at bit 3, SCAN fails with 5/3A 00.
- **Timing:** the scanner holds the card for only a short time. SCAN ~0.8–0.9 s after bit 3 appears works. After 4+ s
  (calibrating first) the sensor no longer reports the card and SCAN fails with 5/3A. So calibrate before waiting for the card.
- **A card resting in the slot after being scanned still sets bit 3.** Scanning it again gives a jam (3/80 00, no data).
  canon_r10.py therefore needs the slot to read empty, then a fresh card that stays for 0.8 s.
- **Result:** ~1313 lines at 300 dpi (with the 0.39" lead-in), page info paper_length ≈ 4048–4076/1200" = 3.37–3.40"
  (the card's long side: it travels long edge first, so the image is portrait, 2.2 × 3.4").
- **Crop:** the card is found against the per-column backing level (|pixel − backing| > 16, so dark and light cards both work).
  While a card passes, the strip between the card and the near edge of the scan area reads ~190 against 213 for the empty backing.
  A detected area that touches the image border is therefore moved to the sharpest step (the card edge).
  The card's slant comes from its long side edges.
- canon_r10.py: `--default-card` (colour, both sides, PDF) or `scan --card`; `--card-rotate 90|180|270`.

## Front-sensor shear (measured)
Images from side A (front sensor) are slightly sheared, not just rotated: text lines come out about 0.25–0.40° more tilted
than vertical rules and column edges on the same page (three scans: +0.25/+0.30/+0.40°). Side B shows −0.02 to −0.15°.
Probably the front CIS is not exactly perpendicular to the feed. Straightening therefore measures both directions (projection profile
of horizontal and of vertical structure) and shifts rows by the vertical angle and columns by the horizontal angle.
The second angle is used only when its peak gain is ≥ 1.06 and it is within 0.6° of the first; otherwise one angle is used for both.
Result on the problem page: residual 0.03° (text) / 0.00° (rules), and the paper-edge shadow no longer ends up inside the crop.
Side edges that stay slightly slanted (< 0.1" end to end) are cropped at their inner point.

## Factory light-curve correction (ported)
After the white/black references, the vendor reads 0x80000 bytes at 0x10080000 (READ BUFFER 0x3B) and runs
`AdjustLightFix` → `CSpecialFilter::makeShadingData` → `CAdjustLight::AdjustLightCurve` →
`CLightCurveAdjustData::LoadData/AdjustData` (LLiPmDRP215). Layout (little-endian):
- header: u32 timestamp (Unix; this unit: 2022-07-26), u32 0, u32 record count (12). First word FFFFFFFF = no data.
- record: u16 header_len (34), u16 side (0 front / 1 back), u16 planes (1 gray / 3 RGB), u16 bits (16),
  u32 divisor (4096), u32 width (2552 / 5104), u32 plane_bytes, u32 data_bytes, u16 dpi, u16 per_plane (1),
  u32 flags (bit0 = valid), u8 colour-dropout, u8 emphasis; then data_bytes of u16 per-pixel values.
  Records are front/back × gray/RGB × 300/600 dpi, plus a gray "emphasis" variant (byte 33 = 1) used only with
  colour dropout/emphasis options (tables at 0x9cbc0/0x9cbe0); normal scans use dropout = emphasis = 0.
- Applied per column x and plane: `white'[x] = black[x] + max(0, white[x] − black[x]) · curve[x] / divisor`
  (rounded, clamped to 0xFFFF), before the shading coefficients are computed.
Values are about 5100–5800 (×1.25–1.36, varying up to ~6% across the width). Effect measured on the same sheet: without it
95% of the paper clipped at 255; with it paper sits at about 232 with < 4% clipped, flat to about ±2 levels across the page.
canon_r10.py caches the block per scanner (`<serial>-lightcurve.bin`, re-read when the timestamp changes);
`--no-light-curve` disables it. A dump of this unit's block is in `dump/factory_lightcurve.bin`.

## Colour registration
The CIS lights the R, G and B LEDs in sequence while the paper moves, so in raw line order
R is sampled +1/3 line and B −1/3 line from G. Measured by cross-correlating the plane
profiles: −0.32 / +0.30 lines in the upright image. canon_r10.py resamples R and B by linear
interpolation (`--color-shift`). Defaults: 0.333,−0.333 at 300 dpi (residual < 0.05 lines) and
0.25,−0.25 at 600 dpi (measured residual ±0.08–0.11 with ⅓, ≤ 0.06 with ¼).

## Calibration cache
Results are cached in `~/.cache/canon_r10/<serial>-<mode>-<dpi>-<sides>.json` (register values plus
white/black reference lines). A cached calibration is reused for 300 s (vendor value, R10Lite
`0x41508`) and re-sent with E1 before scanning. Options: `--cal-max-age`, `--recalibrate`.

## Page length, batches, per-sheet info
- Window: uly = −0x1D8 (start 0.39" early, the vendor auto-size overscan) and length = max + 0x3B0.
  The R10 stops by itself about 0.4" after the trailing edge.
- After each sheet the vendor driver reads three 16-byte blocks (four BE32 values each, 1/1200"):
  - `28 00 80 00 00 04 000010 00`: [3] = measured paper length (A4 reads 14112–14124)
    **−1 = no trailing edge seen**: the sheet is longer than the window (max_length 14.14" plus overscan, about 14.5" of
    paper). The R10 then stops the motor with the tail still inside and latches 3/80 00 (paper jam); seen live with a
    long folded leaflet. Canon's app has a "Long Document mode" (strings in R10Lite.ds), not investigated.
  - `28 00 80 00 00 00 000010 00`: the scan window actually used (0, uly, width, length)
  - `28 00 80 00 00 01 000010 00`: (0, ~440, 0, 464), per-side leading-edge offsets
- Between sheets: poll `READ dtc A1` (1 byte) until it is non-zero. The next READ then fails with 5/2C00
  until a new SCAN is sent: **each sheet needs its own SCAN**. The feeder takes one sheet at a time.

## Paper alignment (software)
- Skew from content: projection profile of the ink pixels (dark ones, or light ones on mostly dark pages) in both
  orientations (horizontal and sideways text), keeping whichever has the sharper peak; ±5° coarse, then 0.025° fine. It falls back to
  edge-shadow lines on near-blank pages. Deskew = row shear plus column shear (nearest pixel).
- Only edges facing away from the light cast a shadow: side A shows right+top, side B shows bottom.
  Edges are accepted only as RANSAC lines covering ≥ 50% (vertical) / 35% (horizontal) of the page.
  A missing side edge comes from the extent of the top/bottom shadow; the missing horizontal edge is
  the visible one ± the measured paper length. A detected opposite edge is kept when it agrees with the measured
  length to 0.15". Each edge is taken at its outermost point (hand-folded sheets are not exactly rectangular), and the
  inward trim stops when the edge profile flattens, so dark paper doesn't lose 40 px per edge.
- With the factory light curve the backing reads about 210 (paper about 232) instead of clipping at 255. Edge finding runs on a
  copy scaled by 262/backing (backing taken as the darker of the top/bottom overscan-strip medians), which
  restores the clipped backing the shadow detector was tuned on. Crops get an extra 0.01" trim on each side.

## 600 dpi
Calibration uses exposure 3500 at state 3 and limits 5000/6000 (both from the vendor code) and converges like 300 dpi.
Throughput per duplex sheet: gray about 18 s / 300 MB RSS; colour about 56 s / 710 MB RSS (pure-Python processing).
The alignment geometry (edge bands, tolerances, insets) scales with dpi.

## Text clarity (software)
After shading, ink only reaches about 80–100 and edges are soft (CIS optics). The vendor driver applies gamma/contrast
tables and optional edge emphasis (`_MakeGammaTable`, `sContrastTable`, `cf_EmphasisEdge`, not ported).
canon_r10.py instead applies levels (auto black point = darkest 0.3% − 10, capped at 110; auto white point = paper
median − 2·(median − lower quartile), within 200–250) and then an
unsharp mask (box radius 1 / amount 0.75 at 300 dpi, radius 2 / amount 0.4 at 600 dpi; gentler at 600 because it
otherwise brings out halftone grain). On a 300 dpi text sample, mean ink went from 65 to 36 and the soft edge pixels dropped by 37%.
Colour: once highlights stopped clipping (factory light curve), per-channel sensor noise showed as pink/cyan
specks on white paper. Before sharpening, R−G and B−G are box-smoothed over 5×5 (`--chroma-denoise 2`) only where
that local mean difference is ≤ 12 (near-neutral areas), so printed colour and halftones are untouched. Measured:
tinted paper pixels 0.066% → 0.003%, with the mean of a printed orange unchanged (255,150,32 vs 255,151,33 unsharpened).
Sharpening brightness only was tried and rejected: it pulled saturated colours down (R 255 → 241).
Cost: about 0.2 s per 300 dpi gray page, about 3 s per 600 dpi colour page. Options: `--no-enhance`, `--sharpen`,
`--black-point`, `--white-point`, `--gamma`.

## Black-and-white mode (software)
`--mode bw` scans in gray (and shares the gray calibration), applies the text-clarity steps, then thresholds at 170
(`--threshold`). 128 breaks up grey/halftone headings and 192 picks up paper specks. Isolated single black
pixels are then removed (bitwise on packed rows; `--no-despeckle`). Output is packed 1-bit
(1 = white; PNG bit depth 1, PDF `/BitsPerComponent 1`, Flate): about 0.14 MB per 300 dpi A4 page versus about 1.3 MB gray.
Photos and halftone logos lose detail; the vendor's error-diffusion mode is not implemented.

## Blank-page skip and automatic colour/gray (software)
- `--skip-blank`: computed before contrast stretching (which would turn show-through into "ink"). Percent of interior
  pixels (0.25" inset) darker than 0.35 × paper level (75th percentile), blank below `--blank-threshold` 0.005%.
  Measured: blank back with heavy show-through and translucent grease spots 0.0001%; text pages 5–7%; dark
  leaflet 8–58%. A page carrying only a page number is about 0.01%.
- `--mode auto`: scans and calibrates in colour, then measures colour on 6×6 px block means after enhancement
  (averaging cancels the alternating red/blue fringes at black-text edges). Spread > 36 counts as a colour block.
  Below `--colour-threshold` 0.25% of blocks, the side is saved as gray (Rec.601 luma).
  Measured: black-text page 0.000–0.001%, blank-with-show-through 0.049%, insurance-letter page with only teal headings 0.96%,
  logo page 1.6%, LEGO leaflet 3.7–33%.

## Long document mode (stored setting)
Canon's maintenance panel item "Maximum length for paper size" (Standard 356 mm, Long Document 1,000 mm / 3,000 mm) is a
**persistent scanner setting**, not a per-scan flag (`CCanoDR::SetMaxScanLength`, `DRUIController::changeMaxScanLength:`):
- READ `28 00 8c 00 00 01 000080 00` (0x80 bytes); the BE32 at offset 0x10 is the maximum length in **micrometres**
  (factory value 355600 = 14.0"; the app writes 355600 / 1000000 / 3000000).
- Write it back with SEND `2a 00 8c 00 00 01 000080 00` + the 0x80-byte block (data-out packet as usual).
- INQUIRY EVPD F0 max_length follows immediately (8484 → 23858 @600 dpi = 39.76" for 1,000 mm), so window
  sizing from max_length picks it up with no other changes. Verified live: a 15.65" leaflet scanned complete
  (it previously stopped at about 14.5" with jam 3/80 00 and paper_length −1).
- Vendor caveats: feed long sheets straight and by hand; jam detection is delayed.
- **Gray scans in long document mode come back stretched ~3× vertically** (nine A4 sheets: 3.02–3.05×, including the
  lead-in overscan), presumably because the motor runs at colour speed (one exposure per line instead of three).
  Colour scans in the same mode are normal. canon_r10.py compares lines received with the scanner's measured
  paper_length (+ 0x1D8 overscan, + ~20 trailing lines). When the ratio is near 2, 3 or 4 (±0.3), it averages that many lines into
  one before any other processing. Normal scans give a ratio of 1 and are untouched.
canon_r10.py: `max-length [standard|1000|3000]`. The original block of this unit is saved in `dump/dtc8c_q01_before.bin`.

## PDF output (software)
Streaming writer: one image XObject per page with the MediaBox from dpi. Gray and black-and-white pages use Flate
(B&W is 1-bit). Colour pages use JPEG (`/DCTDecode`, `--jpeg-quality` default 85, 0 = lossless). The encoder is Pillow
if importable, else `cjpeg` on PATH (fed a PPM on stdin; NixOS: `nix shell nixpkgs#libjpeg_turbo`), else lossless with
a notice. Measured at q85: 600 dpi colour leaflet 93.9 → 14.3 MB; insurance-letter colour pages 9.4 → 3.4 MB (2.5 MB at q75);
text shows no visible artefacts at 2× zoom.

## Scanner button
Vendor status "OperationpanelEZKeyStatus" (`CCanoDR::GetStatus`): READ `28 00 84 00 00 00 000008 00`.
Byte 0 bit 7 = the R10's button (vendor key 1; bits 6 and 2 are keys 2 and 3, unused).
**Verified live**: the bit is set only while the button is held (about 0.2 s per press) and is not latched, so poll
every ≤ 100 ms. Idle reply: `00 00 00 01 00 00 00 15`. The vendor polls it during scanning to abort a
batch (`SetEzKeyAbort`). canon_r10.py: a press while waiting for the next sheet ends the batch. GET SCANNER STATUS (C5, 8 bytes) is decoded by the driver as byte0 bit2 / bit0,
but here it returned the same bytes as the preceding READ (possibly stale INDATA), so it is not used.

## Error codes
A failed command returns status 2 (CHECK CONDITION). REQUEST SENSE (`03 00 00 00 0e 00`, 14 bytes,
fixed format) then gives key = byte2 & 0x0F, ASC = byte12, ASCQ = byte13.
The driver maps sense → internal code (`CCanoDR::DecodeSense`) → message (`CCanoDRDS::ShowAlert`,
English `Localizable.strings` in R10Lite.ds). canon_r10.py prints the same messages (`SENSE_MESSAGES`).

| sense key/ASC ASCQ | driver code | message (vendor) | notes |
|---|---|---|---|
| 0/— | 0 | — (no error) | key 0 + ILI = normal end of page; the residue is in bytes 3–6 |
| 2/any | 0x10000 | Scanner is not ready. (Power may have been cycled.) | |
| 3/3A 00 | 0x20000 | No page was found in the feeder | also 5/3A 00 |
| 3/80 00 | 0x30000 | Paper jammed in scanner. Clear paper and continue. | |
| 3/80 01 | 0x40000 | Scanner cover is open. Close the Scanner cover. | **verified live**: every command except TEST UNIT READY fails with it, including READ 8B (doc ready) |
| 3/81 01 | 0x50000 | A double paper-feed has occurred. | needs DEFINE SCAN MODE 0x30 detection on |
| 3/60 00 | 0x60000 | Lamp error | |
| 3/other | 0xF0000 | Unknown error (power-cycle) | |
| 4/any | 0x70000 | Scanner hardware problem. Power off and on. | |
| 5/2C 00 | 0xB0000 | Scanner command invalid in current state. | seen when READ is sent after a sheet without a new SCAN |
| 5/55 00 | 0xC0000 | Scanner out of memory. | |
| 5/other | 0x80000 | Illegal request | seen as 5/1A 00 for an invalid side-mode / window-id combination |
| 6/29 00 | 0x10000 | Not ready (power cycled) | UNIT ATTENTION after reset or reconnect; retried automatically |
| B/80 00 | 0xA0000 | Scanner timed out, check paper feeder. | |
| other | 0xF0000 | Unknown error | |

Host-side codes in ShowAlert: 2 = out of memory, 0x100 = device not found, 0x400000 / 0x800000 = no page
dialogs, 0x40000000 = cancelled. TEST UNIT READY returns good even with the cover open, so test the
feeder with READ 8B (or REQUEST SENSE after it).

## Button cancel during a sheet (verified live)
The vendor driver polls the panel key (READ dtc 84) between 1 MB image READs, at intervals. When the key is down it stops reading and sends
OBJECT POSITION unload `31 00 …` (eject), then in batch mode STOP BATCH `D8 00 00 00 00 00 00 00 00 00`. Both return GOOD.
Afterwards TEST UNIT READY is clean and no sense is pending. canon_r10.py polls every 0.3 s while reading, discards the partial sheet
and finishes the batch (`--no-button-cancel` disables this).

## Other resolutions and dithered B&W (software, verified live)
The scanner only scans at 300 or 600 dpi (base 600). `--dpi N` (50–1200) scans at 300 (N ≤ 300) or 600 and resamples after enhancement.
Shrinking by 2× or more is done first by 2×2 box averaging (keeps thin strokes), then bilinear.
The ratio is used as an exact fraction, so each output column phase is a strided slice; ratios whose repeat exceeds 16 pixels are refused (e.g. 299).
An A4 side takes 0.06 s for 300→200 and 0.8 s for 600→1200, matching a reference bilinear to ±1.
The PDF page size uses the output dpi. `--dither` replaces the bw threshold with serpentine Floyd–Steinberg error diffusion
(~1.7 s per A4 side at 300 dpi); despeckle is skipped for dithered pages.

## TODO
Features
- Double-feed detection (DEFINE SCAN MODE page 0x30; sense 3/81 01 is already decoded).
- Searchable PDF: not needed here (OCR is done downstream, after the PDFs are imported into Paperless-ngx).
- Roller/pad counters (READ dtc 8C) and counter reset.

Quality / speed
- Gray LED exposure uses the 31% rate path rather than the vendor "BunZGray" register routine.
- Rotation uses nearest-pixel shears (fine for documents; slight stair-stepping on photos).
- Pure-Python processing: 600 dpi colour duplex takes about 56 s and 700 MB per sheet; optional numpy path.

Usability
- Volume auto-mount is done (finds CANON/R10 in /sys/block, mounts or remounts it read-write via udisksctl).
  Not tested: hot-plugging during a run, or two R10s attached at once (it uses the first one found).

Untested live
- Final alignment changes (sideways and white-on-black text, non-square sheets) were checked offline only.
- 0.01" crop trim; the long-sheet jam warning; 600 dpi with the factory light curve; colour chroma denoise on a fresh scan.
- Error codes other than cover open (3/80 01) and jam (3/80 00) were taken from vendor code only.
- tools/decode_bot.py was never run on a real capture.