# canon_r10 — Linux driver for the Canon imageFORMULA R10

A single-file, dependency-free Python script that drives the **Canon imageFORMULA R10**
portable document scanner on Linux and saves scans as PDF or PNG.

Canon only supports Windows and macOS for the R10, through the *CaptureOnTouch Lite* app that
the scanner carries on its own built-in drive. This project talks to the scanner directly:
no Canon software, no SANE backend, no kernel driver and no root.

> ## ⚠️ Built with AI
> This project was **written with an AI assistant**: Anthropic's Claude, working in Claude Code.
> The AI reverse-engineered the protocol from Canon's own app, wrote the code and documentation,
> and tested them on a real scanner with a human operator feeding paper.
>
> It is an **unofficial** project, not affiliated with or endorsed by Canon. It works on the
> author's scanner, but expect rough edges. Read the code before trusting it with anything
> important, and keep the originals of documents you care about.

## Features

- **Duplex** (both sides in one pass), **colour**, **gray** and **black-and-white**
- **Presets** for everyday use: scan into one PDF while you hand-feed sheets, and press the
  scanner's button to finish
- **Automatic clean-up:**
  - deskew and crop to the paper;
  - Canon's factory light correction and calibration (cached);
  - auto levels, sharpening and colour-speck removal;
  - blank-page skipping;
  - automatic colour or gray per page.
- **PDF output**, with JPEG for colour pages when an encoder is available and lossless otherwise
- **ID / bank cards** through the front card slot, cropped to the card
- **Long documents** up to 1 m or 3 m (long document mode)
- **Any output resolution** from 50 to 1200 dpi (the scanner itself does 300 or 600 dpi),
  plus dithered black-and-white for photos
- **Scanner button:** finishes a batch, or cancels and ejects the sheet being scanned
- **Readable error messages** for paper jams, cover open, no paper and so on
- **Auto-detects and mounts** the scanner's drive

## Requirements

| | |
|---|---|
| OS | Linux (developed on NixOS; any distribution should work) |
| Python | 3.11 or newer, **standard library only** |
| udisks2 | `udisksctl`, used to auto-mount the scanner's drive; present on most desktops |
| Scanner | Canon imageFORMULA R10 (USB ID `1083:167f`), connected by USB |
| Optional | **Pillow** (`pip install pillow`) or **`cjpeg`** from libjpeg-turbo, to store colour pages in the PDF as JPEG. Without either, colour pages are lossless and the files are several times bigger. |

No root is needed. The scanner appears as a USB drive called **ONTOUCHLITE**, and the script mounts
it as your user through udisks. If auto-mounting is disabled on your system, mount the drive yourself
and pass its path with `--volume /path/to/ONTOUCHLITE`.

On NixOS, for JPEG support: `nix shell nixpkgs#libjpeg_turbo` (puts `cjpeg` on PATH).

## Quick start

Plug in the scanner, open its feeder, and run:

```sh
python3 canon_r10.py --default-col          # colour documents
python3 canon_r10.py --default-bw           # black-and-white text documents
python3 canon_r10.py --default-card         # ID / bank cards
```

Each preset:
1. waits for you to feed the first sheet;
2. scans both sides of every sheet as you feed it;
3. finishes when you press the **scanner button** (Ctrl-C also finishes and saves);
4. writes one PDF called `scan-YYYYmmdd-HHMMSS.pdf` in the current folder.

## Common commands

```sh
# Save into a folder (timestamped name) or to a named file
python3 canon_r10.py --default-col -o ~/scans/
python3 canon_r10.py --default-bw  -o ~/scans/electric-bill.pdf

# Smaller files: lower resolution
python3 canon_r10.py --default-bw  --dpi 200
python3 canon_r10.py --default-col --dpi 150

# Black and white, but keep photos/shading as dot patterns (dithering)
python3 canon_r10.py --default-bw --dither

# Keep blank sides (presets skip them by default)
python3 canon_r10.py --default-col --keep-blank

# Higher quality (600 dpi scan)
python3 canon_r10.py --default-col --dpi 600

# Cards: turn them landscape
python3 canon_r10.py --default-card --card-rotate 90

# Long sheets (receipts, leaflets over 14"): switch the scanner to long mode,
# scan, then switch back (the setting is stored in the scanner)
python3 canon_r10.py max-length 1000
python3 canon_r10.py --default-col
python3 canon_r10.py max-length standard

# One-off scan with full control, one PNG per side in ./scans/
python3 canon_r10.py scan --duplex --mode color --dpi 300

# Scanner information / wait for the button in your own scripts
python3 canon_r10.py info
python3 canon_r10.py button --loop

# Every option, with the recommended settings explained
python3 canon_r10.py --help
python3 canon_r10.py scan --help
```

## Using the scanner

- **Paper:** feed sheets into the top feeder one at a time. The script waits for each sheet to
  settle before scanning it, then waits for the next one.
- **Button:** pressing it between sheets **finishes** the batch and saves the PDF. Pressing it
  while a sheet is going through **cancels** that sheet: it is ejected and not saved, and the
  batch finishes with the sheets before it.
- **Cards:** push the card into the **front card slot** (the clear flap at the front right). The
  scanner pulls it in, scans both sides and pushes it back out. Take it out before pushing in the next card.
- **Errors:** jams, an open cover, and no paper are reported in plain words, with what to do next.
  A sheet over 14" stops with a warning that suggests long document mode.

## Image settings (on by default)

| Setting | Default | Turn off / change |
|---|---|---|
| Factory light-curve correction | on | `--no-light-curve` |
| Deskew and crop to the paper | on | `--no-align` |
| Auto black/white levels | per page | `--black-point`, `--white-point`, `--gamma` |
| Sharpening | 0.75 (300 dpi), 0.4 (600 dpi) | `--sharpen N` (0 = off) |
| Colour-speck removal | radius 2 | `--chroma-denoise 0` |
| All of the above | | `--no-enhance` |
| B&W threshold | 170, with speck removal | `--threshold N`, `--no-despeckle`, `--dither` |
| JPEG quality (colour) | 85 | `--jpeg-quality Q` |

## Files

| File | What it is |
|---|---|
| `canon_r10.py` | the driver and command-line tool (stdlib only, single file) |
| `PROTOCOL.md` | everything learned about the R10 protocol: the file-based transport, commands, calibration, sensors, error codes and measurements |

## How it works (short version)

The R10 is a USB **mass-storage** device. Its drive has two special 2 MiB files, `TRANSFER.dat` and
`INDATA.dat`, which the scanner's firmware intercepts:
- **Commands:** SCSI-style commands are written into `TRANSFER.dat`.
- **Data back:** image data and replies are read from `INDATA.dat`.

Both use direct I/O, bypassing the page cache. The command set is close to that of Canon's other
document scanners (the SANE `canon_dr` family). Calibration, the light curve, page geometry and
the image clean-up are ports or re-implementations of what Canon's own app does. See `PROTOCOL.md`
for the details.

## Known limitations

- **Speed:** processing is pure Python. At 300 dpi a duplex sheet takes a few seconds, but 600 dpi colour
  is slow (about a minute per sheet).
- **Tested hardware:** only on one R10, one Linux machine, with hand-fed sheets.
- **No double-feed detection:** it isn't enabled yet.
- **Wrong page size in long mode:** long document mode makes gray scans come back stretched. The script
  corrects this, but use `max-length standard` unless you need long sheets.
- **Not yet confirmed on the scanner:** some error codes are taken from Canon's driver code
  and haven't been seen on the real scanner.

## Licence and disclaimer

Provided as-is, with no warranty. Canon, imageFORMULA and CaptureOnTouch are trademarks of Canon Inc.
This project contains no Canon code or firmware: Canon's app was only studied to understand the protocol.
