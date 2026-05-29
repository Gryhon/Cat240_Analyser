# CAT240 ASTERIX Radar Video Analyzer

A Python tool that parses PCAP/PCAPNG network captures, decodes ASTERIX CAT240 radar video packets, and visualises radar signals as interactive **PPI** (Plan Position Indicator) and **A-Scope** displays.

> **Development note:** This project was developed and tested on **macOS**. The virtual environment setup script (`enviroment.sh`) is a Bash script and requires a Unix-like shell. On **Windows** you will need to create the virtual environment manually (see below).

> **AI assistance:** This project was built with the help of **[Claude](https://claude.ai)** (Anthropic).

---

## Requirements

- Python 3.13+ (managed via [pyenv](https://github.com/pyenv/pyenv) on macOS/Linux)
- Dependencies: `numpy`, `matplotlib`, `rich`, `fpdf2` (PDF export)

---

## Setup

### macOS / Linux

```bash
# Create virtual environment, install dependencies, activate:
source enviroment.sh

# Force-recreate the environment:
source enviroment.sh --force

# Remove the environment only:
source enviroment.sh --clean
```

### Windows

The Bash setup script does not run on Windows. Create the environment manually:

```bat
python -m venv venv_cat240
venv_cat240\Scripts\activate
pip install -r requirements.txt
```

---

## Programs

### `cat240_analyzer.py` — PPI & A-Scope Visualizer

Decodes a PCAP/PCAPNG recording or a live UDP stream and displays the radar video as a polar PPI image with an interactive A-Scope.

#### Replay a file (time-controlled animation)

```bash
# 1× real-time:
python cat240_analyzer.py --replay Data/recording.pcapng

# 20× faster:
python cat240_analyzer.py --replay Data/recording.pcapng --speed 20

# Loop continuously (PPI cleared on each restart):
python cat240_analyzer.py --replay Data/recording.pcapng --loop --speed 10
```

#### Live UDP reception

```bash
# Interactive configuration prompt:
python cat240_analyzer.py --live

# Direct with port and optional multicast group:
python cat240_analyzer.py --live --port 4379 --multicast 239.0.0.1

# Multicast on a specific interface:
python cat240_analyzer.py --live --port 4379 --multicast 239.0.0.1 --host 192.168.1.10

# From JSON configuration:
python cat240_analyzer.py --config config_live.json
```

#### Configuration from JSON

All options can be specified in a JSON configuration file. Useful for complex or repeated setups:

```bash
# Load configuration from JSON
python cat240_analyzer.py --config my_config.json

# Command-line arguments take precedence over JSON
python cat240_analyzer.py --config my_config.json --speed 20
```

**JSON file format:**

```json
{
  "replay": "Data/recording.pcapng",
  "speed": 1.0,
  "loop": false,
  "stream": null,
  "no_filter": false,
  "log_compress": true,
  "interpolate": false,
  "sweepline": false,
  "waterfall": false
}
```

**Supported keys:**
- **Mode:** `replay` (file path), `live` (boolean)
- **Replay:** `speed` (float), `loop` (boolean), `stream` (IP:PORT or null), `no_filter` (boolean)
- **Live:** `port` (number), `host` (IP address), `multicast` (IP or null)
- **Display:** `log_compress`, `interpolate`, `sweepline`, `waterfall` (all boolean)

See `template.json` (replay) and `config_live.json` (live) for complete examples.

#### Live options

| Option | Description |
|---|---|
| `--port N` | UDP port (default: interactive prompt) |
| `--host IP` | Bind address / interface (default: `0.0.0.0`) |
| `--multicast IP` | Join multicast group (e.g. `239.0.0.1`) |

#### Replay options

| Option | Description |
|---|---|
| `--speed X` | Playback speed multiplier (default: 1.0) |
| `--loop` | Loop continuously; PPI is cleared on each restart |
| `--stream IP:PORT` | Pre-select a UDP stream, skips interactive prompt |
| `--no-filter` | Show all UDP streams for selection, not only detected CAT240 streams |

#### General options

| Option | Description |
|---|---|
| `--log-compress` | Add soft-log overlay to A-Scope (second Y-axis, 0–255) |
| `--interpolate` | Interpolate missing azimuths in gaps (for imperfect network data) |
| `--sweepline` | Show rotating yellow line indicating current azimuth |
| `--waterfall` | Show waterfall display (range vs. azimuth) — useful for spotting azimuth gaps |

#### PPI display

**Window title** shows:
- Message count (`N msgs`)
- Coverage percentage (`XX.X% coverage`) — percentage of azimuths with data
- Range scale resets (if any)

**Buttons:**

| Button | Effect |
|---|---|
| `Pause` / `Play` | Pause or resume replay / live mode |
| `Zoom` | Activate rectangle zoom — drag to select area, releases and applies zoom automatically. Click again to cancel. Cursor changes to crosshair while active. |
| `[ ] A-Scope` / `[A] A-Scope` | Open or close the A-Scope window |
| `Rng` | Toggle A-Scope mode: amplitude vs. range ↔ amplitude vs. angle |

#### PPI / A-Scope interaction

**PPI:**

| Action | Effect |
|---|---|
| Left-click | A-Scope shows amplitude profile at that azimuth |
| Right-click | Toggle A-Scope mode: amplitude vs. range ↔ amplitude vs. angle |
| Scroll wheel | Zoom in / out centred on cursor |
| Double-click | Reset zoom to full range |

**A-Scope:**

| Action | Effect |
|---|---|
| Mouse move | Cursor readout: cell / azimuth and amplitude |
| Left-click | FWHM measurement of nearest peak |
| Left double-click | Reset zoom |
| Scroll wheel | Zoom X-axis centred on cursor |
| Right-drag | Pan X-axis |
| Right-click (azimuth mode) | Start / end manual span selection |
| `-` / `+` buttons | Zoom out / in |
| `<` / `>` buttons | Pan left / right |
| `Lin` / `Log` buttons | Toggle linear / log overlay (only with `--log-compress`) |

#### Azimuth coverage & interpolation

The PPI grid has 4096 azimuth bins covering 360°. Each incoming CAT240 message specifies a **START_AZ** and **END_AZ** azimuth range; the entire range is filled to eliminate artificial gaps.

**Coverage percentage** (displayed in window title) shows what fraction of the 4096 bins contain data:
- **≥99%** — No visible gaps; normal operation
- **95–99%** — Minor gaps possible; usually acceptable  
- **<95%** — Significant data loss in the network stream

Use `--interpolate` to automatically fill gaps with data from the previous revolution. This smooths the image for imperfect network data.

#### Waterfall display

When `--waterfall` is enabled, a second window shows a **range-vs-azimuth** display:
- **X-axis:** Azimuths (0° to 360°)
- **Y-axis:** Range cells (0 to maximum)
- **Echoes:** Colored using the same colormap as the PPI

**Purpose:** Spot missing azimuths (gaps appear as black vertical lines) and verify continuous coverage across the full revolution.

**Buttons:**

| Button | Effect |
|---|---|
| `Pause` / `Play` | Pause or resume playback (synchronized with PPI) |
| `Zoom` | Activate rectangle zoom — drag to select area, click again to cancel |

**Interactions:**
- **Scroll wheel** — Zoom in/out centered on cursor (both axes)
- **Double-click** — Reset zoom to full view

---

### `cat240_stream_info.py` — Stream Statistics & Report

Scans one or more PCAP/PCAPNG files, auto-detects all CAT240 streams and prints detailed statistics (geometry, azimuth step, RPM, cell resolution, amplitude distribution). Also writes a Markdown report. Streams are sorted by source IP. Glob patterns work on all platforms (including Windows).

```bash
# Full analysis (terminal output only):
python cat240_stream_info.py Data/recording.pcapng

# Multiple files / glob pattern:
python cat240_stream_info.py Data/*.pcapng

# Analyse only the first 10 000 UDP packets:
python cat240_stream_info.py Data/recording.pcapng --packets 10000

# Generate Markdown report (default path: <filename>_analysis.md):
python cat240_stream_info.py Data/recording.pcapng --md

# Markdown with custom path:
python cat240_stream_info.py Data/recording.pcapng --md report.md

# Generate PDF report:
python cat240_stream_info.py Data/recording.pcapng --pdf

# PDF with custom path:
python cat240_stream_info.py Data/recording.pcapng --pdf report.pdf

# Both Markdown and PDF in a subdirectory (created if missing):
python cat240_stream_info.py Data/recording.pcapng --md --pdf --output-dir reports/

# Include detailed per-revolution azimuth gap analysis:
python cat240_stream_info.py Data/recording.pcapng --gaps

# Gap analysis combined with PDF export:
python cat240_stream_info.py Data/recording.pcapng --gaps --pdf
```

The report includes per-stream:
- Source IP address(es) and destination IP:port
- Cells per azimuth, bit depth, start cell, compression
- Azimuth step size, azimuths per revolution, RPM
- CELL_DUR raw value with derived range per cell and total range
- SAC / SIC (data source identifier)
- FSPEC breakdown with active UAP items
- Amplitude statistics and distribution histogram

With `--gaps`: detailed per-revolution azimuth gap table (landscape PDF pages), showing the largest gap per revolution, coverage percentage, gap azimuth range, and the messages immediately before and after the gap (VRH, timestamp, azimuth).

### `cat240_split_by_range.py` — Split PCAPNG by Range Scale

Splits a PCAP/PCAPNG file into separate files, one per unique pulse length (CELL_DUR). Useful for isolating streams with different range scales (e.g. near-range, far-range modes) into individual files for separate analysis.

```bash
# Split into separate files by pulse length:
python cat240_split_by_range.py Data/recording.pcapng

# Write split files to a specific directory:
python cat240_split_by_range.py Data/recording.pcapng --output-dir split_files/
```

**Output example:**
- `recording_12nm.pcapng` — Near-range mode (0.1448 µs pulse)
- `recording_41nm.pcapng` — Mid-range mode (0.0618 µs pulse)
- `recording_96nm.pcapng` — Far-range mode (1.1583 µs pulse)

Each output file contains all packets (headers + data) and can be analyzed independently with `cat240_analyzer.py` or `cat240_stream_info.py`.

---

## Specification

The decoder implements **EUROCONTROL-SPEC-0149-240** (*ASTERIX Category 240 — Video Transmission Standard*), edition 1.3.

The specification is freely available from EUROCONTROL:
[https://www.eurocontrol.int/asterix](https://www.eurocontrol.int/asterix)

Direct link to the CAT240 specification document:
[https://www.eurocontrol.int/sites/default/files/2021-09/asterix-cat240-part9-video-transmission-standard-v1.3.pdf](https://www.eurocontrol.int/sites/default/files/2021-09/asterix-cat240-part9-video-transmission-standard-v1.3.pdf)

---

## Project structure

```
cat240_analyzer.py       Main tool: PPI + A-Scope visualiser
cat240_stream_info.py    Stream statistics and report generator
cat240_split_by_range.py Split PCAPNG by pulse length (range scale)
template.json            Template for replay JSON configuration
enviroment.sh            macOS/Linux virtual environment setup (Bash)
requirements.txt         Python dependencies
.python-version          Python version pin for pyenv (3.13.0)
```
