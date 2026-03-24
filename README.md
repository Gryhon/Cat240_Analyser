# CAT240 ASTERIX Radar Video Analyzer

A Python tool that parses PCAP/PCAPNG network captures, decodes ASTERIX CAT240 radar video packets, and visualises radar signals as interactive **PPI** (Plan Position Indicator) and **A-Scope** displays.

> **Development note:** This project was developed and tested on **macOS**. The virtual environment setup script (`enviroment.sh`) is a Bash script and requires a Unix-like shell. On **Windows** you will need to create the virtual environment manually (see below).

> **AI assistance:** This project was built with the help of **[Claude](https://claude.ai)** (Anthropic).

---

## Requirements

- Python 3.13+ (managed via [pyenv](https://github.com/pyenv/pyenv) on macOS/Linux)
- Dependencies: `numpy`, `matplotlib`, `rich`

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

Decodes a PCAP/PCAPNG file (or a live UDP stream) and displays the radar video as a polar PPI image with an interactive A-Scope.

#### Analyse a file (static)

```bash
python cat240_analyzer.py --file Data/recording.pcapng
```

If the file contains multiple UDP streams, you will be prompted to select one. You can also pass the stream directly:

```bash
python cat240_analyzer.py --file Data/recording.pcapng --stream 239.0.0.1:4379
```

#### Replay a file (time-controlled animation)

```bash
# 1× real-time:
python cat240_analyzer.py --replay Data/recording.pcapng

# 20× faster:
python cat240_analyzer.py --replay Data/recording.pcapng --speed 20
```

#### Live UDP reception

```bash
# Interactive configuration prompt:
python cat240_analyzer.py --live

# Direct with port and optional multicast group:
python cat240_analyzer.py --live --port 4379 --multicast 239.0.0.1
```

#### Additional options

| Option | Description |
|---|---|
| `--azimuth N` | Initial A-Scope azimuth in degrees (default: 0) |
| `--save FILE.png` | Save PPI as PNG and exit |
| `--no-display` | Decode only, no GUI |
| `--stream IP:PORT` | Pre-select a UDP stream (skip interactive prompt) |
| `--speed X` | Replay speed multiplier (default: 1.0) |

#### PPI / A-Scope interaction

| Action | Effect |
|---|---|
| Left-click in PPI | A-Scope shows amplitude profile at that azimuth |
| Right-click in PPI | Toggle A-Scope mode: amplitude vs. range ↔ amplitude vs. angle |
| Mouse over A-Scope | Measurement cursor with cell number and amplitude |

---

### `cat240_stream_info.py` — Stream Statistics & Report

Scans a PCAP/PCAPNG file, auto-detects all CAT240 streams and prints detailed statistics (geometry, azimuth step, RPM, cell resolution, amplitude distribution). Also writes a Markdown report.

```bash
# Full analysis, auto-generate <filename>_analysis.md:
python cat240_stream_info.py Data/recording.pcapng

# Analyse only the first 10 000 UDP packets:
python cat240_stream_info.py Data/recording.pcapng --packets 10000

# Specify output path for the Markdown report:
python cat240_stream_info.py Data/recording.pcapng --output report.md
```

The report includes per-stream:
- Cells per azimuth, bit depth, start cell, compression
- Azimuth step size, azimuths per revolution, RPM
- CELL_DUR raw value with derived range per cell and total range
- SAC / SIC (data source identifier)
- FSPEC breakdown with active UAP items
- Amplitude statistics and distribution histogram

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
cat240_analyzer.py      Main tool: PPI + A-Scope visualiser
cat240_stream_info.py   Stream statistics and Markdown report generator
enviroment.sh           macOS/Linux virtual environment setup (Bash)
requirements.txt        Python dependencies
.python-version         Python version pin for pyenv (3.13.0)
```
