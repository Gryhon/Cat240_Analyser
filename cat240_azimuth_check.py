#!/usr/bin/env python3
"""
cat240_azimuth_check.py – CAT240 Azimuth Completeness Check
=============================================================
Reads PCAP/PCAPNG files, splits the azimuth stream into revolutions and
reports how many azimuths are missing per revolution.

Usage:
    python cat240_azimuth_check.py Data/*.pcapng
    python cat240_azimuth_check.py Data/file.pcapng --packets 5000
    python cat240_azimuth_check.py Data/file.pcapng --output report.md
"""

import argparse
import struct
import sys
from collections import Counter
from typing import Dict, List, Optional, Tuple

import numpy as np

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    RICH = True
except ImportError:
    RICH = False
    print("Note: run 'pip install rich' for formatted output.", file=sys.stderr)

console = Console() if RICH else None


# ─────────────────────────────────────────────────────────────────────────────
# CAT240 Decoder  (azimuth + DSI only; video payload is skipped)
# ─────────────────────────────────────────────────────────────────────────────

class Cat240Decoder:
    """Decodes azimuth and DSI from CAT240 scan packets; ignores video cells."""

    def decode(self, data: bytes):
        if len(data) < 3 or data[0] != 0xF0:
            return None
        length = struct.unpack(">H", data[1:3])[0]
        if length > len(data):
            return None

        offset = 3
        fspec = []
        while offset < length:
            byte = data[offset]; fspec.append(byte); offset += 1
            if not (byte & 0x01):
                break

        active_items = []
        for i, byte in enumerate(fspec):
            for bit in range(7, 0, -1):
                if byte & (1 << bit):
                    active_items.append(i * 7 + (8 - bit))

        r = {'sac': 0, 'sic': 0, 'start_az': None, 'end_az': 0.0, 'has_video': False}
        for item in active_items:
            if offset >= length:
                break
            offset = self._parse_item(data, offset, length, item, r)
            if offset is None:
                break

        if r['start_az'] is None or not r['has_video']:
            return None
        return r['sac'], r['sic'], r['start_az'], r['end_az']

    def _parse_item(self, data, offset, length, item, r):
        try:
            if item == 1:                           # DSI: SAC + SIC
                r['sac'] = data[offset]; r['sic'] = data[offset + 1]
                return offset + 2
            elif item == 2:  return offset + 1      # Msg type
            elif item == 3:  return offset + 4      # VRH
            elif item == 4:                          # Video Summary
                return offset + 1 + data[offset]
            elif item == 5:                          # I240/040 nano
                if offset + 12 > length: return length
                sa = struct.unpack(">H", data[offset:offset+2])[0]
                ea = struct.unpack(">H", data[offset+2:offset+4])[0]
                r['start_az'] = sa / 65536.0 * 360.0
                r['end_az']   = ea / 65536.0 * 360.0
                return offset + 12
            elif item == 6:                          # I240/041 femto
                if offset + 12 > length: return length
                sa = struct.unpack(">H", data[offset:offset+2])[0]
                ea = struct.unpack(">H", data[offset+2:offset+4])[0]
                r['start_az'] = sa / 65536.0 * 360.0
                r['end_az']   = ea / 65536.0 * 360.0
                return offset + 12
            elif item == 7:   return offset + 2     # CellRes
            elif item == 8:   return offset + 5     # Counters
            elif item == 9:                          # VideoLow
                r['has_video'] = True
                if offset >= length: return length
                rep = data[offset]
                return offset + 1 + rep * 4
            elif item == 10:                         # VideoMedium
                r['has_video'] = True
                if offset >= length: return length
                rep = data[offset]
                return offset + 1 + rep * 64
            elif item == 11:                         # VideoHigh
                r['has_video'] = True
                if offset >= length: return length
                rep = data[offset]
                return offset + 1 + rep * 256
            elif item == 12: return offset + 3       # ToD
            else:
                if offset < length:
                    field_len = data[offset]
                    return offset + (field_len if field_len > 0 else 1)
                return offset + 1
        except Exception:
            return length


# ─────────────────────────────────────────────────────────────────────────────
# PCAP/PCAPNG Reader  (identical to cat240_stream_info.py)
# ─────────────────────────────────────────────────────────────────────────────

class PcapReader:
    PCAP_MAGIC_LE = 0xa1b2c3d4
    PCAP_MAGIC_BE = 0xd4c3b2a1
    PCAPNG_MAGIC  = 0x0a0d0d0a

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._frag_buffer: dict = {}

    def packets(self):
        with open(self.filepath, 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]
            f.seek(0)
            if magic in (self.PCAP_MAGIC_LE, self.PCAP_MAGIC_BE):
                yield from self._read_pcap(f, magic)
            elif magic == self.PCAPNG_MAGIC:
                yield from self._read_pcapng(f)
            else:
                raise ValueError(f"Unknown file format (magic=0x{magic:08X})")

    def _extract_udp(self, raw: bytes, link_type: int) -> Optional[Tuple]:
        try:
            if link_type == 1:
                if len(raw) < 14: return None
                ether_type = struct.unpack('>H', raw[12:14])[0]
                ip_start = 14
                if ether_type == 0x8100:
                    ip_start += 4
                    ether_type = struct.unpack('>H', raw[16:18])[0]
                if ether_type != 0x0800: return None
            elif link_type == 101:
                ip_start = 0
            else:
                return None
            ip_hdr = raw[ip_start:]
            if len(ip_hdr) < 20: return None
            ihl = (ip_hdr[0] & 0x0F) * 4
            if ip_hdr[9] != 17: return None
            src_ip  = '.'.join(str(b) for b in ip_hdr[12:16])
            dst_ip  = '.'.join(str(b) for b in ip_hdr[16:20])
            ip_id   = struct.unpack('>H', ip_hdr[4:6])[0]
            flags_frag = struct.unpack('>H', ip_hdr[6:8])[0]
            mf      = bool((flags_frag >> 13) & 1)
            frag_off= (flags_frag & 0x1FFF) * 8
            ip_payload = raw[ip_start + ihl:]
            if not mf and frag_off == 0:
                if len(ip_payload) < 8: return None
                dst_port = struct.unpack('>H', ip_payload[2:4])[0]
                udp_len  = struct.unpack('>H', ip_payload[4:6])[0]
                return ip_payload[8:udp_len], src_ip, dst_ip, dst_port
            key = (src_ip, dst_ip, 17, ip_id)
            if key not in self._frag_buffer:
                self._frag_buffer[key] = {'frags': {}, 'last_off': -1, 'src_ip': src_ip}
            entry = self._frag_buffer[key]
            entry['frags'][frag_off] = ip_payload
            if not mf:
                entry['last_off'] = frag_off
            if entry['last_off'] < 0: return None
            offsets = sorted(entry['frags'].keys())
            total = bytearray()
            for off in offsets:
                if off != len(total): return None
                total.extend(entry['frags'][off])
            del self._frag_buffer[key]
            if len(total) < 8: return None
            dst_port = struct.unpack('>H', bytes(total[2:4]))[0]
            udp_len  = struct.unpack('>H', bytes(total[4:6]))[0]
            return bytes(total[8:udp_len]), entry['src_ip'], dst_ip, dst_port
        except Exception:
            return None

    def _read_pcap(self, f, magic):
        endian = '<' if magic == self.PCAP_MAGIC_LE else '>'
        hdr = f.read(24)
        link_type = struct.unpack(endian + 'I', hdr[20:24])[0] if len(hdr) >= 24 else 1
        while True:
            rec = f.read(16)
            if len(rec) < 16: break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + 'IIII', rec)
            raw = f.read(incl_len)
            if len(raw) < incl_len: break
            r = self._extract_udp(raw, link_type)
            if r: yield ts_sec + ts_usec / 1e6, r[0], r[1], r[2], r[3]

    def _read_pcapng(self, f):
        endian, link_type = '<', 1
        while True:
            hdr = f.read(8)
            if len(hdr) < 8: break
            block_type, block_len = struct.unpack(endian + 'II', hdr)
            if block_len < 12: break
            body = f.read(block_len - 12); f.read(4)
            if block_type == 0x0A0D0D0A:
                if len(body) >= 4:
                    bom = struct.unpack('<I', body[:4])[0]
                    endian = '<' if bom == 0x1A2B3C4D else '>'
            elif block_type == 0x00000001:
                if len(body) >= 2:
                    link_type = struct.unpack(endian + 'H', body[:2])[0]
            elif block_type == 0x00000006:
                if len(body) >= 20:
                    ts_hi, ts_lo, cap_len, _ = struct.unpack(endian + 'IIII', body[4:20])
                    r = self._extract_udp(body[20:20 + cap_len], link_type)
                    if r: yield ((ts_hi << 32) | ts_lo) / 1e6, r[0], r[1], r[2], r[3]
            elif block_type == 0x00000003:
                r = self._extract_udp(body[4:], link_type)
                if r: yield 0.0, r[0], r[1], r[2], r[3]


# ─────────────────────────────────────────────────────────────────────────────
# Revolution analysis
# ─────────────────────────────────────────────────────────────────────────────

_FULL_REV_MIN_DEG = 340.0   # minimum angular span (°) to count as a full revolution


def _compute_rev_stats(az_list: List[float], timestamps: List[float]) -> Optional[dict]:
    """
    Detects revolutions in az_list and returns per-revolution completeness stats.
    Only full revolutions (angular span >= _FULL_REV_MIN_DEG) are included in
    the statistics; partial revolutions at recording start/end (or after gaps)
    are silently dropped and counted separately.
    Returns None if not enough data.
    """
    if len(az_list) < 20:
        return None

    # Normalised deltas (wrapped to [-180, +180])
    az = np.array(az_list, dtype=np.float64)
    d = np.diff(az)
    d = np.where(d < -180, d + 360, d)
    d = np.where(d >  180, d - 360, d)

    # Median positive step → expected azimuths/revolution
    pos = d[d > 0.01]
    if len(pos) < 10:
        return None
    median_step = float(np.median(pos))
    if median_step <= 0:
        return None
    spokes_per_rev = round(360.0 / median_step)

    # Detect revolution boundaries: raw (unnormalised) large negative jump
    # e.g. az goes 359.8 → 0.1  →  raw delta = -359.7
    raw_d = np.diff(az)
    wrap_threshold = -(median_step * 3.0)
    boundary_indices = list(np.where(raw_d < wrap_threshold)[0] + 1)
    rev_starts = [0] + boundary_indices + [len(az_list)]

    ts_arr = np.array(timestamps) if timestamps else None
    all_positions = set(range(spokes_per_rev))

    # First pass: compute angular span per candidate revolution and classify
    candidates = []
    for j in range(len(rev_starts) - 1):
        s, e = rev_starts[j], rev_starts[j + 1]
        slice_az = az_list[s:e]
        if len(slice_az) < 2:
            continue
        # Angular span: sum of positive normalised steps within this revolution.
        # A full 360° sweep sums to ~360° regardless of how many azimuths are
        # missing; a partial sweep (recording cut) sums to less.
        d_sl = np.diff(np.array(slice_az, dtype=np.float64))
        d_sl = np.where(d_sl < -180, d_sl + 360, d_sl)
        d_sl = np.where(d_sl >  180, d_sl - 360, d_sl)
        angular_span = float(d_sl[d_sl > 0].sum())

        received_pos = set(
            int(round(a / median_step)) % spokes_per_rev for a in slice_az
        )
        missing = max(0, spokes_per_rev - len(received_pos))
        ts_start = float(ts_arr[s]) if ts_arr is not None else 0.0
        candidates.append({
            'idx':          j,
            'received':     len(received_pos),
            'missing':      missing,
            'ts_start':     ts_start,
            'angular_span': angular_span,
            'received_pos': received_pos,
        })

    # Second pass: keep only full revolutions for statistics
    full_revs   = [c for c in candidates if c['angular_span'] >= _FULL_REV_MIN_DEG]
    partial_cnt = len(candidates) - len(full_revs)

    if not full_revs:
        return None

    # Build missing-position counter from full revolutions only
    missing_pos_counter: Counter = Counter()
    for r in full_revs:
        if r['missing'] > 0:
            for p in (all_positions - r['received_pos']):
                missing_pos_counter[p] += 1

    # Strip helper fields before returning
    revolutions = []
    for r in full_revs:
        revolutions.append({
            'idx':      r['idx'],
            'received': r['received'],
            'missing':  r['missing'],
            'ts_start': r['ts_start'],
        })

    missing_values = [r['missing'] for r in revolutions]
    dist = Counter(missing_values)
    complete = dist.get(0, 0)
    worst = sorted(revolutions, key=lambda r: r['missing'], reverse=True)[:5]

    # Top-10 most frequently missing azimuth positions → convert to degrees
    top_missing_pos = [
        (round(pos * median_step, 3), count)
        for pos, count in missing_pos_counter.most_common(10)
    ]

    return {
        'spokes_per_rev':   spokes_per_rev,
        'median_step':      median_step,
        'total_revs':       len(revolutions),
        'partial_revs':     partial_cnt,
        'missing_dist':     dist,          # missing_count → n_revolutions
        'complete_revs':    complete,
        'mean_missing':     float(np.mean(missing_values)),
        'max_missing':      int(np.max(missing_values)),
        'worst_revs':       worst,
        'top_missing_pos':  top_missing_pos,
    }


def _stream_sort_key(item):
    """Sorts streams by src IP (numeric) then by stream key."""
    key, s = item
    ip = min(s['src_ips']) if s['src_ips'] else '0.0.0.0'
    return (tuple(int(x) for x in ip.split('.')), key)


# ─────────────────────────────────────────────────────────────────────────────
# File analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyse(filepath: str, max_packets: int = 0) -> dict:
    """
    Returns:
        streams  – Dict[stream_key, {'az_list', 'timestamps', 'sac_sic', 'src_ips', 'msg_count'}]
        total_udp, non_cat240
    """
    reader  = PcapReader(filepath)
    decoder = Cat240Decoder()
    streams: Dict[str, dict] = {}
    total_udp = 0
    non_cat240 = 0

    def _process():
        nonlocal total_udp, non_cat240
        for ts, payload, src_ip, dst_ip, dst_port in reader.packets():
            total_udp += 1
            if max_packets and total_udp > max_packets:
                break
            result = decoder.decode(payload)
            if result is None:
                if len(payload) >= 1 and payload[0] == 0xF0:
                    non_cat240 += 1
                continue
            sac, sic, start_az, _ = result
            key = f"{dst_ip}:{dst_port}"
            if key not in streams:
                streams[key] = {
                    'az_list':    [],
                    'timestamps': [],
                    'sac_sic':    Counter(),
                    'src_ips':    set(),
                    'msg_count':  0,
                }
            s = streams[key]
            s['az_list'].append(start_az)
            s['timestamps'].append(ts)
            s['sac_sic'][(sac, sic)] += 1
            s['src_ips'].add(src_ip)
            s['msg_count'] += 1

    if RICH:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TaskProgressColumn(), console=console) as prog:
            prog.add_task(f"Reading {filepath} …", total=None)
            _process()
    else:
        print(f"Reading {filepath} …", file=sys.stderr)
        _process()

    return streams, total_udp, non_cat240


# ─────────────────────────────────────────────────────────────────────────────
# Terminal report (rich)
# ─────────────────────────────────────────────────────────────────────────────

_BAR_CHARS = " ▏▎▍▌▋▊▉█"

def _bar(frac: float, width: int = 20) -> str:
    filled = frac * width
    full   = int(filled)
    partial_idx = int((filled - full) * 8)
    bar = "█" * full
    if full < width and partial_idx > 0:
        bar += _BAR_CHARS[partial_idx]
    return bar.ljust(width)


def print_report(filepath: str, streams: dict, total_udp: int, non_cat240: int):
    total_msgs = sum(s['msg_count'] for s in streams.values())
    console.print()
    console.rule(f"[bold cyan]Azimuth Completeness: {filepath}")
    console.print(
        f"  UDP packets: [bold]{total_udp:,}[/]   "
        f"CAT240: [bold]{total_msgs:,}[/]   "
        f"Streams: [bold]{len(streams)}[/]"
        + (f"   Non-CAT240: {non_cat240}" if non_cat240 else "")
    )

    for key, s in sorted(streams.items(), key=_stream_sort_key):
        stats = _compute_rev_stats(s['az_list'], s['timestamps'])
        sac_sic_str = ", ".join(f"{a}/{b}" for (a, b), _ in s['sac_sic'].most_common(2))
        src_str = ", ".join(sorted(s['src_ips'])) if s['src_ips'] else "?"

        if stats is None:
            console.print(f"\n[yellow]Stream {key} — not enough data for revolution analysis[/]")
            continue

        total_revs   = stats['total_revs']
        complete     = stats['complete_revs']
        pct_complete = 100 * complete / total_revs if total_revs else 0
        dist         = stats['missing_dist']

        title = f"[bold]{key}[/]  [dim]src: {src_str}  SAC/SIC: {sac_sic_str}  msgs: {s['msg_count']:,}[/]"
        console.print()
        console.print(Panel(title, expand=False))

        # Summary row
        partial_note = (f"  [dim](+{stats['partial_revs']} partial skipped)[/]"
                        if stats['partial_revs'] else "")
        console.print(
            f"  Expected az/rev: [bold]{stats['spokes_per_rev']}[/]  "
            f"Step: {stats['median_step']:.4f}°   "
            f"Full revolutions: [bold]{total_revs}[/]{partial_note}   "
            f"Complete (0 missing): [bold green]{complete}[/] "
            f"([bold green]{pct_complete:.1f}%[/])   "
            f"Mean missing: [bold]{stats['mean_missing']:.2f}[/]   "
            f"Max missing: [bold red]{stats['max_missing']}[/]"
        )

        # Distribution table
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta",
                    title="Missing azimuths per revolution")
        tbl.add_column("Missing", justify="right")
        tbl.add_column("Revolutions", justify="right")
        tbl.add_column("%", justify="right")
        tbl.add_column("", justify="left", min_width=22)

        for missing_cnt in sorted(dist.keys()):
            n   = dist[missing_cnt]
            pct = 100 * n / total_revs
            color = "green" if missing_cnt == 0 else ("yellow" if missing_cnt <= 3 else "red")
            tbl.add_row(
                f"[{color}]{missing_cnt}[/]",
                f"[{color}]{n:,}[/]",
                f"[{color}]{pct:.1f}%[/]",
                f"[{color}]{_bar(pct / 100)}[/]",
            )
        console.print(tbl)

        # Worst revolutions
        worst = stats['worst_revs']
        if worst and worst[0]['missing'] > 0:
            console.print("  [bold]Worst revolutions:[/]")
            for r in worst:
                if r['missing'] == 0:
                    break
                console.print(
                    f"    Rev #{r['idx']:>4d}  missing: [red]{r['missing']:>4d}[/]"
                    f"  received: {r['received']:>4d}"
                    + (f"  ts: {r['ts_start']:.3f}s" if r['ts_start'] else "")
                )

        # Frequently missing positions
        if stats['top_missing_pos']:
            console.print("  [bold]Most frequently missing azimuth positions:[/]")
            parts = []
            for az_deg, count in stats['top_missing_pos'][:5]:
                parts.append(f"{az_deg:.3f}° [dim]({count}×)[/]")
            console.print("    " + "   ".join(parts))


# ─────────────────────────────────────────────────────────────────────────────
# Plain-text report
# ─────────────────────────────────────────────────────────────────────────────

def print_report_plain(filepath: str, streams: dict, total_udp: int, non_cat240: int):
    sep = "=" * 70
    total_msgs = sum(s['msg_count'] for s in streams.values())
    print(f"\n{sep}\nAZIMUTH COMPLETENESS: {filepath}\n{sep}")
    print(f"UDP: {total_udp}  CAT240: {total_msgs}  Streams: {len(streams)}")

    for key, s in sorted(streams.items(), key=_stream_sort_key):
        stats = _compute_rev_stats(s['az_list'], s['timestamps'])
        print(f"\n[{key}]  msgs: {s['msg_count']:,}  SAC/SIC: {dict(s['sac_sic'].most_common(2))}")
        if stats is None:
            print("  Not enough data.")
            continue
        total_revs = stats['total_revs']
        pct = 100 * stats['complete_revs'] / total_revs if total_revs else 0
        partial_note = f"  (+{stats['partial_revs']} partial skipped)" if stats['partial_revs'] else ""
        print(f"  Expected az/rev : {stats['spokes_per_rev']}  step: {stats['median_step']:.4f}°")
        print(f"  Full revolutions: {total_revs}{partial_note}")
        print(f"  Complete (0 mis): {stats['complete_revs']} ({pct:.1f}%)")
        print(f"  Mean missing    : {stats['mean_missing']:.2f}  Max: {stats['max_missing']}")
        print("  Distribution    :")
        for mc in sorted(stats['missing_dist']):
            n = stats['missing_dist'][mc]
            print(f"    missing={mc:4d} : {n:6,} revs  ({100*n/total_revs:.1f}%)")
        if stats['top_missing_pos']:
            pos_str = "  ".join(f"{az:.3f}°({cnt}×)" for az, cnt in stats['top_missing_pos'][:5])
            print(f"  Freq. missing az.: {pos_str}")


# ─────────────────────────────────────────────────────────────────────────────
# Markdown report
# ─────────────────────────────────────────────────────────────────────────────

def write_markdown(filepath: str, streams: dict, total_udp: int, non_cat240: int,
                   md_path: str):
    import os
    lines = []
    w = lines.append

    total_msgs = sum(s['msg_count'] for s in streams.values())
    w(f"# Azimuth Completeness Report")
    w(f"")
    w(f"**File:** `{os.path.basename(filepath)}`  ")
    w(f"**UDP packets:** {total_udp:,}  |  **CAT240 messages:** {total_msgs:,}  "
      f"|  **Streams:** {len(streams)}")
    w("")

    for key, s in sorted(streams.items(), key=_stream_sort_key):
        stats = _compute_rev_stats(s['az_list'], s['timestamps'])
        sac_sic_str = ", ".join(f"{a}/{b}" for (a, b), _ in s['sac_sic'].most_common(2))
        src_str = ", ".join(sorted(s['src_ips'])) if s['src_ips'] else "?"
        w(f"---")
        w(f"")
        w(f"## Stream `{key}`")
        w(f"")
        w(f"| Parameter | Value |")
        w(f"|---|---|")
        w(f"| Source IP(s) | {src_str} |")
        w(f"| SAC / SIC | {sac_sic_str} |")
        w(f"| Messages | {s['msg_count']:,} |")

        if stats is None:
            w(f"| Status | Not enough data for revolution analysis |")
            w("")
            continue

        total_revs   = stats['total_revs']
        pct_complete = 100 * stats['complete_revs'] / total_revs if total_revs else 0
        partial_note = f" (+{stats['partial_revs']} partial skipped)" if stats['partial_revs'] else ""
        w(f"| Expected az/revolution | {stats['spokes_per_rev']} |")
        w(f"| Azimuth step (median) | {stats['median_step']:.4f}° |")
        w(f"| Full revolutions | {total_revs}{partial_note} |")
        w(f"| Complete revolutions (0 missing) | {stats['complete_revs']} ({pct_complete:.1f}%) |")
        w(f"| Mean missing per revolution | {stats['mean_missing']:.2f} |")
        w(f"| Max missing in one revolution | {stats['max_missing']} |")
        w("")

        w("### Missing azimuths per revolution — distribution")
        w("")
        w("| Missing | Revolutions | % |")
        w("|---:|---:|---:|")
        for mc in sorted(stats['missing_dist']):
            n   = stats['missing_dist'][mc]
            pct = 100 * n / total_revs
            w(f"| {mc} | {n:,} | {pct:.1f}% |")
        w("")

        worst = stats['worst_revs']
        if worst and worst[0]['missing'] > 0:
            w("### Worst revolutions")
            w("")
            w("| Rev # | Missing | Received | Timestamp (s) |")
            w("|---:|---:|---:|---:|")
            for r in worst:
                if r['missing'] == 0:
                    break
                ts_str = f"{r['ts_start']:.3f}" if r['ts_start'] else "—"
                w(f"| {r['idx']} | {r['missing']} | {r['received']} | {ts_str} |")
            w("")

        if stats['top_missing_pos']:
            w("### Most frequently missing azimuth positions")
            w("")
            w("| Azimuth (°) | Revolutions missing |")
            w("|---:|---:|")
            for az_deg, count in stats['top_missing_pos']:
                w(f"| {az_deg:.3f} | {count} |")
            w("")

    with open(md_path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines) + '\n')


# ─────────────────────────────────────────────────────────────────────────────
# PDF report
# ─────────────────────────────────────────────────────────────────────────────

def write_pdf(filepath: str, streams: dict, total_udp: int, non_cat240: int,
              pdf_path: str) -> None:
    try:
        from fpdf import FPDF, XPos, YPos
    except ImportError:
        print("PDF export not available (pip install fpdf2)", file=sys.stderr)
        return

    from datetime import datetime

    C_HEADER   = (0,   51, 102)
    C_SECTION  = (0,   68, 136)
    C_ROW_EVEN = (240, 244, 248)
    C_ROW_ODD  = (255, 255, 255)
    C_TEXT     = (26,  26,  26)
    C_DIM      = (100, 100, 100)

    class PDF(FPDF):
        def header(self):
            self.set_fill_color(*C_HEADER)
            self.rect(0, 0, 210, 10, 'F')
            self.set_font('Helvetica', 'B', 8)
            self.set_text_color(255, 255, 255)
            self.set_xy(10, 2)
            self.cell(0, 6, 'CAT240 Azimuth Completeness Check', align='L')
            self.set_xy(0, 2)
            self.cell(200, 6, f'Page {self.page_no()}', align='R')
            self.set_text_color(*C_TEXT)
            self.ln(12)

        def footer(self):
            self.set_y(-10)
            self.set_font('Helvetica', '', 7)
            self.set_text_color(*C_DIM)
            self.cell(0, 5,
                      f'Generated by cat240_azimuth_check.py  ·  {filepath}',
                      align='C')

    pdf = PDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_margins(14, 14, 14)
    pdf.add_page()

    W = 182

    def _s(text):
        return (str(text)
                .replace('\u2014', '-').replace('\u2013', '-')
                .replace('\u2192', '->').replace('\u00b0', ' deg')
                .replace('\u2019', "'").replace('\u00d7', 'x')
                .encode('latin-1', errors='replace').decode('latin-1'))

    def _ensure_space(min_mm: float):
        if pdf.get_y() + min_mm > pdf.h - pdf.b_margin:
            pdf.add_page()

    def h1(text):
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_text_color(*C_HEADER)
        pdf.cell(W, 8, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(*C_HEADER)
        pdf.set_line_width(0.5)
        pdf.line(14, pdf.get_y(), 196, pdf.get_y())
        pdf.ln(2)
        pdf.set_text_color(*C_TEXT)

    def h2(text):
        _ensure_space(35)
        pdf.ln(3)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(W, 7, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(200, 210, 220)
        pdf.set_line_width(0.3)
        pdf.line(14, pdf.get_y(), 196, pdf.get_y())
        pdf.ln(1)
        pdf.set_text_color(*C_TEXT)

    def h3(text, table_rows=0):
        # Reserve space for the heading itself plus the table header row and
        # at least the first data rows, so the heading never ends up alone at
        # the bottom of a page.
        needed = 2 + 5 + 1 + 5 + max(table_rows, 3) * 5  # ln + h3 + ln + thead + rows
        _ensure_space(needed)
        pdf.ln(2)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(W, 5, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C_TEXT)

    def kv_table(rows, col_w=(80, 102)):
        # No _ensure_space here – h3() already reserved space for heading +
        # first rows; auto_page_break handles overflow of long tables.
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(*C_HEADER)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_w[0], 5, 'Parameter', border=0, fill=True)
        pdf.cell(col_w[1], 5, 'Value',     border=0, fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(*C_TEXT)
        for i, (k, v) in enumerate(rows):
            pdf.set_fill_color(*(C_ROW_EVEN if i % 2 == 0 else C_ROW_ODD))
            pdf.cell(col_w[0], 5, _s(k), border=0, fill=True)
            pdf.cell(col_w[1], 5, _s(v), border=0, fill=True,
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    def wide_table(headers, rows, col_ws=None):
        # No _ensure_space here – see kv_table comment above.
        n = len(headers)
        if col_ws is None:
            col_ws = [W // n] * n
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_fill_color(*C_HEADER)
        pdf.set_text_color(255, 255, 255)
        for h, w in zip(headers, col_ws):
            pdf.cell(w, 5, _s(h), border=0, fill=True)
        pdf.ln()
        pdf.set_font('Helvetica', '', 7.5)
        pdf.set_text_color(*C_TEXT)
        for i, row in enumerate(rows):
            pdf.set_fill_color(*(C_ROW_EVEN if i % 2 == 0 else C_ROW_ODD))
            for val, w in zip(row, col_ws):
                pdf.cell(w, 5, _s(val), border=0, fill=True)
            pdf.ln()
        pdf.ln(2)

    # ── Title ────────────────────────────────────────────────────────────────
    total_msgs = sum(s['msg_count'] for s in streams.values())
    all_ts: list = []
    for s in streams.values():
        all_ts.extend(s['timestamps'])
    duration = max(all_ts) - min(all_ts) if all_ts else 0

    h1('CAT240 Azimuth Completeness Check')
    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(*C_DIM)
    pdf.cell(W, 5, f'File: {filepath}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(W, 5, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(*C_TEXT)
    pdf.ln(2)

    kv_table([
        ('Recording duration', f'{duration:.1f} s'),
        ('UDP packets',        f'{total_udp:,}'),
        ('CAT240 messages',    f'{total_msgs:,}'),
        ('Streams',            str(len(streams))),
        ('Non-CAT240 UDP',     str(non_cat240) if non_cat240 else '0'),
    ])

    # ── Stream overview ───────────────────────────────────────────────────────
    h2('Stream Overview')
    ov_rows = []
    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        stats = _compute_rev_stats(s['az_list'], s['timestamps'])
        sac_sic = ', '.join(f'{a}/{b}' for (a, b), _ in s['sac_sic'].most_common(2))
        src_str = ', '.join(sorted(s['src_ips'])) if s['src_ips'] else '?'
        if stats:
            spokes = str(stats['spokes_per_rev'])
            full_r = str(stats['total_revs'])
            pct_ok = (f"{100*stats['complete_revs']/stats['total_revs']:.1f}%"
                      if stats['total_revs'] else '?')
            mean_m = f"{stats['mean_missing']:.1f}"
            max_m  = str(stats['max_missing'])
        else:
            spokes = full_r = pct_ok = mean_m = max_m = '?'
        ov_rows.append([str(idx), src_str, key, sac_sic,
                        f"{s['msg_count']:,}",
                        spokes, full_r, pct_ok, mean_m, max_m])
    wide_table(
        ['#', 'Src IP', 'Dst IP:Port', 'SAC/SIC', 'Messages',
         'Az/rev', 'Full revs', 'Complete%', 'Mean miss', 'Max miss'],
        ov_rows,
        [7, 30, 38, 18, 20, 14, 14, 16, 16, 15],
    )

    # ── Per-stream detail ─────────────────────────────────────────────────────
    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        stats = _compute_rev_stats(s['az_list'], s['timestamps'])
        if idx > 1:
            pdf.add_page()
        sac_sic = ', '.join(f'{a}/{b}' for (a, b), _ in s['sac_sic'].most_common(2))
        src_str = ', '.join(sorted(s['src_ips'])) if s['src_ips'] else '?'
        h2(f'Stream {idx}: {key}')
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(*C_DIM)
        pdf.cell(W, 5, _s(f'src: {src_str}   SAC/SIC: {sac_sic}   {s["msg_count"]:,} messages'),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C_TEXT)
        pdf.ln(1)

        if stats is None:
            pdf.set_font('Helvetica', 'I', 8)
            pdf.cell(W, 5, 'Not enough data for revolution analysis.',
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            continue

        total_revs   = stats['total_revs']
        pct_complete = 100 * stats['complete_revs'] / total_revs if total_revs else 0
        partial_note = (f"  (+{stats['partial_revs']} partial skipped)"
                        if stats['partial_revs'] else '')

        summary_rows = [
            ('Expected az/revolution',          str(stats['spokes_per_rev'])),
            ('Azimuth step (median)',            f"{stats['median_step']:.4f} deg"),
            ('Full revolutions',                f"{total_revs}{partial_note}"),
            ('Complete revolutions (0 missing)',f"{stats['complete_revs']} ({pct_complete:.1f}%)"),
            ('Mean missing per revolution',     f"{stats['mean_missing']:.2f}"),
            ('Max missing in one revolution',   str(stats['max_missing'])),
        ]
        h3('Summary', table_rows=len(summary_rows))
        kv_table(summary_rows)

        dist_rows = []
        for mc in sorted(stats['missing_dist']):
            n   = stats['missing_dist'][mc]
            pct = 100 * n / total_revs
            dist_rows.append([str(mc), f'{n:,}', f'{pct:.1f}%'])
        h3('Missing azimuths per revolution — distribution', table_rows=len(dist_rows))
        wide_table(['Missing', 'Revolutions', '%'], dist_rows, [40, 50, 40])

        worst = stats['worst_revs']
        if worst and worst[0]['missing'] > 0:
            worst_rows = []
            for r in worst:
                if r['missing'] == 0:
                    break
                ts_str = f"{r['ts_start']:.3f}" if r['ts_start'] else '-'
                worst_rows.append([str(r['idx']), str(r['missing']),
                                   str(r['received']), ts_str])
            h3('Worst revolutions', table_rows=len(worst_rows))
            wide_table(['Rev #', 'Missing', 'Received', 'Timestamp (s)'],
                       worst_rows, [30, 40, 40, 50])

        if stats['top_missing_pos']:
            pos_rows = [[f"{az:.3f} deg", str(cnt)]
                        for az, cnt in stats['top_missing_pos']]
            h3('Most frequently missing azimuth positions', table_rows=len(pos_rows))
            wide_table(['Azimuth', 'Revolutions missing'], pos_rows, [60, 60])

    pdf.output(pdf_path)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyses per-revolution azimuth completeness in CAT240 PCAP/PCAPNG files.",
    )
    parser.add_argument("file", nargs="+",
                        help="Path(s) to PCAP or PCAPNG file(s); glob patterns are expanded by the shell")
    parser.add_argument("--packets", "-n", type=int, default=0, metavar="N",
                        help="Analyse only the first N UDP packets (0 = all)")
    parser.add_argument("--output", "-o", metavar="FILE.md",
                        help="Markdown output path (only for single-file input; default: <input>_azcheck.md)")
    parser.add_argument("--pdf", metavar="FILE.pdf", nargs="?", const="",
                        help="Also generate a PDF report (default path: <input>_azcheck.pdf)")
    args = parser.parse_args()

    import os

    if len(args.file) > 1 and args.output:
        print("Warning: --output ignored when multiple files are given.", file=sys.stderr)

    exit_code = 0
    for filepath in args.file:
        if len(args.file) > 1:
            if RICH:
                console.rule(f"[bold]{filepath}")
            else:
                print(f"\n=== {filepath} ===")

        base    = os.path.splitext(os.path.basename(filepath))[0]
        md_path = (args.output if (args.output and len(args.file) == 1)
                   else f"{base}_azcheck.md")
        pdf_path = (args.pdf if args.pdf else f"{base}_azcheck.pdf") if args.pdf is not None else None

        try:
            streams, total_udp, non_cat240 = analyse(filepath, max_packets=args.packets)
            if not streams:
                print(f"No CAT240 messages found in {filepath}.", file=sys.stderr)
                exit_code = 1
                continue

            if RICH:
                print_report(filepath, streams, total_udp, non_cat240)
            else:
                print_report_plain(filepath, streams, total_udp, non_cat240)

            write_markdown(filepath, streams, total_udp, non_cat240, md_path=md_path)
            if RICH:
                console.print(f"[dim]Markdown saved: [cyan]{md_path}[/][/]")
            else:
                print(f"Markdown saved: {md_path}")

            if pdf_path is not None:
                write_pdf(filepath, streams, total_udp, non_cat240, pdf_path)
                if RICH:
                    console.print(f"[dim]PDF saved:      [cyan]{pdf_path}[/][/]")
                else:
                    print(f"PDF saved: {pdf_path}")

        except FileNotFoundError:
            print(f"Error: file not found: {filepath}", file=sys.stderr)
            exit_code = 1
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            exit_code = 1
        except KeyboardInterrupt:
            print("\nAborted.")
            break

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
