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
from math import gcd
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


def _compute_rev_stats(az_list: List[float], timestamps: List[float],
                       expected_spokes: int = 0,
                       end_az_list: Optional[List[float]] = None) -> Optional[dict]:
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

    # Gap-delta threshold: a delta > 1.5 × median_step means at least one spoke
    # is missing between two consecutive unique azimuth positions.
    gap_threshold = 1.5 * median_step

    # First pass: compute angular span per candidate revolution and classify
    candidates = []
    for j in range(len(rev_starts) - 1):
        s, e = rev_starts[j], rev_starts[j + 1]
        slice_az = az_list[s:e]
        slice_end_az = end_az_list[s:e] if end_az_list is not None else None
        if len(slice_az) < 2:
            continue
        # Angular span: sum of positive normalised steps within this revolution.
        # A full 360° sweep sums to ~360° regardless of how many azimuths are
        # missing; a partial sweep (recording cut) sums to less.
        d_sl = np.diff(np.array(slice_az, dtype=np.float64))
        d_sl = np.where(d_sl < -180, d_sl + 360, d_sl)
        d_sl = np.where(d_sl >  180, d_sl - 360, d_sl)
        angular_span = float(d_sl[d_sl > 0].sum())

        # Deduplicate: keep only azimuths that are ≥ median_step/2 away from
        # the previous one.  Duplicate messages (same or very close start_az)
        # do not count as a new spoke position.
        sorted_az = sorted(slice_az)
        unique_az_rev = [sorted_az[0]]
        for a in sorted_az[1:]:
            if a - unique_az_rev[-1] >= median_step / 2:
                unique_az_rev.append(a)
        n_unique  = len(unique_az_rev)
        total_msgs = e - s

        # Deltas between consecutive unique positions + wrap-around delta
        deltas = [unique_az_rev[k + 1] - unique_az_rev[k]
                  for k in range(n_unique - 1)]
        deltas.append(unique_az_rev[0] + 360.0 - unique_az_rev[-1])

        # Detect gaps and count missing spokes
        missing = 0
        gaps: List[Tuple[float, float]] = []   # (gap_start_deg, gap_size_deg)
        for k, delta in enumerate(deltas):
            if delta > gap_threshold:
                n_miss = max(0, round(delta / median_step) - 1)
                missing += n_miss
                gap_start = (unique_az_rev[k] + median_step) % 360.0
                gap_size  = delta - median_step
                gaps.append((gap_start, gap_size))

        ts_start = float(ts_arr[s]) if ts_arr is not None else 0.0
        candidates.append({
            'idx':            j,
            'total_msgs':     total_msgs,
            'unique_az':      n_unique,
            'received':       n_unique,    # kept for report compatibility
            'missing':        missing,
            'ts_start':       ts_start,
            'angular_span':   angular_span,
            'gaps':           gaps,
            'unique_az_list': unique_az_rev,   # degree positions for presence_matrix
            'end_az_slice':   slice_end_az,    # per-message end azimuth (or None)
            'start_az_slice': list(slice_az),  # original (non-deduped) start az list
        })

    # Second pass: keep only full revolutions for statistics
    full_revs   = [c for c in candidates if c['angular_span'] >= _FULL_REV_MIN_DEG]
    partial_cnt = len(candidates) - len(full_revs)

    if not full_revs:
        return None

    # Coverage-based gap recalculation: when end_az_list is available, replace the
    # delta-based gaps stored in candidates with interval-coverage gaps.
    # Each message covers [start_az, end_az) in raw 16-bit units.
    # Gaps are angular regions not covered by any message's span.
    step_raw = round(median_step / 360.0 * 65536)
    if step_raw < 1:
        step_raw = 1

    def _coverage_gaps(start_az_slice, end_az_slice):
        """Return (missing_count, gaps_list) using coverage-based detection."""
        if not start_az_slice:
            return 0, []
        # Build absolute intervals in raw 16-bit units
        intervals = []
        for sa_deg, ea_deg in zip(start_az_slice, end_az_slice):
            sa_r = round(sa_deg / 360.0 * 65536) % 65536
            ea_r = round(ea_deg / 360.0 * 65536) % 65536
            span_raw = (ea_r - sa_r) % 65536
            if span_raw == 0:
                span_raw = step_raw
            intervals.append((sa_r, sa_r + span_raw))  # absolute (non-wrapped)
        # Sort by start
        intervals.sort(key=lambda x: x[0])
        # Merge overlapping intervals
        merged = [list(intervals[0])]
        for sa_abs, ea_abs in intervals[1:]:
            if sa_abs <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], ea_abs)
            else:
                merged.append([sa_abs, ea_abs])
        # Find gaps between merged intervals, including the wrap-around gap
        gaps = []
        missing = 0
        n = len(merged)
        for k in range(n):
            next_k = (k + 1) % n
            if next_k == 0:
                # Wrap-around gap: from last interval end to first start + 65536
                gap_raw = (merged[0][0] + 65536) - merged[-1][1]
            else:
                gap_raw = merged[next_k][0] - merged[k][1]
            if gap_raw <= 0:
                continue
            n_miss = max(0, round(gap_raw / step_raw))
            if n_miss == 0:
                continue
            missing += n_miss
            # Convert gap start back to degrees
            if next_k == 0:
                gap_start_raw = merged[-1][1] % 65536
            else:
                gap_start_raw = merged[k][1] % 65536
            gap_start_deg = (gap_start_raw / 65536.0 * 360.0) % 360.0
            gap_size_deg  = gap_raw / 65536.0 * 360.0
            gaps.append((gap_start_deg, gap_size_deg))
        return missing, gaps

    if end_az_list is not None:
        for r in full_revs:
            new_missing, new_gaps = _coverage_gaps(
                r['start_az_slice'], r['end_az_slice'])
            r['missing'] = new_missing
            r['gaps']    = new_gaps

    # display_cols: bin up to 720 columns so the heatmap stays readable even for
    # radars with 4096+ spokes/rev (each column ≈ 0.5°).
    display_cols = min(spokes_per_rev, 720)

    # missing_matrix: fractional 2-D array (n_full_revs × display_cols).
    #   Each value = fraction of expected spokes missing in that bin (0.0–1.0).
    #   0.0 = no missing spokes in this bin/revolution
    #   1.0 = all expected spokes in this bin are missing
    # missing_freq: 1-D array (display_cols,) counting how many full revolutions
    #   had any gap in each angular bin.
    missing_matrix   = np.zeros((len(full_revs), display_cols), dtype=np.float32)
    missing_freq     = np.zeros(display_cols, dtype=np.float32)
    missing_pos_counter: Counter = Counter()

    spokes_per_bin = spokes_per_rev / display_cols  # z.B. 4096/720 ≈ 5.69

    for i, r in enumerate(full_revs):
        col_counts = np.zeros(display_cols, dtype=np.float32)
        for gap_start, gap_size in r['gaps']:
            n_miss = max(0, round(gap_size / median_step))
            if n_miss == 0:
                continue
            col_s = int(gap_start * display_cols / 360.0)
            col_e = min(int((gap_start + gap_size) * display_cols / 360.0),
                        display_cols - 1)
            n_cols = max(1, col_e - col_s + 1)
            col_counts[col_s:col_e + 1] += n_miss / n_cols
            missing_freq[col_s:col_e + 1] += 1.0
            for m in range(n_miss):
                angle = round((gap_start + m * median_step) % 360.0, 3)
                missing_pos_counter[angle] += 1
        missing_matrix[i] = np.clip(col_counts / spokes_per_bin, 0.0, 1.0)

    import math as _math

    # presence_matrix: binary 2-D array (n_full_revs × spokes_per_rev).
    #   1 = azimuth index was received in this revolution
    #   0 = azimuth index was missing
    # Span-aware: ceil(span_raw / step_raw) bins werden markiert, damit
    # Pakete die breiter als ein Schritt sind (z.B. E6410 48-raw bei step 40)
    # auch den Folge-Bin abdecken.
    presence_matrix = np.zeros((len(full_revs), spokes_per_rev), dtype=np.float32)
    for i, r in enumerate(full_revs):
        if r['end_az_slice'] is not None:
            bins = []
            for sa_deg, ea_deg in zip(r['start_az_slice'], r['end_az_slice']):
                sa_bin   = round(sa_deg / median_step) % spokes_per_rev
                span_raw = round(((ea_deg - sa_deg) % 360.0) / 360.0 * 65536)
                n_bins   = max(1, _math.ceil(span_raw / step_raw))
                for b in range(n_bins):
                    bins.append((sa_bin + b) % spokes_per_rev)
            presence_matrix[i, np.unique(np.array(bins, dtype=int))] = 1.0
        else:
            idxs = np.array(
                [round(az / median_step) % spokes_per_rev
                 for az in r['unique_az_list']],
                dtype=int)
            idxs = np.clip(idxs, 0, spokes_per_rev - 1)
            presence_matrix[i, idxs] = 1.0

    # Reference-grid matrix: map received azimuths onto a user-supplied
    # expected_spokes grid (e.g. 4096) to visualise how many of those
    # reference positions the radar actually transmits.
    reference_matrix = None
    if expected_spokes and expected_spokes != spokes_per_rev:
        ref_step     = 360.0 / expected_spokes
        ref_step_raw = round(65536.0 / expected_spokes)
        if ref_step_raw < 1:
            ref_step_raw = 1
        reference_matrix = np.zeros((len(full_revs), expected_spokes), dtype=np.float32)
        for i, r in enumerate(full_revs):
            if r['end_az_slice'] is not None:
                bins = []
                for sa_deg, ea_deg in zip(r['start_az_slice'], r['end_az_slice']):
                    sa_bin   = round(sa_deg / ref_step) % expected_spokes
                    span_raw = round(((ea_deg - sa_deg) % 360.0) / 360.0 * 65536)
                    n_bins   = max(1, _math.ceil(span_raw / ref_step_raw))
                    for b in range(n_bins):
                        bins.append((sa_bin + b) % expected_spokes)
                reference_matrix[i, np.unique(np.array(bins, dtype=int))] = 1.0
            else:
                idxs = np.array(
                    [round(az / ref_step) % expected_spokes for az in r['unique_az_list']],
                    dtype=int)
                idxs = np.clip(idxs, 0, expected_spokes - 1)
                reference_matrix[i, idxs] = 1.0

    # Span-Analyse: tatsächliche Paket-Span-Verteilung in raw-Einheiten (keine Bin-Schätzung)
    span_stats: dict = {}
    if end_az_list is not None and az_list and step_raw > 0:
        span_raws_all = [
            round(((ea - sa) % 360.0) / 360.0 * 65536)
            for sa, ea in zip(az_list, end_az_list)
        ]
        span_raw_dist = Counter(span_raws_all)   # raw_value → Anzahl
        zero_idxs = [i for i, sr in enumerate(span_raws_all) if sr == 0]
        wide_idxs = [i for i, sr in enumerate(span_raws_all) if sr > step_raw]
        ts_list   = list(timestamps) if timestamps else []
        n_full    = len(full_revs)
        span_stats = {
            'span_raw_dist':     span_raw_dist,   # Counter: raw → count
            'step_raw':          step_raw,
            'zero_span_total':   len(zero_idxs),
            'zero_span_per_rev': len(zero_idxs) / n_full if n_full else 0.0,
            'wide_span_total':   len(wide_idxs),
            'wide_span_per_rev': len(wide_idxs) / n_full if n_full else 0.0,
            'zero_span_examples': [(ts_list[i], az_list[i])
                                   for i in zero_idxs[:5] if i < len(ts_list)],
            'wide_span_examples': [(ts_list[i], az_list[i], end_az_list[i])
                                   for i in wide_idxs[:5] if i < len(ts_list)],
        }

    # Strip helper fields before returning
    revolutions = []
    for r in full_revs:
        revolutions.append({
            'idx':        r['idx'],
            'total_msgs': r['total_msgs'],
            'unique_az':  r['unique_az'],
            'received':   r['unique_az'],   # kept for report compatibility
            'missing':    r['missing'],
            'ts_start':   r['ts_start'],
        })

    missing_values = [r['missing'] for r in revolutions]
    dist = Counter(missing_values)
    complete = dist.get(0, 0)
    worst = sorted(revolutions, key=lambda r: r['missing'], reverse=True)[:5]

    top_missing_pos = list(missing_pos_counter.most_common(10))

    # Coverage stats: wie viele der erwarteten N Azimuths werden pro Umdrehung gesendet
    coverage: dict = {}
    if expected_spokes > 0 and expected_spokes != spokes_per_rev:
        cov_pct  = 100.0 * spokes_per_rev / expected_spokes
        miss_rev = expected_spokes - spokes_per_rev
        rpm = 0.0
        rev_period = 0.0
        if ts_arr is not None and len(ts_arr) > 1 and full_revs:
            dur = float(ts_arr[-1] - ts_arr[0])
            if dur > 0:
                rpm = len(full_revs) / dur * 60.0
                rev_period = dur / len(full_revs)
        mean_beam_width = 0.0
        if end_az_list is not None and az_list:
            bw = [(e - s) % 360.0 for s, e in zip(az_list, end_az_list)
                  if 0 < (e - s) % 360.0 < 10.0]
            mean_beam_width = float(np.mean(bw)) if bw else 0.0
        coverage = {
            'expected_spokes':  expected_spokes,
            'coverage_pct':     cov_pct,
            'missing_per_rev':  miss_rev,
            'rpm':              rpm,
            'rev_period':       rev_period,
            'mean_beam_width':  mean_beam_width,
        }

    return {
        'spokes_per_rev':   spokes_per_rev,
        'median_step':      median_step,
        'total_revs':       len(revolutions),
        'partial_revs':     partial_cnt,
        'missing_dist':     dist,
        'missing_matrix':   missing_matrix,
        'missing_freq':     missing_freq,
        'complete_revs':    complete,
        'mean_missing':     float(np.mean(missing_values)),
        'max_missing':      int(np.max(missing_values)),
        'mean_msgs':        float(np.mean([r['total_msgs'] for r in revolutions])),
        'mean_unique':      float(np.mean([r['unique_az']  for r in revolutions])),
        'mean_duplicate':   float(np.mean([r['total_msgs'] - r['unique_az']
                                           for r in revolutions])),
        'worst_revs':       worst,
        'top_missing_pos':  top_missing_pos,
        'presence_matrix':  presence_matrix,
        'reference_matrix': reference_matrix,
        'reference_spokes': expected_spokes if reference_matrix is not None else None,
        'coverage':         coverage,
        'span_stats':       span_stats,
    }


def _stream_sort_key(item):
    """Sorts streams by src IP (numeric) then by stream key."""
    key, s = item
    ip = min(s['src_ips']) if s['src_ips'] else '0.0.0.0'
    return (tuple(int(x) for x in ip.split('.')), key)


# ─────────────────────────────────────────────────────────────────────────────
# Figures
# ─────────────────────────────────────────────────────────────────────────────

# Threshold fractions for missing-frequency categories
_FREQ_SYSTEMATIC = 0.80   # missing in >80 % of revolutions → systematic
_FREQ_FREQUENT   = 0.10   # missing in >10 % of revolutions → frequent
# below 10 % → sporadic

_COL_SYSTEMATIC = '#e63946'   # red
_COL_FREQUENT   = '#f4a261'   # orange
_COL_SPORADIC   = '#2a9d8f'   # teal
_COL_NONE       = '#dddddd'   # light grey (never missing)


def _freq_colors(freq_frac: np.ndarray) -> list:
    """Map a fraction array [0,1] to per-bin category colors."""
    colors = []
    for f in freq_frac:
        if f > _FREQ_SYSTEMATIC:
            colors.append(_COL_SYSTEMATIC)
        elif f > _FREQ_FREQUENT:
            colors.append(_COL_FREQUENT)
        elif f > 0:
            colors.append(_COL_SPORADIC)
        else:
            colors.append(_COL_NONE)
    return colors


def _make_stream_figure(key: str, stats: dict):
    """
    Returns a 3-panel matplotlib Figure for one stream:
      Top-left    — heatmap: rows = revolutions, cols = azimuth bins,
                    white = present (0 %), red = fully missing (100 %).
      Bottom-left — frequency chart: fraction of revolutions each azimuth
                    bin was missing, color-coded by category.
      Right       — polar coverage ring: mean data presence per angular bin
                    (white = always received, red = always missing).
    Returns None if matplotlib is unavailable.
    """
    try:
        import matplotlib as _mpl
        _mpl.use('Agg')
        import matplotlib.pyplot as _plt
        import matplotlib.colors as _mcolors
        import matplotlib.patches as _mpatches
        import matplotlib.gridspec as _gridspec
    except ImportError:
        return None

    missing_matrix = stats['missing_matrix']   # (n_revs, display_cols)
    missing_freq   = stats['missing_freq']      # (display_cols,)
    total_revs     = stats['total_revs']
    spokes_per_rev = stats['spokes_per_rev']
    n_revs, display_cols = missing_matrix.shape

    freq_frac = missing_freq / total_revs if total_revs > 0 else missing_freq

    fig = _plt.figure(figsize=(14, 6), facecolor='white')
    gs  = _gridspec.GridSpec(2, 2,
                              height_ratios=[3, 1], width_ratios=[2.5, 1],
                              hspace=0.45, wspace=0.35,
                              left=0.06, right=0.97, top=0.93, bottom=0.09)
    ax_heat  = fig.add_subplot(gs[0, 0])
    ax_freq  = fig.add_subplot(gs[1, 0])

    # Shared tick positions in degrees and matching azimuth indices
    x_ticks_deg = [0, 90, 180, 270, 360]
    x_ticks_idx = [int(d * spokes_per_rev / 360) for d in x_ticks_deg]

    # ── Heatmap ──────────────────────────────────────────────────────────────
    cmap = _mcolors.LinearSegmentedColormap.from_list('missing', ['#ffffff', '#e63946'])
    ax_heat.imshow(missing_matrix, aspect='auto', origin='upper',
                   interpolation='nearest', cmap=cmap, vmin=0, vmax=1)
    ax_heat.set_ylabel('Revolution', fontsize=7)
    ax_heat.set_xlabel('Azimuth (°)', fontsize=7)

    # Bottom X: degrees
    heat_tick_cols = [d * display_cols / 360 for d in x_ticks_deg]
    ax_heat.set_xticks(heat_tick_cols)
    ax_heat.set_xticklabels([f'{d}°' for d in x_ticks_deg], fontsize=7)

    # Top X: azimuth index
    ax_heat2 = ax_heat.twiny()
    ax_heat2.set_xlim(ax_heat.get_xlim())
    ax_heat2.set_xticks(heat_tick_cols)
    ax_heat2.set_xticklabels([str(i) for i in x_ticks_idx], fontsize=7)
    ax_heat2.set_xlabel('Azimuth index', fontsize=7)
    ax_heat2.set_title(f'Missing Azimuths per Revolution  —  {key}', fontsize=9, pad=22)

    # Y ticks: revolution numbers starting at 1
    n_ticks = min(10, n_revs)
    tick_idx = np.linspace(0, n_revs - 1, n_ticks, dtype=int)
    ax_heat.set_yticks(tick_idx + 0.5)
    ax_heat.set_yticklabels([str(i + 1) for i in tick_idx], fontsize=7)

    # ── Frequency bar chart ───────────────────────────────────────────────────
    x_edges = np.linspace(0, 360, display_cols, endpoint=False)
    bar_w   = 360.0 / display_cols
    ax_freq.bar(x_edges, freq_frac * 100, width=bar_w,
                color=_freq_colors(freq_frac), linewidth=0, align='edge')

    ax_freq.set_xlim(0, 360)
    ax_freq.set_ylim(0, 100)
    ax_freq.set_xlabel('Azimuth (°)', fontsize=7)
    ax_freq.set_ylabel('Missing (%)', fontsize=7)
    ax_freq.set_title(
        f'Missing Azimuth Frequency  '
        f'(spokes/rev: {spokes_per_rev},  revolutions: {total_revs})',
        fontsize=8,
    )
    ax_freq.set_xticks(x_ticks_deg)
    ax_freq.set_xticklabels([f'{d}°' for d in x_ticks_deg], fontsize=7)
    ax_freq.tick_params(axis='y', labelsize=7)
    ax_freq.axhline(y=_FREQ_SYSTEMATIC * 100, color=_COL_SYSTEMATIC,
                    linewidth=0.6, linestyle='--', alpha=0.6)
    ax_freq.axhline(y=_FREQ_FREQUENT * 100,   color=_COL_FREQUENT,
                    linewidth=0.6, linestyle='--', alpha=0.6)

    # Top X: azimuth index
    ax_freq2 = ax_freq.twiny()
    ax_freq2.set_xlim(ax_freq.get_xlim())
    ax_freq2.set_xticks(x_ticks_deg)
    ax_freq2.set_xticklabels([str(i) for i in x_ticks_idx], fontsize=7)
    ax_freq2.set_xlabel('Azimuth index', fontsize=7)

    legend_elements = [
        _mpatches.Patch(facecolor=_COL_SYSTEMATIC, label=f'Systematic (>{int(_FREQ_SYSTEMATIC*100)}%)'),
        _mpatches.Patch(facecolor=_COL_FREQUENT,   label=f'Frequent (>{int(_FREQ_FREQUENT*100)}%)'),
        _mpatches.Patch(facecolor=_COL_SPORADIC,   label='Sporadic (>0%)'),
        _mpatches.Patch(facecolor=_COL_NONE,       label='Never missing'),
    ]
    ax_freq.legend(handles=legend_elements, fontsize=6, loc='upper right',
                   framealpha=0.8)

    # ── Polar coverage ring ───────────────────────────────────────────────────
    # Mean fraction of revolutions that HAD data in each angular bin.
    # White = always present, red = always missing.
    ax_polar = fig.add_subplot(gs[:, 1], projection='polar')
    coverage     = 1.0 - freq_frac                    # shape (display_cols,)
    theta_edges  = np.linspace(0, 2 * np.pi, display_cols + 1)
    r_edges      = np.array([0.25, 1.0])
    cmap_cov     = _mcolors.LinearSegmentedColormap.from_list(
                       'cov', ['#e63946', '#ffffff'])
    ax_polar.pcolormesh(theta_edges, r_edges, coverage.reshape(1, display_cols),
                        cmap=cmap_cov, vmin=0, vmax=1, linewidth=0)
    ax_polar.set_theta_zero_location('N')
    ax_polar.set_theta_direction(-1)         # clockwise = radar convention
    ax_polar.set_ylim(0, 1)
    ax_polar.set_yticks([])
    ax_polar.set_xticks(np.radians([0, 90, 180, 270]))
    ax_polar.set_xticklabels(['0°', '90°', '180°', '270°'], fontsize=6)
    ax_polar.tick_params(pad=2)
    ax_polar.set_title('Coverage\n(mean over revolutions)', fontsize=7, pad=8)

    return fig


def _make_spoke_presence_figure(key: str, stats: dict):
    """
    Returns a standalone 2-panel Figure showing which azimuth indices (0…N-1)
    were received in each revolution:
      Top panel    — presence matrix: rows = revolutions, cols = azimuth index.
                     White = received, red = missing.
      Bottom panel — received-count bar: for each azimuth index, in how many
                     revolutions was it received (0 = never, total_revs = always).
    Returns None if matplotlib is unavailable or no data exists.
    """
    try:
        import matplotlib as _mpl
        _mpl.use('Agg')
        import matplotlib.pyplot as _plt
        import matplotlib.colors as _mcolors
        import matplotlib.gridspec as _gridspec
    except ImportError:
        return None

    presence_matrix = stats.get('presence_matrix')
    if presence_matrix is None or presence_matrix.size == 0:
        return None

    n_revs, spokes_per_rev = presence_matrix.shape
    total_revs    = stats['total_revs']
    median_step   = stats['median_step']

    # How many revolutions received each index
    received_count = presence_matrix.sum(axis=0)   # shape (spokes_per_rev,)

    # Shared tick positions: every 90°
    deg_ticks  = [0, 90, 180, 270, 360]
    idx_ticks  = [int(d / median_step) for d in deg_ticks]
    idx_ticks[-1] = spokes_per_rev   # clamp 360° → last index

    fig = _plt.figure(figsize=(16, 5), facecolor='white')
    gs  = _gridspec.GridSpec(2, 1, height_ratios=[3, 1], hspace=0.5,
                              left=0.05, right=0.98, top=0.91, bottom=0.09)
    ax_pres = fig.add_subplot(gs[0])
    ax_cnt  = fig.add_subplot(gs[1])

    # ── Presence matrix ───────────────────────────────────────────────────────
    cmap = _mcolors.LinearSegmentedColormap.from_list('pres', ['#e63946', '#ffffff'])
    ax_pres.imshow(presence_matrix, aspect='auto', origin='upper',
                   interpolation='nearest', cmap=cmap, vmin=0, vmax=1)
    ax_pres.set_ylabel('Revolution', fontsize=7)
    ax_pres.set_xlabel('Azimuth index', fontsize=7)
    ax_pres.set_title(
        f'Azimuth Index Presence per Revolution  —  {key}  '
        f'(white = received, red = missing)',
        fontsize=9)

    # Bottom X: azimuth index
    ax_pres.set_xticks(idx_ticks)
    ax_pres.set_xticklabels([str(i) for i in idx_ticks], fontsize=7)

    # Top X: degrees
    ax_pres2 = ax_pres.twiny()
    ax_pres2.set_xlim(ax_pres.get_xlim())
    ax_pres2.set_xticks(idx_ticks)
    ax_pres2.set_xticklabels([f'{d}°' for d in deg_ticks], fontsize=7)
    ax_pres2.set_xlabel('Azimuth (°)', fontsize=7)

    # Y ticks
    n_ticks  = min(10, n_revs)
    tick_idx = np.linspace(0, n_revs - 1, n_ticks, dtype=int)
    ax_pres.set_yticks(tick_idx + 0.5)
    ax_pres.set_yticklabels([str(i + 1) for i in tick_idx], fontsize=7)

    # ── Received-count bar chart ──────────────────────────────────────────────
    # Color: green if received in all revolutions, red if never, grey in-between
    frac = received_count / total_revs if total_revs > 0 else received_count
    colors = np.where(frac >= 1.0, '#2a9d8f',
             np.where(frac <= 0.0, '#e63946', '#aaaaaa'))
    ax_cnt.bar(np.arange(spokes_per_rev), received_count,
               width=1.0, color=colors, linewidth=0, align='edge')
    ax_cnt.set_xlim(0, spokes_per_rev)
    ax_cnt.set_ylim(0, total_revs)
    ax_cnt.set_xlabel('Azimuth index', fontsize=7)
    ax_cnt.set_ylabel('Revolutions\nreceived', fontsize=7)
    ax_cnt.set_xticks(idx_ticks)
    ax_cnt.set_xticklabels([str(i) for i in idx_ticks], fontsize=7)
    ax_cnt.tick_params(axis='y', labelsize=7)
    ax_cnt.axhline(y=total_revs, color='#2a9d8f', linewidth=0.6,
                   linestyle='--', alpha=0.7)

    return fig


def _make_reference_grid_figure(key: str, stats: dict):
    """
    Returns a 2-panel Figure comparing the radar's actual transmissions against
    a user-specified reference grid (e.g. 4096 spokes/rev):
      Top panel    — presence matrix: rows = revolutions, cols = reference index.
                     White = azimuth position received, red = never received.
      Bottom panel — received-count bar: for each reference index, in how many
                     revolutions it was received (green = always, red = never).
    Returns None if no reference_matrix exists or matplotlib is unavailable.
    """
    try:
        import matplotlib as _mpl
        _mpl.use('Agg')
        import matplotlib.pyplot as _plt
        import matplotlib.colors as _mcolors
        import matplotlib.gridspec as _gridspec
    except ImportError:
        return None

    ref_matrix  = stats.get('reference_matrix')
    ref_spokes  = stats.get('reference_spokes')
    if ref_matrix is None or ref_matrix.size == 0 or not ref_spokes:
        return None

    n_revs, ref_n  = ref_matrix.shape
    total_revs     = stats['total_revs']
    spokes_per_rev = stats['spokes_per_rev']
    ref_step       = 360.0 / ref_n

    received_count   = ref_matrix.sum(axis=0)          # shape (ref_n,)
    # Per-revolution: mean number of reference positions covered in one revolution
    mean_per_rev     = float(ref_matrix.sum(axis=1).mean())
    mean_coverage_pct = 100.0 * mean_per_rev / ref_n

    deg_ticks = [0, 90, 180, 270, 360]
    idx_ticks = [int(d / ref_step) for d in deg_ticks]
    idx_ticks[-1] = ref_n   # clamp 360° to last index

    fig = _plt.figure(figsize=(16, 5), facecolor='white')
    gs  = _gridspec.GridSpec(2, 1, height_ratios=[3, 1], hspace=0.5,
                              left=0.05, right=0.98, top=0.91, bottom=0.09)
    ax_pres = fig.add_subplot(gs[0])
    ax_cnt  = fig.add_subplot(gs[1])

    # ── Presence matrix ───────────────────────────────────────────────────────
    cmap = _mcolors.LinearSegmentedColormap.from_list('pres', ['#e63946', '#ffffff'])
    ax_pres.imshow(ref_matrix, aspect='auto', origin='upper',
                   interpolation='nearest', cmap=cmap, vmin=0, vmax=1)
    ax_pres.set_ylabel('Revolution', fontsize=7)
    ax_pres.set_xlabel('Reference azimuth index', fontsize=7)
    ax_pres.set_title(
        f'Reference Grid Coverage  —  {key}  '
        f'(actual: {spokes_per_rev} spokes/rev  vs.  reference: {ref_n}  →  '
        f'{mean_per_rev:.0f} positions/revolution = {mean_coverage_pct:.1f}%  transmitted)',
        fontsize=9)

    ax_pres.set_xticks(idx_ticks)
    ax_pres.set_xticklabels([str(i) for i in idx_ticks], fontsize=7)

    ax_pres2 = ax_pres.twiny()
    ax_pres2.set_xlim(ax_pres.get_xlim())
    ax_pres2.set_xticks(idx_ticks)
    ax_pres2.set_xticklabels([f'{d}°' for d in deg_ticks], fontsize=7)
    ax_pres2.set_xlabel('Azimuth (°)', fontsize=7)

    n_ticks  = min(10, n_revs)
    tick_idx = np.linspace(0, n_revs - 1, n_ticks, dtype=int)
    ax_pres.set_yticks(tick_idx + 0.5)
    ax_pres.set_yticklabels([str(i + 1) for i in tick_idx], fontsize=7)

    # ── Received-count bar chart ──────────────────────────────────────────────
    frac   = received_count / total_revs if total_revs > 0 else received_count
    colors = np.where(frac >= 1.0, '#2a9d8f',
             np.where(frac <= 0.0, '#e63946', '#aaaaaa'))
    ax_cnt.bar(np.arange(ref_n), received_count,
               width=1.0, color=colors, linewidth=0, align='edge')
    ax_cnt.set_xlim(0, ref_n)
    ax_cnt.set_ylim(0, total_revs)
    ax_cnt.set_xlabel('Reference azimuth index', fontsize=7)
    ax_cnt.set_ylabel('Revolutions\nreceived', fontsize=7)
    ax_cnt.set_xticks(idx_ticks)
    ax_cnt.set_xticklabels([str(i) for i in idx_ticks], fontsize=7)
    ax_cnt.tick_params(axis='y', labelsize=7)
    ax_cnt.axhline(y=total_revs, color='#2a9d8f', linewidth=0.6,
                   linestyle='--', alpha=0.7)

    return fig


def _make_overview_figure(streams: dict):
    """
    Returns a matplotlib Figure with one frequency-chart row per stream,
    sharing the same x-axis — for a quick cross-stream comparison.
    Returns None if no stream has stats or matplotlib is unavailable.
    """
    try:
        import matplotlib as _mpl
        _mpl.use('Agg')
        import matplotlib.pyplot as _plt
        import matplotlib.patches as _mpatches
    except ImportError:
        return None

    stream_stats = [
        (key, _compute_rev_stats(s['az_list'], s['timestamps'],
                                 end_az_list=s.get('end_az_list')))
        for key, s in sorted(streams.items(), key=_stream_sort_key)
    ]
    stream_stats = [(k, st) for k, st in stream_stats if st is not None]
    if not stream_stats:
        return None

    n = len(stream_stats)
    fig, axes = _plt.subplots(n, 1, figsize=(12, 2.2 * n + 0.8),
                               sharex=True, facecolor='white')
    if n == 1:
        axes = [axes]

    fig.subplots_adjust(left=0.07, right=0.97, top=0.92, bottom=0.08,
                        hspace=0.55)
    fig.suptitle('Missing Azimuth Frequency — All Streams', fontsize=10)

    x_ticks_deg = [0, 90, 180, 270, 360]

    for ax, (key, stats) in zip(axes, stream_stats):
        total_revs     = stats['total_revs']
        missing_freq   = stats['missing_freq']
        display_cols   = len(missing_freq)
        spokes_per_rev = stats['spokes_per_rev']
        freq_frac = missing_freq / total_revs if total_revs > 0 else missing_freq

        x_edges = np.linspace(0, 360, display_cols, endpoint=False)
        bar_w   = 360.0 / display_cols
        ax.bar(x_edges, freq_frac * 100, width=bar_w,
               color=_freq_colors(freq_frac), linewidth=0, align='edge')
        ax.set_xlim(0, 360)
        ax.set_ylim(0, 100)
        ax.set_ylabel('Missing (%)', fontsize=7)
        ax.set_title(
            f'{key}   (spokes/rev: {spokes_per_rev},  revolutions: {total_revs})',
            fontsize=8,
        )
        ax.tick_params(labelsize=7)
        ax.axhline(y=_FREQ_SYSTEMATIC * 100, color=_COL_SYSTEMATIC,
                   linewidth=0.6, linestyle='--', alpha=0.6)
        ax.axhline(y=_FREQ_FREQUENT * 100,   color=_COL_FREQUENT,
                   linewidth=0.6, linestyle='--', alpha=0.6)

        # Top X: azimuth index
        x_ticks_idx = [int(d * spokes_per_rev / 360) for d in x_ticks_deg]
        ax2 = ax.twiny()
        ax2.set_xlim(ax.get_xlim())
        ax2.set_xticks(x_ticks_deg)
        ax2.set_xticklabels([str(i) for i in x_ticks_idx], fontsize=6)
        ax2.set_xlabel('Azimuth index', fontsize=6)

    axes[-1].set_xlabel('Azimuth (°)', fontsize=7)
    axes[-1].set_xticks(x_ticks_deg)
    axes[-1].set_xticklabels([f'{d}°' for d in x_ticks_deg], fontsize=7)

    # Shared legend on the last axis
    legend_elements = [
        _mpatches.Patch(facecolor=_COL_SYSTEMATIC, label=f'Systematic (>{int(_FREQ_SYSTEMATIC*100)}%)'),
        _mpatches.Patch(facecolor=_COL_FREQUENT,   label=f'Frequent (>{int(_FREQ_FREQUENT*100)}%)'),
        _mpatches.Patch(facecolor=_COL_SPORADIC,   label='Sporadic (>0%)'),
        _mpatches.Patch(facecolor=_COL_NONE,       label='Never missing'),
    ]
    axes[-1].legend(handles=legend_elements, fontsize=6, loc='upper right',
                    framealpha=0.8)

    return fig


def _save_figures(filepath: str, streams: dict, expected_spokes: int = 0):
    """Save per-stream figures and overview figure as PNG files."""
    import os
    try:
        import matplotlib.pyplot as _plt
    except ImportError:
        print("matplotlib not installed — cannot save figures.", file=sys.stderr)
        return

    base = os.path.splitext(filepath)[0]

    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        stats = _compute_rev_stats(s['az_list'], s['timestamps'],
                                   expected_spokes=expected_spokes,
                                   end_az_list=s.get('end_az_list'))
        if stats is None:
            continue
        fig = _make_stream_figure(key, stats)
        if fig is None:
            continue
        safe_key = key.replace(':', '_').replace('/', '_')
        out_path = f"{base}_azcheck_stream{idx}_{safe_key}.png"
        fig.savefig(out_path, dpi=150, bbox_inches='tight')
        _plt.close(fig)
        if RICH:
            console.print(f"[dim]Figure saved:    [cyan]{out_path}[/][/]")
        else:
            print(f"Figure saved: {out_path}")

        fig2 = _make_spoke_presence_figure(key, stats)
        if fig2 is not None:
            out_path2 = f"{base}_azcheck_stream{idx}_{safe_key}_presence.png"
            fig2.savefig(out_path2, dpi=150, bbox_inches='tight')
            _plt.close(fig2)
            if RICH:
                console.print(f"[dim]Figure saved:    [cyan]{out_path2}[/][/]")
            else:
                print(f"Figure saved: {out_path2}")

        fig3 = _make_reference_grid_figure(key, stats)
        if fig3 is not None:
            out_path3 = f"{base}_azcheck_stream{idx}_{safe_key}_refgrid.png"
            fig3.savefig(out_path3, dpi=150, bbox_inches='tight')
            _plt.close(fig3)
            if RICH:
                console.print(f"[dim]Figure saved:    [cyan]{out_path3}[/][/]")
            else:
                print(f"Figure saved: {out_path3}")

    if len(streams) > 1:
        fig = _make_overview_figure(streams)
        if fig is not None:
            out_path = f"{base}_azcheck_overview.png"
            fig.savefig(out_path, dpi=150, bbox_inches='tight')
            _plt.close(fig)
            if RICH:
                console.print(f"[dim]Figure saved:    [cyan]{out_path}[/][/]")
            else:
                print(f"Figure saved: {out_path}")


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
            sac, sic, start_az, end_az = result
            key = f"{dst_ip}:{dst_port}"
            if key not in streams:
                streams[key] = {
                    'az_list':     [],
                    'end_az_list': [],
                    'timestamps':  [],
                    'sac_sic':     Counter(),
                    'src_ips':     set(),
                    'msg_count':   0,
                }
            s = streams[key]
            s['az_list'].append(start_az)
            s['end_az_list'].append(end_az)
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


def print_report(filepath: str, streams: dict, total_udp: int, non_cat240: int,
                 expected_spokes: int = 0):
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
        stats = _compute_rev_stats(s['az_list'], s['timestamps'],
                                   expected_spokes=expected_spokes,
                                   end_az_list=s.get('end_az_list'))
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
            f"Max missing: [bold red]{stats['max_missing']}[/]\n"
            f"  Msgs/rev (mean): [bold]{stats['mean_msgs']:.1f}[/]   "
            f"Unique az/rev: [bold]{stats['mean_unique']:.1f}[/]   "
            f"Duplicates/rev: [bold yellow]{stats['mean_duplicate']:.1f}[/]"
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

        # Coverage vs. expected
        cov = stats.get('coverage')
        if cov:
            console.print()
            bw_str = (f"  Beam width: [bold]{cov['mean_beam_width']:.4f}°[/]"
                      if cov['mean_beam_width'] > 0 else "")
            rpm_str = (f"  RPM: [bold]{cov['rpm']:.1f}[/]  Period: {cov['rev_period']:.2f} s"
                       if cov['rpm'] > 0 else "")
            console.print(
                f"  [bold yellow]Coverage vs. expected {cov['expected_spokes']} az/rev:[/]  "
                f"[bold]{cov['coverage_pct']:.1f}%[/]"
                f"  ([red]{cov['missing_per_rev']} missing/rev = {100 - cov['coverage_pct']:.1f}%[/])"
                f"{bw_str}{rpm_str}"
            )

        # Worst revolutions
        worst = stats['worst_revs']
        if worst and worst[0]['missing'] > 0:
            console.print("  [bold]Worst revolutions:[/]")
            for r in worst:
                if r['missing'] == 0:
                    break
                dup = r['total_msgs'] - r['unique_az']
                console.print(
                    f"    Rev #{r['idx']:>4d}  msgs: {r['total_msgs']:>4d}"
                    f"  unique: {r['unique_az']:>4d}"
                    f"  dup: [yellow]{dup:>3d}[/]"
                    f"  missing: [red]{r['missing']:>4d}[/]"
                    + (f"  ts: {r['ts_start']:.3f}s" if r['ts_start'] else "")
                )

        # Packet span analysis
        span_s = stats.get('span_stats', {})
        if span_s:
            raw_dist = span_s['span_raw_dist']
            step_r   = span_s['step_raw']
            dist_str = "  ".join(
                f"[bold]{sr}[/] raw ({sr/65536*360:.4f}°): [bold]{cnt:,}[/]×"
                for sr, cnt in sorted(raw_dist.items())
            )
            console.print(f"\n  [bold]Packet span analysis[/]  (step={step_r} raw = {step_r/65536*360:.4f}°)")
            console.print(f"    {dist_str}")
            console.print(
                f"    Zero-span (0 raw):       [yellow]{span_s['zero_span_total']:,}[/] total"
                f"  ({span_s['zero_span_per_rev']:.1f}/rev)"
            )
            if span_s['zero_span_examples']:
                console.print("    Zero-span examples:")
                for ts_ex, az_ex in span_s['zero_span_examples']:
                    console.print(f"      ts={ts_ex:.6f}  az={az_ex:.4f}°")
            if span_s['wide_span_total']:
                console.print(
                    f"    Wide-span (> {step_r} raw):  {span_s['wide_span_total']:,} total"
                    f"  ({span_s['wide_span_per_rev']:.1f}/rev)"
                )
            if span_s['wide_span_examples']:
                console.print("    Wide-span examples:")
                for ts_ex, sa_ex, ea_ex in span_s['wide_span_examples']:
                    span_ex = (ea_ex - sa_ex) % 360.0
                    console.print(
                        f"      ts={ts_ex:.6f}  start={sa_ex:.4f}°"
                        f"  end={ea_ex:.4f}°  span={span_ex:.4f}°"
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

def print_report_plain(filepath: str, streams: dict, total_udp: int, non_cat240: int,
                       expected_spokes: int = 0):
    sep = "=" * 70
    total_msgs = sum(s['msg_count'] for s in streams.values())
    print(f"\n{sep}\nAZIMUTH COMPLETENESS: {filepath}\n{sep}")
    print(f"UDP: {total_udp}  CAT240: {total_msgs}  Streams: {len(streams)}")

    for key, s in sorted(streams.items(), key=_stream_sort_key):
        stats = _compute_rev_stats(s['az_list'], s['timestamps'],
                                   expected_spokes=expected_spokes,
                                   end_az_list=s.get('end_az_list'))
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
        print(f"  Msgs/rev (mean) : {stats['mean_msgs']:.1f}  "
              f"Unique az: {stats['mean_unique']:.1f}  "
              f"Duplicates: {stats['mean_duplicate']:.1f}")
        print("  Distribution    :")
        for mc in sorted(stats['missing_dist']):
            n = stats['missing_dist'][mc]
            print(f"    missing={mc:4d} : {n:6,} revs  ({100*n/total_revs:.1f}%)")
        cov = stats.get('coverage')
        if cov:
            print(f"  Coverage vs. expected {cov['expected_spokes']} az/rev:")
            print(f"    Coverage per revolution   : {cov['coverage_pct']:.1f}%"
                  f"  ({cov['missing_per_rev']} missing = {100 - cov['coverage_pct']:.1f}%)")
            if cov['mean_beam_width'] > 0:
                print(f"    Mean beam width           : {cov['mean_beam_width']:.4f} deg")
            if cov['rpm'] > 0:
                print(f"    Antenna RPM               : {cov['rpm']:.1f}")
                print(f"    Revolution period         : {cov['rev_period']:.2f} s")
        span_s = stats.get('span_stats', {})
        if span_s:
            step_r   = span_s['step_raw']
            raw_dist = span_s['span_raw_dist']
            dist_str = "  ".join(
                f"{sr}raw({sr/65536*360:.4f}deg):{cnt}x"
                for sr, cnt in sorted(raw_dist.items())
            )
            print(f"  Span distribution (step={step_r}raw): {dist_str}")
            print(f"  Zero-span (0 raw)      : {span_s['zero_span_total']:,} total"
                  f"  ({span_s['zero_span_per_rev']:.1f}/rev)")
            for ts_ex, az_ex in span_s['zero_span_examples']:
                print(f"    example: ts={ts_ex:.6f}  az={az_ex:.4f} deg")
            if span_s['wide_span_total']:
                print(f"  Wide-span (>{step_r}raw) : {span_s['wide_span_total']:,} total"
                      f"  ({span_s['wide_span_per_rev']:.1f}/rev)")
            for ts_ex, sa_ex, ea_ex in span_s['wide_span_examples']:
                span_ex = (ea_ex - sa_ex) % 360.0
                print(f"    example: ts={ts_ex:.6f}  start={sa_ex:.4f} deg"
                      f"  end={ea_ex:.4f} deg  span={span_ex:.4f} deg")
        if stats['top_missing_pos']:
            pos_str = "  ".join(f"{az:.3f}°({cnt}×)" for az, cnt in stats['top_missing_pos'][:5])
            print(f"  Freq. missing az.: {pos_str}")


# ─────────────────────────────────────────────────────────────────────────────
# Markdown report
# ─────────────────────────────────────────────────────────────────────────────

def write_markdown(filepath: str, streams: dict, total_udp: int, non_cat240: int,
                   md_path: str, expected_spokes: int = 0):
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
        stats = _compute_rev_stats(s['az_list'], s['timestamps'],
                                   expected_spokes=expected_spokes,
                                   end_az_list=s.get('end_az_list'))
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
        w(f"| Messages/revolution (mean) | {stats['mean_msgs']:.1f} |")
        w(f"| Unique azimuths/revolution (mean) | {stats['mean_unique']:.1f} |")
        w(f"| Duplicate messages/revolution (mean) | {stats['mean_duplicate']:.1f} |")
        w(f"| Mean missing per revolution | {stats['mean_missing']:.2f} |")
        w(f"| Max missing in one revolution | {stats['max_missing']} |")
        w("")

        cov = stats.get('coverage')
        if cov:
            w(f"### Coverage vs. Expected {cov['expected_spokes']} Azimuths/Revolution")
            w("")
            w(f"| Parameter | Value |")
            w(f"|---|---|")
            w(f"| Expected azimuths/revolution | {cov['expected_spokes']} |")
            w(f"| Observed azimuths/revolution | ~{stats['spokes_per_rev']} |")
            w(f"| Coverage per revolution | {cov['coverage_pct']:.1f}% |")
            w(f"| Missing per revolution (vs. expected) | {cov['missing_per_rev']} "
              f"({100 - cov['coverage_pct']:.1f}%) |")
            if cov['mean_beam_width'] > 0:
                w(f"| Mean beam width (end_az \u2212 start_az) | {cov['mean_beam_width']:.4f}\u00b0 |")
            if cov['rpm'] > 0:
                w(f"| Antenna RPM | {cov['rpm']:.1f} |")
                w(f"| Revolution period | {cov['rev_period']:.2f} s |")
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
            w("| Rev # | Total msgs | Unique az | Duplicates | Missing | Timestamp (s) |")
            w("|---:|---:|---:|---:|---:|---:|")
            for r in worst:
                if r['missing'] == 0:
                    break
                dup    = r['total_msgs'] - r['unique_az']
                ts_str = f"{r['ts_start']:.3f}" if r['ts_start'] else "—"
                w(f"| {r['idx']} | {r['total_msgs']} | {r['unique_az']} "
                  f"| {dup} | {r['missing']} | {ts_str} |")
            w("")

        span_s = stats.get('span_stats', {})
        if span_s:
            step_r   = span_s['step_raw']
            raw_dist = span_s['span_raw_dist']
            w("### Packet span analysis")
            w("")
            w(f"Step size: {step_r} raw units = {step_r/65536*360:.4f}°")
            w("")
            w("| Span (raw) | Span (°) | Count |")
            w("|---:|---:|---:|")
            for sr, cnt in sorted(raw_dist.items()):
                w(f"| {sr} | {sr/65536*360:.4f} | {cnt:,} |")
            w("")
            w(f"**Zero-span (0 raw):** {span_s['zero_span_total']:,} packets total"
              f" ({span_s['zero_span_per_rev']:.1f}/revolution)")
            w("")
            if span_s['zero_span_examples']:
                w("Zero-span examples:")
                w("")
                w("| Timestamp (s) | Start azimuth (°) |")
                w("|---:|---:|")
                for ts_ex, az_ex in span_s['zero_span_examples']:
                    w(f"| {ts_ex:.6f} | {az_ex:.4f} |")
                w("")
            if span_s['wide_span_total']:
                w(f"**Wide-span (> {step_r} raw):** {span_s['wide_span_total']:,} packets total"
                  f" ({span_s['wide_span_per_rev']:.1f}/revolution)")
                w("")
            if span_s['wide_span_examples']:
                w("Wide-span examples:")
                w("")
                w("| Timestamp (s) | Start azimuth (°) | End azimuth (°) | Span (°) |")
                w("|---:|---:|---:|---:|")
                for ts_ex, sa_ex, ea_ex in span_s['wide_span_examples']:
                    span_ex = (ea_ex - sa_ex) % 360.0
                    w(f"| {ts_ex:.6f} | {sa_ex:.4f} | {ea_ex:.4f} | {span_ex:.4f} |")
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
              pdf_path: str, expected_spokes: int = 0) -> None:
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
        stats = _compute_rev_stats(s['az_list'], s['timestamps'],
                                   expected_spokes=expected_spokes,
                                   end_az_list=s.get('end_az_list'))
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
        stats = _compute_rev_stats(s['az_list'], s['timestamps'],
                                   expected_spokes=expected_spokes,
                                   end_az_list=s.get('end_az_list'))
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
            ('Expected az/revolution',              str(stats['spokes_per_rev'])),
            ('Azimuth step (median)',                f"{stats['median_step']:.4f} deg"),
            ('Full revolutions',                    f"{total_revs}{partial_note}"),
            ('Complete revolutions (0 missing)',    f"{stats['complete_revs']} ({pct_complete:.1f}%)"),
            ('Messages/revolution (mean)',          f"{stats['mean_msgs']:.1f}"),
            ('Unique azimuths/revolution (mean)',   f"{stats['mean_unique']:.1f}"),
            ('Duplicate messages/revolution (mean)',f"{stats['mean_duplicate']:.1f}"),
            ('Mean missing per revolution',         f"{stats['mean_missing']:.2f}"),
            ('Max missing in one revolution',       str(stats['max_missing'])),
        ]
        h3('Summary', table_rows=len(summary_rows))
        kv_table(summary_rows)

        cov = stats.get('coverage')
        if cov:
            cov_rows = [
                ('Expected azimuths/revolution',  str(cov['expected_spokes'])),
                ('Observed azimuths/revolution',  f"~{stats['spokes_per_rev']}"),
                ('Coverage per revolution',       f"{cov['coverage_pct']:.1f}%"),
                ('Missing per revolution (vs. expected)',
                 f"{cov['missing_per_rev']} ({100 - cov['coverage_pct']:.1f}%)"),
            ]
            if cov['mean_beam_width'] > 0:
                cov_rows.append(('Mean beam width (end_az - start_az)',
                                 f"{cov['mean_beam_width']:.4f} deg"))
            if cov['rpm'] > 0:
                cov_rows += [
                    ('Antenna RPM',       f"{cov['rpm']:.1f}"),
                    ('Revolution period', f"{cov['rev_period']:.2f} s"),
                ]
            h3(f'Coverage vs. Expected {cov["expected_spokes"]} Azimuths/Revolution',
               table_rows=len(cov_rows))
            kv_table(cov_rows)

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
                dup    = r['total_msgs'] - r['unique_az']
                ts_str = f"{r['ts_start']:.3f}" if r['ts_start'] else '-'
                worst_rows.append([str(r['idx']), str(r['total_msgs']),
                                   str(r['unique_az']), str(dup),
                                   str(r['missing']), ts_str])
            h3('Worst revolutions', table_rows=len(worst_rows))
            wide_table(['Rev #', 'Total msgs', 'Unique az', 'Dup', 'Missing', 'Timestamp (s)'],
                       worst_rows, [20, 28, 28, 20, 28, 38])

        if stats['top_missing_pos']:
            pos_rows = [[f"{az:.3f} deg", str(cnt)]
                        for az, cnt in stats['top_missing_pos']]
            h3('Most frequently missing azimuth positions', table_rows=len(pos_rows))
            wide_table(['Azimuth', 'Revolutions missing'], pos_rows, [60, 60])

        span_s = stats.get('span_stats', {})
        if span_s:
            step_r   = span_s['step_raw']
            raw_dist = span_s['span_raw_dist']
            dist_rows = [
                [str(sr), f"{sr/65536*360:.4f} deg", f"{cnt:,}"]
                for sr, cnt in sorted(raw_dist.items())
            ]
            h3(f'Packet span analysis  (step = {step_r} raw = {step_r/65536*360:.4f} deg)',
               table_rows=len(dist_rows))
            wide_table(['Span (raw)', 'Span (deg)', 'Count'], dist_rows, [40, 55, 55])
            _ensure_space(8)
            pdf.set_font('Helvetica', '', 8)
            pdf.cell(W, 5,
                     _s(f"Zero-span (0 raw): {span_s['zero_span_total']:,} total"
                        f"  ({span_s['zero_span_per_rev']:.1f}/rev)"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if span_s['wide_span_total']:
                pdf.cell(W, 5,
                         _s(f"Wide-span (>{step_r} raw): {span_s['wide_span_total']:,} total"
                            f"  ({span_s['wide_span_per_rev']:.1f}/rev)"),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)
            if span_s['zero_span_examples']:
                ex_rows = [[f"{ts_ex:.6f}", f"{az_ex:.4f} deg"]
                           for ts_ex, az_ex in span_s['zero_span_examples']]
                h3('Zero-span examples', table_rows=len(ex_rows))
                wide_table(['Timestamp (s)', 'Start azimuth'], ex_rows, [60, 60])
            if span_s['wide_span_examples']:
                ex_rows2 = [
                    [f"{ts_ex:.6f}", f"{sa_ex:.4f}", f"{ea_ex:.4f}",
                     f"{(ea_ex - sa_ex) % 360.0:.4f}"]
                    for ts_ex, sa_ex, ea_ex in span_s['wide_span_examples']
                ]
                h3('Wide-span examples', table_rows=len(ex_rows2))
                wide_table(['Timestamp (s)', 'Start az (deg)', 'End az (deg)', 'Span (deg)'],
                           ex_rows2, [48, 44, 44, 40])

        # ── Per-stream figure (heatmap + frequency chart + coverage ring) ───────
        fig = _make_stream_figure(key, stats)
        if fig is not None:
            import io as _io
            import matplotlib.pyplot as _plt
            fig_w_in, fig_h_in = fig.get_size_inches()
            img_h_mm = W * (fig_h_in / fig_w_in)
            _ensure_space(9 + img_h_mm)
            h3('Missing Azimuth Heatmap & Frequency', table_rows=0)
            buf = _io.BytesIO()
            fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            _plt.close(fig)
            buf.seek(0)
            pdf.image(buf, x=14, w=W)

        # ── Per-stream spoke presence figure (full index resolution) ──────────
        fig2 = _make_spoke_presence_figure(key, stats)
        if fig2 is not None:
            import io as _io
            import matplotlib.pyplot as _plt
            fig_w_in, fig_h_in = fig2.get_size_inches()
            img_h_mm = W * (fig_h_in / fig_w_in)
            _ensure_space(9 + img_h_mm)
            h3('Azimuth Index Presence per Revolution', table_rows=0)
            buf = _io.BytesIO()
            fig2.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            _plt.close(fig2)
            buf.seek(0)
            pdf.image(buf, x=14, w=W)

        # ── Reference grid figure (coverage vs. expected N-spoke grid) ────────
        fig3 = _make_reference_grid_figure(key, stats)
        if fig3 is not None:
            import io as _io
            import matplotlib.pyplot as _plt
            fig_w_in, fig_h_in = fig3.get_size_inches()
            img_h_mm = W * (fig_h_in / fig_w_in)
            _ensure_space(9 + img_h_mm)
            ref_n = stats['reference_spokes']
            h3(f'Reference Grid Coverage ({ref_n} spokes/rev)', table_rows=0)
            buf = _io.BytesIO()
            fig3.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            _plt.close(fig3)
            buf.seek(0)
            pdf.image(buf, x=14, w=W)

    # ── Overview figure (all streams, frequency only) ─────────────────────────
    if len(streams) > 1:
        fig = _make_overview_figure(streams)
        if fig is not None:
            import io as _io
            import matplotlib.pyplot as _plt
            fig_w_in, fig_h_in = fig.get_size_inches()
            img_h_mm = W * (fig_h_in / fig_w_in)
            pdf.add_page()
            h2('Missing Azimuth Frequency — All Streams')
            buf = _io.BytesIO()
            fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            _plt.close(fig)
            buf.seek(0)
            pdf.image(buf, x=14, w=W)

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
    parser.add_argument("--plot", action="store_true",
                        help="Save per-stream heatmap+frequency figures as PNG files")
    parser.add_argument("--expected-spokes", "-e", type=int, default=0,
                        metavar="N",
                        help="Reference grid size for coverage comparison figure "
                             "(e.g. 4096); generates an extra heatmap showing which "
                             "of the N expected azimuth positions the radar actually "
                             "transmits. Only useful when N differs from the "
                             "auto-detected spokes/rev.")
    args = parser.parse_args()

    import os
    import glob as _glob

    # On Windows the shell does not expand wildcards, so do it here.
    expanded = []
    for pattern in args.file:
        matches = _glob.glob(pattern)
        if matches:
            expanded.extend(sorted(matches))
        else:
            expanded.append(pattern)   # keep as-is; FileNotFoundError will follow
    args.file = expanded

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
                print_report(filepath, streams, total_udp, non_cat240,
                             expected_spokes=args.expected_spokes)
            else:
                print_report_plain(filepath, streams, total_udp, non_cat240,
                                   expected_spokes=args.expected_spokes)

            write_markdown(filepath, streams, total_udp, non_cat240, md_path=md_path,
                           expected_spokes=args.expected_spokes)
            if RICH:
                console.print(f"[dim]Markdown saved: [cyan]{md_path}[/][/]")
            else:
                print(f"Markdown saved: {md_path}")

            if pdf_path is not None:
                write_pdf(filepath, streams, total_udp, non_cat240, pdf_path,
                          expected_spokes=args.expected_spokes)
                if RICH:
                    console.print(f"[dim]PDF saved:      [cyan]{pdf_path}[/][/]")
                else:
                    print(f"PDF saved: {pdf_path}")

            if args.plot:
                _save_figures(filepath, streams, expected_spokes=args.expected_spokes)

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
