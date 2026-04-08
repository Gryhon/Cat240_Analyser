#!/usr/bin/env python3
"""
cat240_stream_info.py – CAT240 Stream Analysis
===============================================
Reads a PCAP/PCAPNG file, auto-detects all contained CAT240 streams
(by destination IP:port + SAC/SIC) and prints detailed statistics.

Usage:
    python cat240_stream_info.py Data/aufzeichnung.pcapng
    python cat240_stream_info.py Data/aufzeichnung.pcapng --packets 5000
"""

import argparse
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
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
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Cat240Message:
    start_azimuth_deg: float
    end_azimuth_deg:   float
    start_range_cell:  int
    cell_duration_raw: int        # CELL_DUR raw value (ns for I240/040, fs for I240/041)
    video_data:        np.ndarray
    compression:       int = 0
    num_cells:         int = 0
    sac:               int = 0    # Source Area Code  (from DSI, Item 1)
    sic:               int = 0    # Source Ident Code (from DSI, Item 1)
    fspec_hex:         str = ""
    item_types:        list = field(default_factory=list, repr=False)
    cell_bits:         int = 0    # 8, 16 or 32


# ─────────────────────────────────────────────────────────────────────────────
# CAT240 Decoder
# ─────────────────────────────────────────────────────────────────────────────

class Cat240Decoder:

    def decode(self, data: bytes) -> Optional[Cat240Message]:
        if len(data) < 3 or data[0] != 0xF0:
            return None
        length = struct.unpack(">H", data[1:3])[0]
        if length > len(data):
            return None

        offset = 3
        fspec = []
        while offset < length:
            byte = data[offset]
            fspec.append(byte)
            offset += 1
            if not (byte & 0x01):
                break

        active_items = []
        for i, byte in enumerate(fspec):
            for bit in range(7, 0, -1):
                if byte & (1 << bit):
                    active_items.append(i * 7 + (8 - bit))

        result = {
            'start_az': 0.0, 'end_az': 0.0,
            'start_cell': 0, 'cell_dur_raw': 0,
            'video': np.array([], dtype=np.float32),
            'num_cells': 0, 'compression': 0,
            'sac': 0, 'sic': 0, 'cell_bits': 0, 'res': 0,
        }

        for item in active_items:
            if offset >= length:
                break
            offset = self._parse_item(data, offset, length, item, result)
            if offset is None:
                break

        if result['video'].size == 0:
            return None

        return Cat240Message(
            start_azimuth_deg = result['start_az'],
            end_azimuth_deg   = result['end_az'],
            start_range_cell  = result['start_cell'],
            cell_duration_raw = result['cell_dur_raw'],
            video_data        = result['video'],
            compression       = result['compression'],
            num_cells         = result['num_cells'],
            sac               = result['sac'],
            sic               = result['sic'],
            fspec_hex         = bytes(fspec).hex(),
            item_types        = active_items,
            cell_bits         = result['cell_bits'],
        )

    def _parse_item(self, data, offset, length, item, result):
        try:
            if item == 1:
                # I240/010 – DSI: SAC + SIC (1 byte each)
                if offset + 2 <= length:
                    result['sac'] = data[offset]
                    result['sic'] = data[offset + 1]
                return offset + 2

            elif item == 2:
                # I240/000 – Message Type, 1 byte
                return offset + 1

            elif item == 3:
                # I240/020 – Video Record Header (MSG_INDEX 32 bit), 4 bytes
                return offset + 4

            elif item == 4:
                # I240/030 – Video Summary (1B REP + REP×1B ASCII characters)
                if offset >= length: return length
                return offset + 1 + data[offset]

            elif item == 5:
                # I240/040 – Video Header Nano, 12 bytes
                # START_AZ(2B,LSB=360/2^16) + END_AZ(2B) + START_RG(4B) + CELL_DUR(4B,LSB=10^-9 s)
                if offset + 12 > length: return length
                sa = struct.unpack(">H", data[offset:offset+2])[0]
                ea = struct.unpack(">H", data[offset+2:offset+4])[0]
                result['start_az']    = sa / 65536.0 * 360.0
                result['end_az']      = ea / 65536.0 * 360.0
                result['start_cell']  = struct.unpack(">I", data[offset+4:offset+8])[0]
                result['cell_dur_raw']= struct.unpack(">I", data[offset+8:offset+12])[0]
                return offset + 12

            elif item == 6:
                # I240/041 – Video Header Femto, 12 bytes
                # START_AZ(2B,LSB=360/2^16) + END_AZ(2B) + START_RG(4B) + CELL_DUR(4B,LSB=10^-15 s)
                if offset + 12 > length: return length
                sa = struct.unpack(">H", data[offset:offset+2])[0]
                ea = struct.unpack(">H", data[offset+2:offset+4])[0]
                result['start_az']    = sa / 65536.0 * 360.0
                result['end_az']      = ea / 65536.0 * 360.0
                result['start_cell']  = struct.unpack(">I", data[offset+4:offset+8])[0]
                result['cell_dur_raw']= struct.unpack(">I", data[offset+8:offset+12])[0]
                return offset + 12

            elif item == 7:
                # I240/048 – Video Cells Resolution & Compression Indicator, 2 bytes
                # Bit16=C (compression), Bits15-9=Spare, Bits8-1=RES
                if offset + 2 <= length:
                    result['compression'] = (data[offset] >> 7) & 1
                    result['res']         = data[offset + 1]
                    result['cell_bits']   = {1:1,2:2,3:4,4:8,5:16,6:32}.get(result['res'], 0)
                return offset + 2

            elif item == 8:
                # I240/049 – Video Octets & Video Cells Counters, 5 bytes
                # NB_VB(2B) + NB_CELLS(3B)
                if offset + 5 <= length:
                    nb_cells = struct.unpack(">I", b'\x00' + data[offset+2:offset+5])[0]
                    if nb_cells > 0:
                        result['num_cells'] = nb_cells
                return offset + 5

            elif item == 9:
                # I240/050 – Video Block Low Data Volume (1B REP + REP×4B)
                if offset >= length: return length
                rep = data[offset]
                video_bytes = rep * 4
                if offset + 1 + video_bytes <= length:
                    cells = np.frombuffer(data[offset+1:offset+1+video_bytes],
                                          dtype=np.uint8).astype(np.float32)
                    if result['video'].size == 0:
                        result['video'] = cells
                    result['num_cells'] = result['num_cells'] or len(cells)
                return offset + 1 + video_bytes

            elif item == 10:
                # I240/051 – Video Block Medium Data Volume (1B REP + REP×64B)
                if offset >= length: return length
                rep = data[offset]
                video_bytes = rep * 64
                if offset + 1 + video_bytes <= length:
                    dtype = {4: np.uint8, 5: '>u2', 6: '>u4'}.get(result['res'], '>u2')
                    cells = np.frombuffer(data[offset+1:offset+1+video_bytes],
                                          dtype=dtype).astype(np.float32)
                    if result['video'].size == 0:
                        result['video'] = cells
                    result['num_cells'] = result['num_cells'] or len(cells)
                return offset + 1 + video_bytes

            elif item == 11:
                # I240/052 – Video Block High Data Volume (1B REP + REP×256B)
                if offset >= length: return length
                rep = data[offset]
                video_bytes = rep * 256
                if offset + 1 + video_bytes <= length:
                    dtype = {4: np.uint8, 5: '>u2', 6: '>u4'}.get(result['res'], '>u4')
                    cells = np.frombuffer(data[offset+1:offset+1+video_bytes],
                                          dtype=dtype).astype(np.float32)
                    if result['video'].size == 0:
                        result['video'] = cells
                    result['num_cells'] = result['num_cells'] or len(cells)
                return offset + 1 + video_bytes

            elif item == 12:
                # I240/140 – Time of Day, 3 bytes
                return offset + 3

            elif item in (13, 14):
                # RE / SP – variable length (1B total length incl. length byte)
                if offset >= length: return length
                field_len = data[offset]
                return offset + (field_len if field_len > 0 else 1)
            else:
                return offset + 1
        except Exception:
            return length

    def decode_multiple(self, data: bytes) -> List[Cat240Message]:
        messages = []
        offset = 0
        while offset < len(data) - 2:
            if data[offset] != 0xF0:
                break
            length = struct.unpack(">H", data[offset+1:offset+3])[0]
            if length < 3:
                break
            msg = self.decode(data[offset:offset+length])
            if msg:
                messages.append(msg)
            offset += length
        return messages


# ─────────────────────────────────────────────────────────────────────────────
# PCAP/PCAPNG Reader
# ─────────────────────────────────────────────────────────────────────────────

class PcapReader:
    PCAP_MAGIC_LE = 0xa1b2c3d4
    PCAP_MAGIC_BE = 0xd4c3b2a1
    PCAPNG_MAGIC  = 0x0a0d0d0a

    def __init__(self, filepath: str):
        self.filepath = filepath
        # IP-Fragment-Puffer: {(src_ip, dst_ip, proto, ip_id): {'frags': {offset: bytes}, 'last_off': int}}
        self._frag_buffer: dict = {}

    def packets(self):
        """Yields (timestamp, udp_payload, src_ip, dst_ip, dst_port)."""
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
            if ip_hdr[9] != 17: return None  # UDP
            src_ip    = '.'.join(str(b) for b in ip_hdr[12:16])
            dst_ip    = '.'.join(str(b) for b in ip_hdr[16:20])
            ip_id     = struct.unpack('>H', ip_hdr[4:6])[0]
            flags_frag = struct.unpack('>H', ip_hdr[6:8])[0]
            mf        = bool((flags_frag >> 13) & 1)
            frag_off  = (flags_frag & 0x1FFF) * 8
            ip_payload = raw[ip_start + ihl:]

            if not mf and frag_off == 0:
                # Nicht fragmentiert
                if len(ip_payload) < 8: return None
                dst_port = struct.unpack('>H', ip_payload[2:4])[0]
                udp_len  = struct.unpack('>H', ip_payload[4:6])[0]
                return ip_payload[8:udp_len], src_ip, dst_ip, dst_port

            # IP-Fragmentierung: Fragmente sammeln und reassemblieren
            key = (src_ip, dst_ip, 17, ip_id)
            if key not in self._frag_buffer:
                self._frag_buffer[key] = {'frags': {}, 'last_off': -1, 'src_ip': src_ip}
            entry = self._frag_buffer[key]
            entry['frags'][frag_off] = ip_payload
            if not mf:
                entry['last_off'] = frag_off
            if entry['last_off'] < 0:
                return None
            offsets = sorted(entry['frags'].keys())
            total = bytearray()
            for off in offsets:
                if off != len(total): return None  # Lücke
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
        # packets() seeks to 0 before calling us; read the full 24-byte global header
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
            body = f.read(block_len - 12)
            f.read(4)

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
# Per-stream statistics collector
# ─────────────────────────────────────────────────────────────────────────────

class StreamStats:
    """Collects all statistics for a single CAT240 stream."""

    def __init__(self, key: str):
        self.key         = key          # e.g. "239.0.0.1:5000"
        self.src_ips: set = set()       # source IP addresses observed
        self.sac_sic     = Counter()    # (sac, sic) → count
        self.msg_count   = 0
        self.cell_counts = Counter()
        self.crg_counts  = Counter()    # CELL_DUR raw values
        self.srg_counts  = Counter()
        self.comp_counts = Counter()
        self.fspec_counts= Counter()
        self.cell_bits   = Counter()    # 8/16/32
        self.cell_dur_unit = 'unknown'  # 'ns' (I240/040) or 'fs' (I240/041)
        self.azimuth_list= []
        self.az_deltas   = []
        self._prev_az    = None
        self.timestamps  = []
        # Amplitude: sample data
        self.amp_min     = np.inf
        self.amp_max     = -np.inf
        self.amp_sum     = 0.0
        self.amp_n       = 0
        self.amp_zeros   = 0
        self.amp_sample  = []           # max 200k values for histogram
        self._AMP_LIMIT  = 200_000

    def add(self, msg: Cat240Message, ts: float, src_ip: str = ''):
        self.msg_count += 1
        self.timestamps.append(ts)
        if src_ip:
            self.src_ips.add(src_ip)
        self.sac_sic[(msg.sac, msg.sic)] += 1
        self.cell_counts[msg.num_cells] += 1
        self.crg_counts[msg.cell_duration_raw] += 1
        self.srg_counts[msg.start_range_cell] += 1
        self.comp_counts[msg.compression] += 1
        self.fspec_counts[msg.fspec_hex] += 1
        self.cell_bits[msg.cell_bits] += 1
        if self.cell_dur_unit == 'unknown':
            if 5 in msg.item_types:
                self.cell_dur_unit = 'ns'
            elif 6 in msg.item_types:
                self.cell_dur_unit = 'fs'

        self.azimuth_list.append(msg.start_azimuth_deg)
        if self._prev_az is not None:
            d = msg.start_azimuth_deg - self._prev_az
            if d < -180: d += 360
            if d >  180: d -= 360
            self.az_deltas.append(d)
        self._prev_az = msg.start_azimuth_deg

        v = msg.video_data
        if v.size:
            self.amp_min   = min(self.amp_min,   float(v.min()))
            self.amp_max   = max(self.amp_max,   float(v.max()))
            self.amp_sum  += float(v.sum())
            self.amp_n    += v.size
            self.amp_zeros+= int(np.sum(v == 0))
            if len(self.amp_sample) < self._AMP_LIMIT:
                self.amp_sample.extend(v[:32].tolist())


# ─────────────────────────────────────────────────────────────────────────────
# Analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyse(filepath: str, max_packets: int = 0) -> Dict[str, StreamStats]:
    reader  = PcapReader(filepath)
    decoder = Cat240Decoder()

    streams: Dict[str, StreamStats] = {}
    total_udp = 0
    non_cat240 = 0

    if RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task(f"Reading {filepath.split('/')[-1]} …", total=max_packets or None)

            for pkt_idx, (ts, payload, src_ip, dst_ip, dst_port) in enumerate(reader.packets()):
                if max_packets and pkt_idx >= max_packets:
                    break
                progress.advance(task)
                total_udp += 1

                msgs = decoder.decode_multiple(payload)
                if not msgs:
                    if payload and payload[0] != 0xF0:
                        non_cat240 += 1
                    continue

                for msg in msgs:
                    # Stream key: network level (dst IP:port)
                    net_key = f"{dst_ip}:{dst_port}"
                    if net_key not in streams:
                        streams[net_key] = StreamStats(net_key)
                    streams[net_key].add(msg, ts, src_ip)
    else:
        for pkt_idx, (ts, payload, src_ip, dst_ip, dst_port) in enumerate(reader.packets()):
            if max_packets and pkt_idx >= max_packets:
                break
            if pkt_idx % 5000 == 0 and pkt_idx:
                print(f"  {pkt_idx} packets …", end='\r')
            total_udp += 1
            msgs = decoder.decode_multiple(payload)
            if not msgs:
                if payload and payload[0] != 0xF0:
                    non_cat240 += 1
                continue
            for msg in msgs:
                net_key = f"{dst_ip}:{dst_port}"
                if net_key not in streams:
                    streams[net_key] = StreamStats(net_key)
                streams[net_key].add(msg, ts, src_ip)

    return streams, total_udp, non_cat240


# ─────────────────────────────────────────────────────────────────────────────
# Report output (Rich)
# ─────────────────────────────────────────────────────────────────────────────

CELL_BITS_LABEL = {1: "1 Bit", 2: "2 Bit", 4: "4 Bit", 8: "8 Bit", 16: "16 Bit", 32: "32 Bit", 0: "?"}

# Standard CAT240 UAP (Table 3, EUROCONTROL-SPEC-0149-240 v1.3)
UAP_NAMES = {
    1:  ("I240/010", "Data Source Identifier",          "2B"),
    2:  ("I240/000", "Message Type",                    "1B"),
    3:  ("I240/020", "Video Record Header",             "4B"),
    4:  ("I240/030", "Video Summary",                   "1+n"),
    5:  ("I240/040", "Video Header Nano",               "12B  CELL_DUR [ns]"),
    6:  ("I240/041", "Video Header Femto",              "12B  CELL_DUR [fs]"),
    7:  ("I240/048", "Video Cells Resolution",          "2B"),
    8:  ("I240/049", "Video Octets & Cells Counters",   "5B"),
    9:  ("I240/050", "Video Block Low",                 "1+4n B"),
    10: ("I240/051", "Video Block Medium",              "1+64n B"),
    11: ("I240/052", "Video Block High",                "1+256n B"),
    12: ("I240/140", "Time of Day",                     "3B"),
    13: ("RE",       "Reserved Expansion Field",        "1+"),
    14: ("SP",       "Special Purpose Field",           "1+"),
}


def _active_frns(fspec_hex: str) -> list:
    """Returns list of active FRN numbers for a given FSPEC hex string."""
    frns = []
    for i, b in enumerate(bytes.fromhex(fspec_hex)):
        for bit in range(7, 0, -1):
            if b & (1 << bit):
                frns.append(i * 7 + (8 - bit))
    return frns


def _az_stats(stats: StreamStats):
    """Computes azimuth statistics, returns dict."""
    r = {}
    if not stats.azimuth_list:
        return r
    az = np.array(stats.azimuth_list)
    r['unique'] = len(np.unique(np.round(az, 2)))
    r['az_min'] = az.min()
    r['az_max'] = az.max()

    if stats.az_deltas:
        delt_all = np.array([d for d in stats.az_deltas if abs(d) < 10])
        delt_pos = np.array([d for d in stats.az_deltas if 0 < d < 10])
        if len(delt_all):
            r['step_mean']   = float(np.mean(np.abs(delt_all)))
            r['step_median'] = float(np.median(np.abs(delt_all)))
            r['step_min']    = float(np.abs(delt_all).min())
            r['step_max']    = float(np.abs(delt_all).max())
            total_az = np.abs(delt_all).sum()
            r['revs'] = total_az / 360.0
            if stats.timestamps:
                dur = max(stats.timestamps) - min(stats.timestamps)
                r['rpm_timestamps'] = (r['revs'] / dur * 60) if dur > 0 else 0
        if len(delt_pos) > 10:
            step = np.median(delt_pos)
            r['spokes_per_rev'] = round(360.0 / step) if step > 0 else 0
    return r


def _stream_sort_key(item):
    """Sorts streams by src IP (numeric) then by stream key."""
    key, s = item
    ip = min(s.src_ips) if s.src_ips else '0.0.0.0'
    return (tuple(int(x) for x in ip.split('.')), key)


def _amp_stats(stats: StreamStats):
    r = {}
    if not stats.amp_n:
        return r
    r['min']  = stats.amp_min
    r['max']  = stats.amp_max
    r['mean'] = stats.amp_sum / stats.amp_n
    r['zero_pct'] = 100.0 * stats.amp_zeros / stats.amp_n
    if stats.amp_max > 0:
        nonzero_min = stats.amp_min if stats.amp_min > 0 else 1.0
        r['dynamic_db'] = 20 * np.log10(stats.amp_max / nonzero_min)
    if stats.amp_sample:
        arr = np.array(stats.amp_sample, dtype=np.float32)
        r['median'] = float(np.median(arr))
        r['std']    = float(arr.std())
        r['sample_n'] = len(arr)
        r['hist_arr'] = arr
    return r



def _mini_bar(value: float, max_val: float, width: int = 20) -> str:
    filled = int(width * value / max_val) if max_val > 0 else 0
    return "█" * filled + "░" * (width - filled)


def print_report(filepath: str, streams: Dict[str, StreamStats],
                 total_udp: int, non_cat240: int):

    total_msgs = sum(s.msg_count for s in streams.values())
    all_ts = []
    for s in streams.values():
        all_ts.extend(s.timestamps)
    duration = max(all_ts) - min(all_ts) if all_ts else 0

    # ── Main header ─────────────────────────────────────────────────────────
    console.print()
    console.print(Panel.fit(
        f"[bold white]CAT240 Stream Analysis[/]\n"
        f"[dim]{filepath}[/]\n"
        f"[cyan]{total_udp}[/] UDP packets  ·  "
        f"[cyan]{total_msgs}[/] CAT240 messages  ·  "
        f"[cyan]{len(streams)}[/] stream(s)  ·  "
        f"[cyan]{duration:.1f}[/] s recording",
        title="[bold cyan]● REPORT[/]",
        border_style="cyan",
    ))

    # ── Overview table of all streams ───────────────────────────────────────
    console.print()
    overview = Table(
        title="[bold]Stream overview[/]",
        box=box.ROUNDED, border_style="cyan",
        show_header=True, header_style="bold magenta",
    )
    overview.add_column("#",             style="dim",    justify="right", width=3)
    overview.add_column("Src IP",        style="green",  min_width=15)
    overview.add_column("Dst IP:Port",   style="cyan",   min_width=20)
    overview.add_column("SAC / SIC",     style="yellow", justify="center")
    overview.add_column("Messages",      style="green",  justify="right")
    overview.add_column("Cells/az",      style="white",  justify="center")
    overview.add_column("Bit/cell",      style="white",  justify="center")
    overview.add_column("Az/rev",        style="white",  justify="right")
    overview.add_column("RPM",           style="white",  justify="right")
    overview.add_column("FSPEC",         style="dim",    justify="center")

    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        sac_sic_str = ", ".join(
            f"{sac}/{sic}" for (sac, sic), _ in s.sac_sic.most_common(3)
        )
        cells_str = " / ".join(str(c) for c, _ in s.cell_counts.most_common(3))
        bits_str  = " / ".join(
            CELL_BITS_LABEL.get(b, "?") for b, _ in s.cell_bits.most_common(2)
        )
        az = _az_stats(s)
        spokes = str(az.get('spokes_per_rev', '?'))
        rpm = f"{az['rpm_timestamps']:.1f}" if 'rpm_timestamps' in az else '?'
        fspec  = ", ".join(f"0x{f}" for f, _ in s.fspec_counts.most_common(2))
        src_ips_str = ", ".join(sorted(s.src_ips)) if s.src_ips else "?"
        overview.add_row(
            str(idx), src_ips_str, key, sac_sic_str,
            f"{s.msg_count:,}", cells_str,
            bits_str, spokes, rpm, fspec,
        )

    console.print(overview)

    # ── Per-stream detail block ──────────────────────────────────────────────
    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        dur_s = max(s.timestamps) - min(s.timestamps) if s.timestamps else 0
        az    = _az_stats(s)
        amp   = _amp_stats(s)

        console.print()
        console.print(Panel(
            f"[dim]{s.msg_count:,} messages  ·  {dur_s:.1f} s  ·  "
            f"{s.msg_count/dur_s:.0f} msg/s[/]" if dur_s > 0 else "",
            title=f"[bold cyan]Stream {idx}: {key}[/]",
            border_style="blue",
        ))

        # Two columns: geometry | signal strength
        left  = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0,1))
        right = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0,1))
        for t in (left, right):
            t.add_column("Parameter", style="bold")
            t.add_column("Value",     style="cyan")

        # Geometry
        left.add_row("[bold magenta]── Geometry ──", "")
        for cells, cnt in sorted(s.cell_counts.items()):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            left.add_row("Cells/azimuth",
                         f"{cells}  [dim]({cnt:,}×, {pct:.1f}%)[/]")
        for bits, cnt in s.cell_bits.most_common():
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            left.add_row("Bit depth",
                         f"{CELL_BITS_LABEL.get(bits,'?')}  [dim]({pct:.1f}%)[/]")
        for sc, cnt in sorted(s.srg_counts.items()):
            left.add_row("Start cell (SRG)", str(sc))
        comp_str = " / ".join(
            ("uncompressed" if c == 0 else "compressed") + f" ({n:,}×)"
            for c, n in s.comp_counts.most_common()
        )
        left.add_row("Compression", comp_str)

        # Azimuth – per revolution
        left.add_row("", "")
        left.add_row("[bold magenta]── Azimuth (per revolution) ──", "")
        if az:
            if 'spokes_per_rev' in az:
                left.add_row("Azimuths/revolution", f"~{az['spokes_per_rev']}")
            if 'step_median' in az:
                left.add_row("Step size (median)",
                             f"{az['step_median']:.4f}°")
                left.add_row("Step size (min/max)",
                             f"{az['step_min']:.4f}° / {az['step_max']:.4f}°")

        # Azimuth – total recording
        left.add_row("", "")
        left.add_row("[bold magenta]── Azimuth (total recording) ──", "")
        if az:
            left.add_row("Unique azimuths", str(az.get('unique', '?')))
            left.add_row("Az. min / max",
                         f"{az.get('az_min',0):.3f}° / {az.get('az_max',0):.3f}°")
            if 'revs' in az:
                left.add_row("Total revolutions", f"{az['revs']:.1f}")
            if 'rpm_timestamps' in az:
                left.add_row("RPM", f"{az['rpm_timestamps']:.1f}  [dim](from timestamps)[/]")

        # CELL_DUR raw values
        left.add_row("", "")
        unit_lbl = {'ns': 'I240/040 ns', 'fs': 'I240/041 fs'}.get(s.cell_dur_unit, '?')
        left.add_row("[bold magenta]── CELL_DUR (cell duration) ──", "")
        for crg, cnt in sorted(s.crg_counts.items()):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            scale = 1e-15 if s.cell_dur_unit == 'fs' else 1e-9
            range_m = 3e8 * (crg * scale) / 2.0
            total_cells = s.cell_counts.most_common(1)[0][0] if s.cell_counts else 0
            if crg > 0 and 0 < range_m < 1_000_000:
                range_nm = range_m / 1852.0
                note = f"{range_m:.2f} m/cell → ~{total_cells * range_nm:.0f} nm range  [{unit_lbl}]"
            else:
                note = f"[{unit_lbl}]"
            left.add_row(f"CELL_DUR = {crg}",
                         f"[dim]{cnt:,}× ({pct:.1f}%)  {note}[/]")

        # SAC/SIC
        left.add_row("", "")
        left.add_row("[bold magenta]── Data source ──", "")
        left.add_row("Src IP", ", ".join(sorted(s.src_ips)) if s.src_ips else "?")
        for (sac, sic), cnt in s.sac_sic.most_common():
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            left.add_row(f"SAC={sac} / SIC={sic}",
                         f"[dim]{cnt:,}× ({pct:.1f}%)[/]")
        left.add_row("", "")
        left.add_row("[bold magenta]── Message structure (FSPEC) ──", "")
        for fh, cnt in s.fspec_counts.most_common(3):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            fspec_bytes = " ".join(f"0x{b:02X}" for b in bytes.fromhex(fh))
            left.add_row(f"FSPEC {fspec_bytes}", f"[dim]{cnt:,}× ({pct:.1f}%)[/]")
            frns = _active_frns(fh)
            for frn in frns:
                if frn in UAP_NAMES:
                    item_id, name, size = UAP_NAMES[frn]
                    left.add_row(f"  FRN {frn:2d}  {item_id}",
                                 f"[dim]{name}  [{size}][/]")
                else:
                    left.add_row(f"  FRN {frn:2d}", "[dim]unknown[/]")

        # Amplitude
        right.add_row("[bold magenta]── Amplitude ──", "")
        if amp:
            right.add_row("Min", f"{amp['min']:.0f}")
            right.add_row("Max", f"{amp['max']:.0f}")
            right.add_row("Mean",    f"{amp['mean']:.1f}")
            right.add_row("Median", f"{amp.get('median', '?'):.0f}" if 'median' in amp else "?")
            right.add_row("Std. dev.", f"{amp.get('std', 0):.1f}")
            right.add_row("Zero fraction", f"{amp['zero_pct']:.1f}%")
            if 'dynamic_db' in amp:
                right.add_row("Dynamic range", f"{amp['dynamic_db']:.1f} dB")

            # Histogram
            if 'hist_arr' in amp:
                arr = amp['hist_arr']
                arr_norm = arr / arr.max() if arr.max() > 0 else arr
                bins = np.linspace(0, 1, 9)
                hist, edges = np.histogram(arr_norm, bins=bins)
                bar_max = hist.max()
                right.add_row("", "")
                right.add_row("[bold magenta]── Amplitude distribution ──", "")
                for i in range(len(hist)):
                    bar = _mini_bar(hist[i], bar_max, 18)
                    right.add_row(
                        f"{edges[i]:.2f}–{edges[i+1]:.2f}",
                        f"[green]{bar}[/] [dim]{hist[i]:,}[/]"
                    )

        console.print(Columns([left, right], equal=False, expand=True))

    # ── Footer ───────────────────────────────────────────────────────────────
    console.print()
    if non_cat240:
        console.print(f"[dim]Non-CAT240 UDP packets: {non_cat240}[/]")
    console.print(f"[dim]Analysis complete.[/]\n")


def print_report_plain(filepath, streams, total_udp, non_cat240):
    """Fallback without rich."""
    sep = "─" * 60
    total_msgs = sum(s.msg_count for s in streams.values())
    print(f"\n{sep}\nCAT240 ANALYSIS: {filepath}\n{sep}")
    print(f"UDP packets: {total_udp}  |  CAT240: {total_msgs}  |  Streams: {len(streams)}"
          + (f"  |  Non-CAT240: {non_cat240}" if non_cat240 else "") + "\n")
    for key, s in sorted(streams.items(), key=_stream_sort_key):
        az = _az_stats(s)
        amp = _amp_stats(s)
        src_ips_str = ", ".join(sorted(s.src_ips)) if s.src_ips else "?"
        print(f"\n[{key}]  src: {src_ips_str}  {s.msg_count:,} messages")
        print(f"  SAC/SIC       : {dict(s.sac_sic.most_common(3))}")
        print(f"  Cells/azimuth : {dict(s.cell_counts.most_common())}")
        print(f"  Bit/cell      : {dict(s.cell_bits.most_common())}")
        comp_str = " / ".join(
            ("uncompressed" if c == 0 else "LOG COMPRESSED") + f" ({n:,}x)"
            for c, n in s.comp_counts.most_common()
        )
        print(f"  Compression   : {comp_str}")
        print(f"  CELL_DUR raw  : {dict(s.crg_counts.most_common())}")
        if 'spokes_per_rev' in az:
            print(f"  Az/rev        : ~{az['spokes_per_rev']}")
        if 'rpm_timestamps' in az:
            print(f"  RPM           : {az['rpm_timestamps']:.1f}  (from timestamps)")
        if amp:
            print(f"  Amp min/max   : {amp['min']:.0f} / {amp['max']:.0f}")
            print(f"  Zero fraction : {amp['zero_pct']:.1f}%")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Markdown export
# ─────────────────────────────────────────────────────────────────────────────

def write_markdown(filepath: str, streams: Dict[str, StreamStats],
                   total_udp: int, non_cat240: int,
                   md_path: str) -> None:
    """Writes the analysis report as a Markdown file."""
    from datetime import datetime

    total_msgs = sum(s.msg_count for s in streams.values())
    all_ts = []
    for s in streams.values():
        all_ts.extend(s.timestamps)
    duration = max(all_ts) - min(all_ts) if all_ts else 0

    lines = []
    def w(*args): lines.append(" ".join(str(a) for a in args))

    w(f"# CAT240 Stream Analysis")
    w()
    w(f"**File:** `{filepath}`  ")
    w(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    w(f"**Recording duration:** {duration:.1f} s  ")
    w(f"**UDP packets:** {total_udp:,}  |  "
      f"**CAT240 messages:** {total_msgs:,}  |  "
      f"**Streams:** {len(streams)}")
    if non_cat240:
        w(f"**Non-CAT240 UDP:** {non_cat240}")
    w()
    w("---")
    w()

    # ── Overview table ───────────────────────────────────────────────────────
    w("## Stream overview")
    w()
    w("| # | Src IP | Dst IP:Port | SAC/SIC | Messages | Cells/az | Bit/cell | Az/rev | RPM | FSPEC |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        az  = _az_stats(s)
        sac_sic = ", ".join(f"{a}/{b}" for (a,b),_ in s.sac_sic.most_common(2))
        cells   = " / ".join(str(c) for c,_ in s.cell_counts.most_common(3))
        bits    = " / ".join(CELL_BITS_LABEL.get(b,"?") for b,_ in s.cell_bits.most_common(2))
        spokes  = str(az.get('spokes_per_rev', '?'))
        rpm = f"{az['rpm_timestamps']:.1f}" if 'rpm_timestamps' in az else '?'
        fspec = ", ".join(f"`0x{f}`" for f,_ in s.fspec_counts.most_common(2))
        src_ips_str = ", ".join(sorted(s.src_ips)) if s.src_ips else "?"
        w(f"| {idx} | {src_ips_str} | `{key}` | {sac_sic} | {s.msg_count:,} | {cells} | {bits} | {spokes} | {rpm} | {fspec} |")
    w()

    # ── Per-stream detail ────────────────────────────────────────────────────
    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        dur_s = max(s.timestamps) - min(s.timestamps) if s.timestamps else 0
        az    = _az_stats(s)
        amp   = _amp_stats(s)

        if idx > 1:
            w('<div style="page-break-before: always"></div>')
            w()
        w(f"## Stream {idx}: `{key}`")
        w()
        w(f"{s.msg_count:,} messages · {dur_s:.1f} s · "
          + (f"{s.msg_count/dur_s:.0f} msg/s" if dur_s > 0 else ""))
        w()

        # Geometry
        w("### Geometry")
        w()
        w("| Parameter | Value |")
        w("|---|---|")
        for cells, cnt in sorted(s.cell_counts.items()):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            w(f"| Cells/azimuth | {cells} ({cnt:,}×, {pct:.1f}%) |")
        for bits, cnt in s.cell_bits.most_common():
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            w(f"| Bit depth | {CELL_BITS_LABEL.get(bits,'?')} ({pct:.1f}%) |")
        for sc in sorted(s.srg_counts):
            w(f"| Start cell (SRG) | {sc} |")
        comp = " / ".join(
            ("uncompressed" if c == 0 else "compressed") + f" ({n:,}×)"
            for c, n in s.comp_counts.most_common()
        )
        w(f"| Compression | {comp} |")
        w()

        # Azimuth
        w("### Azimuth — per revolution")
        w()
        w("| Parameter | Value |")
        w("|---|---|")
        if az:
            if 'spokes_per_rev' in az:
                w(f"| Azimuths/revolution | ~{az['spokes_per_rev']} |")
            if 'step_median' in az:
                w(f"| Step size (median) | {az['step_median']:.4f}° |")
                w(f"| Step size (min/max) | {az['step_min']:.4f}° / {az['step_max']:.4f}° |")
        w()
        w("### Azimuth — total recording")
        w()
        w("| Parameter | Value |")
        w("|---|---|")
        if az:
            w(f"| Unique azimuths | {az.get('unique','?')} |")
            w(f"| Az. min / max | {az.get('az_min',0):.3f}° / {az.get('az_max',0):.3f}° |")
            if 'revs' in az:
                w(f"| Total revolutions | {az['revs']:.1f} |")
            if 'rpm_timestamps' in az:
                w(f"| RPM | {az['rpm_timestamps']:.1f} *(from timestamps)* |")
        w()

        # CELL_DUR
        unit_lbl = {'ns': 'I240/040 nanoseconds', 'fs': 'I240/041 femtoseconds'}.get(s.cell_dur_unit, '?')
        w(f"### CELL_DUR (cell duration, {unit_lbl})")
        w()
        w("| CELL_DUR value | Messages | Note |")
        w("|---|---|---|")
        for crg, cnt in sorted(s.crg_counts.items()):
            scale = 1e-15 if s.cell_dur_unit == 'fs' else 1e-9
            range_m = 3e8 * (crg * scale) / 2.0
            total_cells = s.cell_counts.most_common(1)[0][0] if s.cell_counts else 0
            if crg > 0 and 0 < range_m < 1_000_000:
                note = f"{range_m:.2f} m/cell → ~{total_cells * range_m / 1852:.0f} nm range"
            else:
                note = f"[{unit_lbl}]"
            w(f"| {crg} | {cnt:,} | {note} |")
        w()

        # Data source
        w("### Data source")
        w()
        w("| Parameter | Value |")
        w("|---|---|")
        src_ips_str = ", ".join(sorted(s.src_ips)) if s.src_ips else "?"
        w(f"| Src IP | {src_ips_str} |")
        for (sac, sic), cnt in s.sac_sic.most_common():
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            w(f"| SAC / SIC | {sac} / {sic} ({cnt:,}×, {pct:.1f}%) |")
        for fh, cnt in s.fspec_counts.most_common(3):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            fspec_bytes = " ".join(f"0x{b:02X}" for b in bytes.fromhex(fh))
            w(f"| FSPEC | `{fspec_bytes}` ({cnt:,}×, {pct:.1f}%) |")
        w()
        # Message structure
        w("### Message structure (FSPEC)")
        w()
        for fh, cnt in s.fspec_counts.most_common(1):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            fspec_bytes = " ".join(f"0x{b:02X}" for b in bytes.fromhex(fh))
            w(f"Most common FSPEC: `{fspec_bytes}` ({pct:.1f}% of messages)")
            w()
            w("| FRN | Data Item | Description | Size |")
            w("|---|---|---|---|")
            for frn in _active_frns(fh):
                if frn in UAP_NAMES:
                    item_id, name, size = UAP_NAMES[frn]
                    w(f"| {frn} | {item_id} | {name} | {size} |")
                else:
                    w(f"| {frn} | — | unknown | — |")
        w()

        # Amplitude
        w("### Amplitude")
        w()
        w("| Parameter | Value |")
        w("|---|---|")
        if amp:
            w(f"| Min | {amp['min']:.0f} |")
            w(f"| Max | {amp['max']:.0f} |")
            w(f"| Mean | {amp['mean']:.1f} |")
            if 'median' in amp:
                w(f"| Median | {amp['median']:.0f} |")
            if 'std' in amp:
                w(f"| Std. dev. | {amp['std']:.1f} |")
            w(f"| Zero fraction | {amp['zero_pct']:.1f}% |")
            if 'dynamic_db' in amp:
                w(f"| Dynamic range | {amp['dynamic_db']:.1f} dB |")
        w()

        # Histogram
        if amp and 'hist_arr' in amp:
            arr = amp['hist_arr']
            arr_norm = arr / arr.max() if arr.max() > 0 else arr
            bins = np.linspace(0, 1, 9)
            hist, edges = np.histogram(arr_norm, bins=bins)
            w("#### Amplitude distribution")
            w()
            w("| Range | Count | Bar |")
            w("|---|---|---|")
            bar_max = hist.max()
            for i in range(len(hist)):
                bar = "█" * int(20 * hist[i] / bar_max) if bar_max else ""
                w(f"| {edges[i]:.2f}–{edges[i+1]:.2f} | {hist[i]:,} | {bar} |")
            w()

    w("---")
    w()
    w(f"*Generated by cat240_stream_info.py*")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")



# ─────────────────────────────────────────────────────────────────────────────
# PDF export
# ─────────────────────────────────────────────────────────────────────────────

def write_pdf(filepath: str, streams: Dict[str, StreamStats],
              total_udp: int, non_cat240: int, pdf_path: str) -> None:
    """Erzeugt einen formatierten PDF-Report mit fpdf2."""
    try:
        from fpdf import FPDF, XPos, YPos
    except ImportError:
        print("PDF-Export nicht verfügbar (pip install fpdf2)", file=sys.stderr)
        return

    from datetime import datetime

    # ── Farben ────────────────────────────────────────────────────────────────
    C_HEADER     = (0,   51, 102)   # dunkelblau – Seitenkopf & Tabellenheader
    C_SECTION    = (0,   68, 136)   # mittelblau – Abschnittsüberschriften
    C_ROW_EVEN   = (240, 244, 248)  # sehr helles blau – gerade Tabellenzeilen
    C_ROW_ODD    = (255, 255, 255)  # weiß
    C_TEXT       = (26,  26,  26)   # fast schwarz
    C_DIM        = (100, 100, 100)  # grau – Metainfo
    C_MONO_BG    = (244, 244, 244)  # hellgrau – Code-Hintergrund

    class PDF(FPDF):
        def header(self):
            self.set_fill_color(*C_HEADER)
            self.rect(0, 0, 210, 10, 'F')
            self.set_font('Helvetica', 'B', 8)
            self.set_text_color(255, 255, 255)
            self.set_xy(10, 2)
            self.cell(0, 6, 'CAT240 Stream Analysis', align='L')
            self.set_xy(0, 2)
            self.cell(200, 6, f'Page {self.page_no()}', align='R')
            self.set_text_color(*C_TEXT)
            self.ln(12)

        def footer(self):
            self.set_y(-10)
            self.set_font('Helvetica', '', 7)
            self.set_text_color(*C_DIM)
            self.cell(0, 5, f'Generated by cat240_stream_info.py  ·  {filepath}',
                      align='C')

    pdf = PDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_margins(14, 14, 14)
    pdf.add_page()

    W = 182  # nutzbare Seitenbreite

    def _s(text):
        """Ersetzt nicht-Latin1-Zeichen für fpdf2-Standardfonts."""
        return (str(text)
                .replace('\u2014', '-').replace('\u2013', '-')
                .replace('\u2192', '->').replace('\u00b0', ' deg')
                .replace('\u2019', "'").replace('\u00d7', 'x')
                .encode('latin-1', errors='replace').decode('latin-1'))

    def h1(text):
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_text_color(*C_HEADER)
        pdf.cell(W, 8, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(*C_HEADER)
        pdf.set_line_width(0.5)
        pdf.line(14, pdf.get_y(), 196, pdf.get_y())
        pdf.ln(2)
        pdf.set_text_color(*C_TEXT)

    def _ensure_space(min_mm: float):
        """Neue Seite wenn verbleibender Platz < min_mm."""
        if pdf.get_y() + min_mm > pdf.h - pdf.b_margin:
            pdf.add_page()

    def h2(text):
        _ensure_space(35)   # Überschrift + mind. ein paar Tabellenzeilen
        pdf.ln(3)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(W, 7, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(200, 210, 220)
        pdf.set_line_width(0.3)
        pdf.line(14, pdf.get_y(), 196, pdf.get_y())
        pdf.ln(1)
        pdf.set_text_color(*C_TEXT)

    def h3(text):
        _ensure_space(30)   # Überschrift + mind. ein paar Tabellenzeilen
        pdf.ln(2)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(*C_SECTION)
        pdf.cell(W, 5, _s(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C_TEXT)

    def kv_table(rows, col_w=(80, 102)):
        """Schlüssel-Wert-Tabelle. rows = [(key, value), ...]"""
        _ensure_space((1 + len(rows)) * 5 + 4)
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
        """Mehrspaltige Tabelle."""
        _ensure_space((1 + len(rows)) * 5 + 4)
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

    def mono(text):
        """Inline-Monospace-Text (z.B. für FSPEC)."""
        pdf.set_font('Courier', '', 8)
        pdf.set_fill_color(*C_MONO_BG)
        pdf.cell(0, 5, text, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Helvetica', '', 8)

    # ── Titelseite / Kopf ─────────────────────────────────────────────────────
    total_msgs = sum(s.msg_count for s in streams.values())
    all_ts: List[float] = []
    for s in streams.values():
        all_ts.extend(s.timestamps)
    duration = max(all_ts) - min(all_ts) if all_ts else 0

    h1('CAT240 Stream Analysis')
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

    # ── Stream-Übersicht ──────────────────────────────────────────────────────
    h2('Stream Overview')
    hdrs = ['#', 'Src IP', 'Dst IP:Port', 'SAC/SIC', 'Messages',
            'Cells/az', 'Bit/cell', 'Az/rev', 'RPM', 'FSPEC']
    cws  = [7, 32, 38, 18, 20, 16, 14, 14, 12, 25]
    rows_ov = []
    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        az  = _az_stats(s)
        sac_sic = ', '.join(f'{a}/{b}' for (a, b), _ in s.sac_sic.most_common(2))
        cells   = '/'.join(str(c) for c, _ in s.cell_counts.most_common(2))
        bits    = '/'.join(CELL_BITS_LABEL.get(b, '?') for b, _ in s.cell_bits.most_common(2))
        spokes  = f"~{az['spokes_per_rev']}" if 'spokes_per_rev' in az else '?'
        rpm     = f"{az['rpm_timestamps']:.1f}" if 'rpm_timestamps' in az else '?'
        fspec   = ', '.join(f"0x{f}" for f, _ in s.fspec_counts.most_common(2))
        src_ips_str = ', '.join(sorted(s.src_ips)) if s.src_ips else '?'
        rows_ov.append([str(idx), src_ips_str, key, sac_sic, f'{s.msg_count:,}',
                        cells, bits, spokes, rpm, fspec])
    wide_table(hdrs, rows_ov, cws)

    # ── Pro-Stream-Details ────────────────────────────────────────────────────
    for idx, (key, s) in enumerate(sorted(streams.items(), key=_stream_sort_key), 1):
        dur_s = max(s.timestamps) - min(s.timestamps) if s.timestamps else 0
        az    = _az_stats(s)
        amp   = _amp_stats(s)

        if idx > 1:
            pdf.add_page()
        h2(f'Stream {idx}: {key}')
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(*C_DIM)
        rate = f'  -  {s.msg_count / dur_s:.0f} msg/s' if dur_s > 0 else ''
        pdf.cell(W, 5, _s(f'{s.msg_count:,} messages  -  {dur_s:.1f} s{rate}'),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(*C_TEXT)
        pdf.ln(1)

        # Geometry
        h3('Geometry')
        geo_rows = []
        for cells, cnt in sorted(s.cell_counts.items()):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            geo_rows.append(('Cells/azimuth', f'{cells}  ({cnt:,}×, {pct:.1f}%)'))
        for bits, cnt in s.cell_bits.most_common():
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            geo_rows.append(('Bit depth', f"{CELL_BITS_LABEL.get(bits,'?')}  ({pct:.1f}%)"))
        for sc in sorted(s.srg_counts):
            geo_rows.append(('Start cell (SRG)', str(sc)))
        comp = ' / '.join(
            ('uncompressed' if c == 0 else 'compressed') + f' ({n:,}×)'
            for c, n in s.comp_counts.most_common())
        geo_rows.append(('Compression', comp))
        kv_table(geo_rows)

        # Azimuth – pro Umdrehung
        if az:
            h3('Azimuth - per revolution')
            az_rev_rows = []
            if 'spokes_per_rev' in az:
                az_rev_rows.append(('Azimuths/revolution', f"~{az['spokes_per_rev']}"))
            if 'step_median' in az:
                az_rev_rows.append(('Step size (median)', f"{az['step_median']:.4f}°"))
                az_rev_rows.append(('Step size (min/max)',
                                    f"{az['step_min']:.4f}° / {az['step_max']:.4f}°"))
            if az_rev_rows:
                kv_table(az_rev_rows)

            h3('Azimuth - total recording')
            az_tot_rows = [('Unique azimuths', str(az.get('unique', '?'))),
                           ('Az. min / max',
                            f"{az.get('az_min',0):.3f}° / {az.get('az_max',0):.3f}°")]
            if 'revs' in az:
                az_tot_rows.append(('Total revolutions', f"{az['revs']:.1f}"))
            if 'rpm_timestamps' in az:
                az_tot_rows.append(('RPM', f"{az['rpm_timestamps']:.1f}  (from timestamps)"))
            kv_table(az_tot_rows)

        # CELL_DUR
        unit_lbl = {'ns': 'I240/040 nanoseconds',
                    'fs': 'I240/041 femtoseconds'}.get(s.cell_dur_unit, '?')
        h3(f'CELL_DUR ({unit_lbl})')
        scale = 1e-15 if s.cell_dur_unit == 'fs' else 1e-9
        total_cells = s.cell_counts.most_common(1)[0][0] if s.cell_counts else 0
        cd_rows = []
        for crg, cnt in sorted(s.crg_counts.items()):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            range_m = 3e8 * (crg * scale) / 2.0
            if crg > 0 and 0 < range_m < 1_000_000:
                note = f"{range_m:.2f} m/cell  →  ~{total_cells * range_m / 1852:.0f} nm range"
            else:
                note = ''
            cd_rows.append((str(crg), f'{cnt:,}  ({pct:.1f}%)', note))
        wide_table(['CELL_DUR value', 'Messages', 'Note'], cd_rows, [35, 40, 107])

        # Data source / FSPEC
        h3('Data Source & FSPEC')
        ds_rows = []
        src_ips_str = ', '.join(sorted(s.src_ips)) if s.src_ips else '?'
        ds_rows.append(('Src IP', src_ips_str))
        for (sac, sic), cnt in s.sac_sic.most_common():
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            ds_rows.append((f'SAC / SIC', f'{sac} / {sic}  ({cnt:,}×, {pct:.1f}%)'))
        for fh, cnt in s.fspec_counts.most_common(3):
            pct = 100 * cnt / s.msg_count if s.msg_count else 0
            fb = ' '.join(f'0x{b:02X}' for b in bytes.fromhex(fh))
            ds_rows.append(('FSPEC', f'{fb}  ({cnt:,}×, {pct:.1f}%)'))
        kv_table(ds_rows)

        # FSPEC-Felder
        for fh, _ in s.fspec_counts.most_common(1):
            frn_rows = []
            for frn in _active_frns(fh):
                if frn in UAP_NAMES:
                    item_id, name, size = UAP_NAMES[frn]
                    frn_rows.append((str(frn), item_id, name, size))
                else:
                    frn_rows.append((str(frn), '—', 'unknown', '—'))
            wide_table(['FRN', 'Data Item', 'Description', 'Size'],
                       frn_rows, [12, 24, 110, 36])

        # Amplitude
        h3('Amplitude')
        if amp:
            amp_rows = [('Min', f"{amp['min']:.0f}"),
                        ('Max', f"{amp['max']:.0f}"),
                        ('Mean', f"{amp['mean']:.1f}"),
                        ('Median', f"{amp.get('median', '?'):.0f}" if 'median' in amp else '?'),
                        ('Std. dev.', f"{amp.get('std', 0):.1f}"),
                        ('Zero fraction', f"{amp['zero_pct']:.1f}%")]
            if 'dynamic_db' in amp:
                amp_rows.append(('Dynamic range', f"{amp['dynamic_db']:.1f} dB"))
            kv_table(amp_rows)

        # Histogramm
        if amp and 'hist_arr' in amp:
            arr = amp['hist_arr']
            arr_norm = arr / arr.max() if arr.max() > 0 else arr
            hist, edges = np.histogram(arr_norm, bins=np.linspace(0, 1, 9))
            bar_max = hist.max() or 1
            h3('Amplitude Distribution')
            ROW_H   = 5.0    # Zeilenhöhe mm
            COL_RNG = 28     # Breite Spalte "Range"
            COL_CNT = 24     # Breite Spalte "Count"
            BAR_MAX = 110    # max. Balkenbreite mm
            _ensure_space((1 + len(hist)) * ROW_H + 4)
            # Tabellenkopf
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_fill_color(*C_HEADER)
            pdf.set_text_color(255, 255, 255)
            for lbl, cw in (('Range', COL_RNG), ('Count', COL_CNT), ('Bar', BAR_MAX)):
                pdf.cell(cw, ROW_H, lbl, border=0, fill=True)
            pdf.ln()
            pdf.set_font('Helvetica', '', 8)
            pdf.set_text_color(*C_TEXT)
            for i in range(len(hist)):
                pdf.set_fill_color(*(C_ROW_EVEN if i % 2 == 0 else C_ROW_ODD))
                row_y = pdf.get_y()
                pdf.cell(COL_RNG, ROW_H,
                         f'{edges[i]:.2f}-{edges[i+1]:.2f}',
                         border=0, fill=True)
                pdf.cell(COL_CNT, ROW_H,
                         f'{hist[i]:,}',
                         border=0, fill=True)
                # Hintergrund der Bar-Zelle
                bar_x = pdf.get_x()
                pdf.cell(BAR_MAX, ROW_H, '', border=0, fill=True)
                pdf.ln()
                # Balken als gefülltes Rechteck
                bar_w = BAR_MAX * hist[i] / bar_max
                if bar_w > 0:
                    pdf.set_fill_color(0, 100, 180)
                    margin = 0.8
                    pdf.rect(bar_x, row_y + margin,
                             bar_w, ROW_H - 2 * margin, 'F')
                    pdf.set_fill_color(*(C_ROW_EVEN if i % 2 == 0 else C_ROW_ODD))
            pdf.ln(2)

    pdf.output(pdf_path)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyses CAT240 streams in PCAP/PCAPNG files.",
    )
    parser.add_argument("file", nargs="+", help="Path(s) to PCAP or PCAPNG file(s); glob patterns are expanded by the shell")
    parser.add_argument(
        "--packets", "-n", type=int, default=0, metavar="N",
        help="Analyse only the first N UDP packets (0 = all)"
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE.md",
        help="Path for Markdown output (only used when a single file is given; default: <input>_analysis.md)"
    )
    parser.add_argument(
        "--pdf", metavar="FILE.pdf", nargs="?", const="",
        help="Also generate a PDF report (default path: <input>_analysis.pdf)"
    )
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
        base = os.path.splitext(os.path.basename(filepath))[0]
        if len(args.file) == 1:
            md_path  = args.output if args.output else f"{base}_analysis.md"
            pdf_path = (args.pdf if args.pdf else f"{base}_analysis.pdf") if args.pdf is not None else None
        else:
            md_path  = f"{base}_analysis.md"
            pdf_path = f"{base}_analysis.pdf" if args.pdf is not None else None

        if RICH and len(args.file) > 1:
            console.rule(f"[bold]{filepath}")
        elif len(args.file) > 1:
            print(f"\n=== {filepath} ===")

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
