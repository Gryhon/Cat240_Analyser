"""
CAT240 ASTERIX Radar Video Analyzer
=====================================
Parses PCAP/PCAPNG files, decodes ASTERIX CAT240 packets
and visualizes the radar video as PPI + A-Scope.

Dependencies:
    pip install matplotlib numpy

Usage:
    # Analyze a PCAP file, show PPI + A-Scope:
    python cat240_analyzer.py --file aufzeichnung.pcap

    # With fixed start azimuth for A-Scope (e.g. 90°):
    python cat240_analyzer.py --file aufzeichnung.pcap --azimuth 90

    # Play back a PCAP file as animated radar (1× real-time):
    python cat240_analyzer.py --replay aufzeichnung.pcapng

    # Play back 20× faster:
    python cat240_analyzer.py --replay aufzeichnung.pcapng --speed 20

    # Loop replay continuously (PPI cleared on each restart):
    python cat240_analyzer.py --replay aufzeichnung.pcapng --loop --speed 10

    # Live stream from UDP port:
    python cat240_analyzer.py --live --port 5000

    # Analyze only, no window:
    python cat240_analyzer.py --file aufzeichnung.pcap --no-display

    # Save PPI as PNG:
    python cat240_analyzer.py --file aufzeichnung.pcap --save ppi_output.png

A-Scope controls:
    - Click in PPI   → A-Scope shows that azimuth
    - Mouse in A-Scope → vertical measurement line with cell no. & amplitude
    - --azimuth N    → A-Scope starts at fixed angle N°
"""

import argparse
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Cat240Message:
    """Represents a decoded CAT240 message."""
    start_azimuth_deg: float        # Start azimuth in degrees
    end_azimuth_deg: float          # End azimuth in degrees
    start_range_cell: int           # First range cell
    cell_duration_ns: float         # Cell duration in nanoseconds
    video_data: np.ndarray          # Amplitude values
    compression: int = 0            # 0=uncompressed, 1=compressed
    num_cells: int = 0
    raw_bytes: bytes = field(default_factory=bytes, repr=False)


# ─────────────────────────────────────────────────────────────────────────────
# CAT240 ASTERIX Decoder
# ─────────────────────────────────────────────────────────────────────────────

class Cat240Decoder:
    """
    Decodes ASTERIX CAT240 binary data according to the Eurocontrol specification.
    Supports: I240/000, I240/001, I240/002, I240/003, I240/004 (Video Cells)
    """

    # UAP positions (FSPEC bit positions) → Data Items
    # 1=I240/000 DSI  2=I240/001 MsgType  3=I240/002 VRH
    # 4=I240/003 VideoSummary  5=I240/004 VHNano  6=I240/005 VHFemto
    # 7=I240/006 VRes  8=I240/007 VComp
    # 9=I240/008 Cells1B  10=I240/009 Cells2B  11=I240/010 Cells4B
    # 12=SPARE  13=I240/SP  14=I240/RE

    def decode(self, data: bytes) -> Optional[Cat240Message]:
        """Decodes a single ASTERIX CAT240 datagram."""
        if len(data) < 3:
            return None

        cat = data[0]
        if cat != 0xF0:  # Category 240 = 0xF0
            return None

        length = struct.unpack(">H", data[1:3])[0]
        if length > len(data):
            return None

        # Read FSPEC (variable length, last byte has bit0 = 0)
        offset = 3
        fspec = []
        while offset < length:
            byte = data[offset]
            fspec.append(byte)
            offset += 1
            if not (byte & 0x01):  # FX bit = 0 → end of FSPEC
                break

        # Determine active Data Items from FSPEC
        active_items = []
        for i, byte in enumerate(fspec):
            for bit in range(7, 0, -1):  # Bits 7..1
                if byte & (1 << bit):
                    item_num = i * 7 + (8 - bit)
                    active_items.append(item_num)

        # Parse Data Items
        result = {
            'start_az': 0.0,
            'end_az':   0.0,
            'start_cell': 0,
            'cell_dur_ns': 0.0,
            'video': np.array([], dtype=np.float32),
            'num_cells': 0,
            'compression': 0,
            'res': 0,
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
            cell_duration_ns  = result['cell_dur_ns'],
            video_data        = result['video'],
            compression       = result['compression'],
            num_cells         = result['num_cells'],
            raw_bytes         = data[:length],
        )

    def _parse_item(self, data: bytes, offset: int, length: int,
                    item: int, result: dict) -> int:
        """Parses a single Data Item according to the CAT240 UAP and returns the new offset."""
        try:
            if item == 1:
                # I240/000 – Data Source Identifier (SAC + SIC), 2 bytes
                return offset + 2

            elif item == 2:
                # I240/000 – Message Type, 1 byte
                return offset + 1

            elif item == 3:
                # I240/020 – Video Record Header (MSG_INDEX 32 bit), 4 bytes
                return offset + 4

            elif item == 4:
                # I240/030 – Video Summary (1B REP + REP×1B ASCII characters)
                if offset >= length:
                    return length
                rep = data[offset]
                return offset + 1 + rep

            elif item == 5:
                # I240/040 – Video Header Nano, 12 bytes
                # START_AZ(2B,LSB=360/2^16) + END_AZ(2B) + START_RG(4B) + CELL_DUR(4B,LSB=10^-9 s)
                if offset + 12 > length:
                    return length
                sa = struct.unpack(">H", data[offset:offset+2])[0]
                ea = struct.unpack(">H", data[offset+2:offset+4])[0]
                result['start_az']    = sa / 65536.0 * 360.0
                result['end_az']      = ea / 65536.0 * 360.0
                result['start_cell']  = struct.unpack(">I", data[offset+4:offset+8])[0]
                result['cell_dur_ns'] = struct.unpack(">I", data[offset+8:offset+12])[0]
                return offset + 12

            elif item == 6:
                # I240/041 – Video Header Femto, 12 bytes
                # START_AZ(2B,LSB=360/2^16) + END_AZ(2B) + START_RG(4B) + CELL_DUR(4B,LSB=10^-15 s)
                # CELL_DUR unit: femtoseconds → convert to nanoseconds
                if offset + 12 > length:
                    return length
                sa = struct.unpack(">H", data[offset:offset+2])[0]
                ea = struct.unpack(">H", data[offset+2:offset+4])[0]
                result['start_az']    = sa / 65536.0 * 360.0
                result['end_az']      = ea / 65536.0 * 360.0
                result['start_cell']  = struct.unpack(">I", data[offset+4:offset+8])[0]
                cell_dur_fs = struct.unpack(">I", data[offset+8:offset+12])[0]
                result['cell_dur_ns'] = cell_dur_fs * 1e-6  # femtoseconds → nanoseconds
                return offset + 12

            elif item == 7:
                # I240/048 – Video Cells Resolution & Compression Indicator, 2 bytes
                # Bit16=C (compression), Bits15-9=Spare, Bits8-1=RES
                if offset + 2 <= length:
                    result['compression'] = (data[offset] >> 7) & 1
                    result['res']         = data[offset + 1]
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
                if offset >= length:
                    return length
                rep = data[offset]
                video_bytes = rep * 4
                if offset + 1 + video_bytes <= length:
                    cells = np.frombuffer(
                        data[offset+1:offset+1+video_bytes], dtype=np.uint8
                    ).astype(np.float32)
                    if result['video'].size == 0:
                        result['video'] = cells
                    result['num_cells'] = result['num_cells'] or len(cells)
                return offset + 1 + video_bytes

            elif item == 10:
                # I240/051 – Video Block Medium Data Volume (1B REP + REP×64B)
                if offset >= length:
                    return length
                rep = data[offset]
                video_bytes = rep * 64
                if offset + 1 + video_bytes <= length:
                    dtype = {4: np.uint8, 5: '>u2', 6: '>u4'}.get(result.get('res', 0), '>u2')
                    cells = np.frombuffer(
                        data[offset+1:offset+1+video_bytes], dtype=dtype
                    ).astype(np.float32)
                    if result['video'].size == 0:
                        result['video'] = cells
                    result['num_cells'] = result['num_cells'] or len(cells)
                return offset + 1 + video_bytes

            elif item == 11:
                # I240/052 – Video Block High Data Volume (1B REP + REP×256B)
                if offset >= length:
                    return length
                rep = data[offset]
                video_bytes = rep * 256
                if offset + 1 + video_bytes <= length:
                    dtype = {4: np.uint8, 5: '>u2', 6: '>u4'}.get(result.get('res', 0), '>u4')
                    cells = np.frombuffer(
                        data[offset+1:offset+1+video_bytes], dtype=dtype
                    ).astype(np.float32)
                    if result['video'].size == 0:
                        result['video'] = cells
                    result['num_cells'] = result['num_cells'] or len(cells)
                return offset + 1 + video_bytes

            elif item == 12:
                # I240/140 – Time of Day, 3 Bytes
                return offset + 3

            elif item in (13, 14):
                # RE / SP – Variable (1B total length incl. length byte)
                if offset >= length:
                    return length
                field_len = data[offset]
                if field_len == 0:
                    return offset + 1
                return offset + field_len

            else:
                # Unknown item – skip 1 byte
                return offset + 1

        except Exception:
            return length

    def decode_multiple(self, data: bytes) -> List[Cat240Message]:
        """Decodes multiple ASTERIX messages in a single UDP datagram."""
        messages = []
        offset = 0
        while offset < len(data) - 2:
            if data[offset] != 0xF0:
                break
            length = struct.unpack(">H", data[offset+1:offset+3])[0]
            msg = self.decode(data[offset:offset+length])
            if msg:
                messages.append(msg)
            offset += length
        return messages


# ─────────────────────────────────────────────────────────────────────────────
# PCAP Reader (without external libpcap binding)
# ─────────────────────────────────────────────────────────────────────────────

class PcapReader:
    """
    Reads PCAP and PCAPNG files and extracts UDP payload data.
    Uses no external libraries (only struct + open).
    """

    PCAP_MAGIC_LE  = 0xa1b2c3d4
    PCAP_MAGIC_BE  = 0xd4c3b2a1
    PCAPNG_MAGIC   = 0x0a0d0d0a

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._format = None    # 'pcap' or 'pcapng'
        self._endian = '<'
        # IP-Fragment-Puffer: {(src_ip, dst_ip, proto, ip_id): {'frags': {offset: bytes}, 'last': bool}}
        self._frag_buffer: dict = {}

    def packets(self):
        """Generator: yields (timestamp, udp_payload_bytes) for each UDP packet."""
        with open(self.filepath, 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]
            f.seek(0)

            if magic in (self.PCAP_MAGIC_LE, self.PCAP_MAGIC_BE):
                yield from self._read_pcap(f, magic)
            elif magic == self.PCAPNG_MAGIC:
                yield from self._read_pcapng(f)
            else:
                raise ValueError(f"Unknown file format (magic=0x{magic:08X})")

    def _read_pcap(self, f, magic):
        endian = '<' if magic == self.PCAP_MAGIC_LE else '>'
        # packets() seeks back to 0 before calling us, so we read the full 24-byte global header
        header = f.read(24)
        link_type = struct.unpack(endian + 'I', header[20:24])[0] if len(header) >= 24 else 1

        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', rec_hdr)
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break
            timestamp = ts_sec + ts_usec / 1e6
            result = self._extract_udp(raw, link_type)
            if result:
                yield timestamp, result[0], result[1], result[2]

    def _read_pcapng(self, f):
        """Simplified PCAPNG reader (Section Header + Interface + Enhanced Packet)."""
        endian = '<'
        link_type = 1  # default Ethernet

        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_len = struct.unpack(endian + 'II', block_hdr)

            if block_len < 12:
                break
            block_body = f.read(block_len - 12)
            f.read(4)  # trailing block_len

            if block_type == 0x0A0D0D0A:  # Section Header
                if len(block_body) >= 4:
                    bom = struct.unpack('<I', block_body[:4])[0]
                    endian = '<' if bom == 0x1A2B3C4D else '>'
            elif block_type == 0x00000001:  # Interface Description
                if len(block_body) >= 2:
                    link_type = struct.unpack(endian + 'H', block_body[:2])[0]
            elif block_type == 0x00000006:  # Enhanced Packet
                if len(block_body) >= 20:
                    ts_high, ts_low, cap_len, orig_len = struct.unpack(
                        endian + 'IIII', block_body[4:20])
                    timestamp = ((ts_high << 32) | ts_low) / 1e6
                    pkt_data = block_body[20:20 + cap_len]
                    result = self._extract_udp(pkt_data, link_type)
                    if result:
                        yield timestamp, result[0], result[1], result[2]

    def _extract_udp(self, raw: bytes, link_type: int) -> Optional[Tuple[bytes, str, int]]:
        """Extracts UDP payload + destination IP + destination port from an Ethernet/IP packet.
        Supports IP fragment reassembly (e.g. SAT2 radar with 8 kB UDP datagrams)."""
        try:
            if link_type == 1:   # Ethernet
                eth_hdr = raw[:14]
                if len(eth_hdr) < 14:
                    return None
                ether_type = struct.unpack('>H', eth_hdr[12:14])[0]
                ip_start = 14
                if ether_type == 0x8100:  # VLAN
                    ip_start += 4
                    ether_type = struct.unpack('>H', raw[16:18])[0]
                if ether_type != 0x0800:  # IPv4 only
                    return None
            elif link_type == 101:  # Raw IP
                ip_start = 0
            else:
                return None

            ip_hdr = raw[ip_start:]
            if len(ip_hdr) < 20:
                return None
            ihl       = (ip_hdr[0] & 0x0F) * 4
            protocol  = ip_hdr[9]
            if protocol != 17:  # UDP only
                return None
            src_ip    = '.'.join(str(b) for b in ip_hdr[12:16])
            dst_ip    = '.'.join(str(b) for b in ip_hdr[16:20])
            ip_id     = struct.unpack('>H', ip_hdr[4:6])[0]
            flags_frag = struct.unpack('>H', ip_hdr[6:8])[0]
            mf        = bool((flags_frag >> 13) & 1)
            frag_off  = (flags_frag & 0x1FFF) * 8

            ip_payload = raw[ip_start + ihl:]

            if not mf and frag_off == 0:
                # Nicht fragmentiert – direkt decodieren
                if len(ip_payload) < 8:
                    return None
                dst_port = struct.unpack('>H', ip_payload[2:4])[0]
                udp_len  = struct.unpack('>H', ip_payload[4:6])[0]
                return ip_payload[8:udp_len], dst_ip, dst_port

            # ── IP-Fragmentierung ────────────────────────────────────────────
            key = (src_ip, dst_ip, protocol, ip_id)
            if key not in self._frag_buffer:
                self._frag_buffer[key] = {'frags': {}, 'last_off': -1, 'dst_ip': dst_ip}
            entry = self._frag_buffer[key]
            entry['frags'][frag_off] = ip_payload
            if not mf:
                entry['last_off'] = frag_off

            # Reassemblieren sobald letztes Fragment bekannt ist
            if entry['last_off'] < 0:
                return None   # letztes Fragment noch nicht eingetroffen

            offsets = sorted(entry['frags'].keys())
            # Vollständigkeitsprüfung: lückenlose Abdeckung bis last_off
            total = bytearray()
            for off in offsets:
                if off != len(total):
                    return None  # Lücke – noch nicht vollständig
                total.extend(entry['frags'][off])

            del self._frag_buffer[key]

            # UDP-Header aus reassembliertem Datagramm lesen
            if len(total) < 8:
                return None
            dst_port = struct.unpack('>H', bytes(total[2:4]))[0]
            udp_len  = struct.unpack('>H', bytes(total[4:6]))[0]
            return bytes(total[8:udp_len]), dst_ip, dst_port

        except Exception:
            return None


# ─────────────────────────────────────────────────────────────────────────────
# PPI Radar Display
# ─────────────────────────────────────────────────────────────────────────────

class RadarPPI:
    """
    Plan Position Indicator (PPI) – classic radar plan view display.
    Accumulates CAT240 azimuths and renders them as a polar image.
    """

    def __init__(self, max_range_cells: int = 512, az_bins: int = 4096):
        self.max_range_cells = max_range_cells
        self.az_bins         = az_bins
        # Polar accumulation grid: [azimuth bins x range cells]
        self.grid = np.zeros((az_bins, max_range_cells), dtype=np.float32)
        self._lock = threading.Lock()
        self._msg_count  = 0
        self._spoke_count = defaultdict(int)
        # Pre-compute meshgrid once (polar → Cartesian)
        az_rad = np.linspace(0, 2 * np.pi, az_bins, endpoint=False)
        r      = np.arange(max_range_cells)
        R, AZ  = np.meshgrid(r, az_rad)
        self._X = (R * np.sin(AZ)).astype(np.float32)
        self._Y = (R * np.cos(AZ)).astype(np.float32)
        # pcolormesh object (created on first render() call)
        self._mesh    = None
        self._mesh_ax = None
        # Cell size in metres (determined from first decoded packet)
        self.cell_size_m      = 0.0
        self._cell_duration_ns = 0.0   # Referenzwert für Range-Wechsel-Erkennung
        self.range_resets      = 0     # Zählt automatische Grid-Resets
        # Range-Ring-Patches (werden bei cell_size-Änderung neu gezeichnet)
        self._range_ring_patches: list = []
        self._rings_drawn_for_cell_size: float = -1.0

    def add_message(self, msg: Cat240Message):
        """Inserts a CAT240 azimuth into the PPI grid."""
        with self._lock:
            # Range-Wechsel erkennen: cell_duration_ns hat sich um mehr als 1% geändert
            if msg.cell_duration_ns > 0:
                if self._cell_duration_ns == 0.0:
                    self._cell_duration_ns = msg.cell_duration_ns
                elif abs(msg.cell_duration_ns - self._cell_duration_ns) / self._cell_duration_ns > 0.01:
                    # Grid löschen und Referenzwerte aktualisieren
                    self.grid[:] = 0
                    self._msg_count = 0
                    self._spoke_count.clear()
                    self._cell_duration_ns = msg.cell_duration_ns
                    self.cell_size_m = 299_792_458.0 * msg.cell_duration_ns * 1e-9 / 2.0
                    self.range_resets += 1

            az_center = (msg.start_azimuth_deg + msg.end_azimuth_deg) / 2.0
            az_idx = int((az_center / 360.0) * self.az_bins) % self.az_bins

            cells = msg.video_data
            n = min(len(cells), self.max_range_cells - msg.start_range_cell)
            if n <= 0:
                return
            r_start = msg.start_range_cell
            r_end   = r_start + n
            if r_end > self.max_range_cells:
                r_end = self.max_range_cells
                n = r_end - r_start
            self.grid[az_idx, r_start:r_end] = cells[:n]
            self._msg_count += 1
            if self.cell_size_m == 0.0 and msg.cell_duration_ns > 0:
                self.cell_size_m       = 299_792_458.0 * msg.cell_duration_ns * 1e-9 / 2.0
                self._cell_duration_ns = msg.cell_duration_ns

    def render(self, ax, title: str = "CAT240 PPI", colormap: str = "plasma"):
        """Renders the PPI image onto a matplotlib axis."""
        import matplotlib.pyplot as plt
        import matplotlib.colors as mcolors

        with self._lock:
            grid_copy = self.grid.copy()
            msg_count = self._msg_count

        # Logarithmic normalisation (like a real radar)
        vmax = grid_copy.max()
        norm = mcolors.PowerNorm(gamma=0.5, vmin=0, vmax=vmax) if vmax > 0 else None

        if self._mesh is None or self._mesh_ax is not ax:
            # First draw: build axis, create pcolormesh
            ax.clear()
            self._range_ring_patches = []
            self._rings_drawn_for_cell_size = -1.0
            ax.set_facecolor('black')
            self._mesh = ax.pcolormesh(self._X, self._Y, grid_copy, cmap=colormap,
                                       norm=norm, shading='nearest', rasterized=True)
            self._mesh_ax = ax

            # Azimuth lines (every 30°)
            for deg in range(0, 360, 30):
                rad = np.deg2rad(deg)
                ax.plot([0, self.max_range_cells * np.sin(rad)],
                        [0, self.max_range_cells * np.cos(rad)],
                        color='#00ff41', linewidth=0.4, alpha=0.3)
                ax.text(self.max_range_cells * 1.05 * np.sin(rad),
                        self.max_range_cells * 1.05 * np.cos(rad),
                        f'{deg}°', color='#00ff41', fontsize=6,
                        ha='center', va='center')

            ax.set_xlim(-self.max_range_cells * 1.1, self.max_range_cells * 1.1)
            ax.set_ylim(-self.max_range_cells * 1.1, self.max_range_cells * 1.1)
            ax.set_aspect('equal')
            ax.tick_params(left=False, bottom=False, labelleft=False, labelbottom=False)
            for sp in ax.spines.values():
                sp.set_visible(False)
        else:
            # Subsequent update: only refresh image data and normalisation
            self._mesh.set_array(grid_copy.ravel())
            if norm is not None:
                self._mesh.set_norm(norm)

        # Range rings – neu zeichnen wenn cell_size_m sich geändert hat
        if self.cell_size_m != self._rings_drawn_for_cell_size:
            for p in self._range_ring_patches:
                try:
                    p.remove()
                except Exception:
                    pass
            self._range_ring_patches = []
            self._draw_range_rings(ax, plt)
            self._rings_drawn_for_cell_size = self.cell_size_m

        reset_info = f'  |  {self.range_resets}× Range-Reset' if self.range_resets > 0 else ''
        ax.set_title(f'{title}  |  {msg_count} azimuths{reset_info}', color='white', fontsize=10)
        return self._mesh

    def _draw_range_rings(self, ax, plt, interval_nm: float = 6.0):
        """Zeichnet Range-Ringe alle interval_nm Seemeilen (oder Bruchteile wenn cell_size unbekannt)."""
        NM = 1852.0
        if self.cell_size_m > 0:
            interval_cells = interval_nm * NM / self.cell_size_m
            max_nm = self.max_range_cells * self.cell_size_m / NM
            r_nm = interval_nm
            while r_nm <= max_nm + 0.01:
                r_cells = r_nm * NM / self.cell_size_m
                circle = plt.Circle((0, 0), r_cells, color='#00ff41',
                                    fill=False, linewidth=0.5, alpha=0.4)
                ax.add_patch(circle)
                txt = ax.text(0, r_cells, f'{r_nm:.0f} NM',
                              color='#00ff41', fontsize=6, ha='center', va='bottom',
                              alpha=0.6)
                self._range_ring_patches.extend([circle, txt])
                r_nm += interval_nm
        else:
            # Fallback ohne cell_size: Bruchteile
            for r_frac in [0.25, 0.5, 0.75, 1.0]:
                r_cells = self.max_range_cells * r_frac
                circle = plt.Circle((0, 0), r_cells, color='#00ff41',
                                    fill=False, linewidth=0.5, alpha=0.4)
                ax.add_patch(circle)
                self._range_ring_patches.append(circle)

    def clear(self):
        with self._lock:
            self.grid[:] = 0
            self._msg_count = 0

    def get_spoke(self, azimuth_deg: float) -> Tuple[np.ndarray, float]:
        """Returns the azimuth (amplitude values) for a given azimuth angle."""
        az_idx = int((azimuth_deg % 360.0) / 360.0 * self.az_bins) % self.az_bins
        with self._lock:
            return self.grid[az_idx].copy(), azimuth_deg

    def get_ring(self, range_cell: int) -> np.ndarray:
        """Returns all amplitude values for a range cell (all azimuths, 0–360°)."""
        rc = max(0, min(range_cell, self.max_range_cells - 1))
        with self._lock:
            return self.grid[:, rc].copy()


# ─────────────────────────────────────────────────────────────────────────────
# A-Scope
# ─────────────────────────────────────────────────────────────────────────────

class AScope:
    """
    A-Scope: amplitude display of a radar azimuth or a range ring.

    Mode 'range':   Amplitude vs. range cell   (fixed azimuth, left-click in PPI)
    Mode 'azimuth': Amplitude vs. angle 0–360° (fixed range ring, left-click in PPI)

    Right-click in PPI → context menu to switch mode.
    """

    GREEN    = '#00ff41'
    BG       = '#0a0a0a'
    GRID     = '#1a3a1a'
    CURSOR   = '#ffcc00'
    WM       = '#ff44ff'   # width measurement colour
    LC_COLOR = '#ffaa00'   # Farbe der Log-Compression-Kurve

    FWHM_HDR   = 'FWHM'
    CURSOR_HDR = 'Cursor'

    @staticmethod
    def _row(lbl: str, val: str) -> str:
        """Zeile: Label linksbündig 10 Zeichen, Wert rechtsbündig 8 Zeichen."""
        return f'{lbl:<10}{val:>8}'

    def __init__(self, ppi: 'RadarPPI', initial_azimuth: float = 0.0,
                 log_compress: bool = False):
        import matplotlib.pyplot as plt
        import matplotlib.gridspec as gridspec

        self.ppi             = ppi
        self.azimuth         = initial_azimuth
        self.range_cell      = 0
        self.mode            = 'range'   # 'range' | 'azimuth'
        self._cursor_x: Optional[float] = None
        self._mode_change_cb   = None    # fn(mode)     – PPI overlay mode change
        self._cursor_change_cb = None    # fn(x | None) – PPI overlay cursor position
        self._log_compress     = log_compress
        self._p0: float        = 1.0
        self._p0_cache_count: int = -1  # _msg_count bei letzter P0-Schätzung
        self._show_linear: bool = True
        self._show_log:    bool = True

        self.fig = plt.figure(figsize=(12, 4), facecolor=self.BG)
        self.fig.canvas.manager.set_window_title('A-Scope  |  CAT240')

        gs = gridspec.GridSpec(1, 1, figure=self.fig,
                               left=0.07, right=0.77, top=0.88, bottom=0.17)
        self.ax = self.fig.add_subplot(gs[0])
        self._style_axes()

        self._line,     = self.ax.plot([], [], color=self.GREEN,
                                       linewidth=1.2, alpha=0.95)
        self._fill      = None
        self._vline     = self.ax.axvline(x=0, color=self.CURSOR,
                                          linewidth=1.0, linestyle='--',
                                          visible=False)
        self._info_text = self.fig.text(
            0.97, 0.90, '', transform=self.fig.transFigure,
            color=self.CURSOR, fontsize=9, va='top', ha='right',
            fontfamily='monospace',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#1a1a00',
                      edgecolor=self.CURSOR, alpha=0.85))

        # Azimuth selection (only in 'azimuth' mode)
        SEL = '#ff6600'
        self._az_sel_start: Optional[float] = None
        self._az_sel_end:   Optional[float] = None
        self._az_sel_fill   = None
        self._az_sel_vline_s = self.ax.axvline(x=0, color=SEL, linewidth=1.2,
                                               linestyle='--', visible=False)
        self._az_sel_vline_e = self.ax.axvline(x=0, color=SEL, linewidth=1.2,
                                               linestyle='--', visible=False)
        self._az_sel_text = self.ax.text(
            0.5, 0.93, '', transform=self.ax.transAxes,
            color=SEL, fontsize=8, va='top', ha='center',
            fontfamily='monospace',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#1a0800',
                      edgecolor=SEL, alpha=0.0))

        # Width measurement overlay (left-click in A-Scope)
        self._wm_hline   = None
        self._wm_vline_l = None
        self._wm_vline_r = None
        self._wm_fill    = None
        self._wm_text    = self.fig.text(
            0.97, 0.46, '', transform=self.fig.transFigure,
            color=self.WM, fontsize=9, va='top', ha='right',
            fontfamily='monospace',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#1a001a',
                      edgecolor=self.WM, linewidth=1.2, alpha=0.85))

        # Zweite Y-Achse für Log-Kompression (nur wenn aktiviert)
        self.ax2       = None
        self._line_lc  = None
        self._fill_lc  = None
        if log_compress:
            self.ax2 = self.ax.twinx()
            self.ax2.set_facecolor(self.BG)
            self.ax2.tick_params(colors=self.LC_COLOR, labelsize=7)
            for spine in self.ax2.spines.values():
                spine.set_edgecolor(self.LC_COLOR)
            self.ax2.set_ylabel('Log-compressed (0–1)', fontsize=8,
                                color=self.LC_COLOR)
            self.ax2.set_ylim(0, 1.1)
            self._line_lc, = self.ax2.plot([], [], color=self.LC_COLOR,
                                           linewidth=1.0, alpha=0.85,
                                           linestyle='--', label='log-compressed')

        self._mode_confirmed = False  # True erst nach erstem PPI-Klick
        self._zoom_xlim: Optional[tuple] = None   # (lo, hi) wenn gezoomt, sonst None
        self._pan_press_px:   Optional[float] = None   # Maus-X in Pixel beim Drücken
        self._pan_xlim_press: Optional[tuple] = None   # xlim beim Drücken
        self._pan_moved:      bool = False             # Wurde die Maus weit genug bewegt?

        self._update_title()

        self.fig.canvas.mpl_connect('motion_notify_event',  self._on_mouse_move)
        self.fig.canvas.mpl_connect('axes_leave_event',     self._on_axes_leave)
        self.fig.canvas.mpl_connect('button_press_event',   self._on_click)
        self.fig.canvas.mpl_connect('button_release_event', self._on_button_release)
        self.fig.canvas.mpl_connect('scroll_event',         self._on_scroll)
        self._setup_buttons()

    # ── Style ─────────────────────────────────────────────────────────────────

    def _style_axes(self):
        ax = self.ax
        ax.set_facecolor(self.BG)
        ax.tick_params(colors=self.GREEN, labelsize=7)
        for spine in ax.spines.values():
            spine.set_color(self.GREEN)
        ax.xaxis.label.set_color(self.GREEN)
        ax.yaxis.label.set_color(self.GREEN)
        ax.set_ylabel('Amplitude', fontsize=8, color=self.GREEN)
        ax.set_ylim(0, 255.0)   # Fixe linke Y-Achse: immer 0–255
        ax.grid(True, color=self.GRID, linewidth=0.5, linestyle=':')
        self._update_xlabel()

    # ── Log-Kompression ───────────────────────────────────────────────────────

    def _estimate_p0(self) -> float:
        """Schätzt P₀ aus dem aktuellen Grid (10. Perzentile aller Nicht-Null-Werte).
        Ergebnis wird gecacht bis sich _msg_count ändert."""
        count = self.ppi._msg_count
        if count == self._p0_cache_count:
            return self._p0
        with self.ppi._lock:
            flat = self.ppi.grid[self.ppi.grid > 0]
        if flat.size < 10:
            return self._p0
        self._p0 = float(np.percentile(flat, 10))
        self._p0_cache_count = count
        return self._p0

    def _compress(self, data: np.ndarray) -> np.ndarray:
        """Soft-Log-Kompression: clip(0,255, 20 + 240·log₁₀(1 + P/P₀))"""
        with np.errstate(divide='ignore', invalid='ignore'):
            out = 240.0 * np.log10(1.0 + data / self._p0)
        return np.clip(out, 0.0, 255.0)

    def _update_xlabel(self):
        if self.mode == 'range':
            self.ax.set_xlabel('Range Cell', fontsize=8, color=self.GREEN)
        else:
            self.ax.set_xlabel('Azimuth (°)', fontsize=8, color=self.GREEN)

    def _update_title(self):
        if self.mode == 'range':
            detail = f'Azimuth {self.azimuth:.1f}°'
        else:
            rc = self.range_cell
            if self.ppi.cell_size_m > 0:
                dist_m = rc * self.ppi.cell_size_m
                detail = f'Range Cell {rc}  ({dist_m:,.0f} m / {dist_m/1852:.1f} NM)'
            else:
                detail = f'Range Cell {rc}'
        mode_lbl = 'Amp vs. Range' if self.mode == 'range' else 'Amp vs. Angle'
        zoom_hint = '  |  Scroll: zoom  |  Dbl-click: reset' if self._zoom_xlim is not None else '  |  Scroll: zoom'
        lc_hint   = f'  |  LC P₀≈{self._p0:.0f}' if self._log_compress else ''
        self.fig.suptitle(
            f'A-Scope  [{mode_lbl}]  |  {detail}  |  L-click: FWHM  |  R-click: span selection{zoom_hint}{lc_hint}',
            color=self.GREEN, fontsize=9, y=0.97)

    # ── Render ────────────────────────────────────────────────────────────────

    def render(self):
        if self.mode == 'range':
            self._render_range()
        else:
            self._render_azimuth()

    def _render_range(self):
        if not self._mode_confirmed:
            self._line.set_data([], [])
            if self._line_lc is not None:
                self._line_lc.set_data([], [])
            self._update_title()
            self.fig.canvas.draw_idle()
            return
        cells, _ = self.ppi.get_spoke(self.azimuth)
        n = len(cells)
        if n == 0:
            return
        x = np.arange(n)
        self._line.set_data(x, cells)
        self._line.set_visible(self._show_linear)
        if self._fill is not None:
            self._fill.remove()
        self._fill = self.ax.fill_between(x, 0, cells, color=self.GREEN,
                                          alpha=0.18 if self._show_linear else 0.0)
        vmax = cells.max() if cells.max() > 0 else 1.0
        self.ax.set_xlim(0, n)
        self.ax.set_ylim(0, 255.0)
        if self._log_compress:
            self._estimate_p0()
            lc = self._compress(cells) / 255.0
            self._line_lc.set_data(x, lc)
            self._line_lc.set_visible(self._show_log)
            if self._fill_lc is not None:
                self._fill_lc.remove()
            self._fill_lc = self.ax2.fill_between(x, 0, lc, color=self.LC_COLOR,
                                                   alpha=0.10 if self._show_log else 0.0)
        if self._zoom_xlim is not None:
            self._apply_zoom(cells, np.arange(n, dtype=float))
        self._update_title()
        if self._cursor_x is not None:
            self._refresh_cursor(self._cursor_x, cells, x_max=n)
        self.fig.canvas.draw_idle()

    def _render_azimuth(self):
        if not self._mode_confirmed:
            self._line.set_data([], [])
            self._update_title()
            self.fig.canvas.draw_idle()
            return
        ring = self.ppi.get_ring(self.range_cell)
        n    = len(ring)
        if n == 0:
            return
        x = np.linspace(0.0, 360.0, n, endpoint=False)
        self._line.set_data(x, ring)
        self._line.set_visible(self._show_linear)
        if self._fill is not None:
            self._fill.remove()
        self._fill = self.ax.fill_between(x, 0, ring, color=self.GREEN,
                                          alpha=0.18 if self._show_linear else 0.0)
        vmax = ring.max() if ring.max() > 0 else 1.0
        self.ax.set_xlim(0, 360)
        self.ax.set_ylim(0, 255.0)
        if self._log_compress:
            self._estimate_p0()
            lc = self._compress(ring) / 255.0
            self._line_lc.set_data(x, lc)
            self._line_lc.set_visible(self._show_log)
            if self._fill_lc is not None:
                self._fill_lc.remove()
            self._fill_lc = self.ax2.fill_between(x, 0, lc, color=self.LC_COLOR,
                                                   alpha=0.10 if self._show_log else 0.0)
        x_arr = np.linspace(0.0, 360.0, n, endpoint=False)
        if self._zoom_xlim is not None:
            self._apply_zoom(ring, x_arr)
        self._update_title()
        if self._cursor_x is not None:
            self._refresh_cursor(self._cursor_x, ring, x_max=360)
        # Redraw selection after data update
        if self._az_sel_start is not None and self._az_sel_end is not None:
            self._update_az_selection()
        self.fig.canvas.draw_idle()

    def clear(self):
        """Setzt den A-Scope-Inhalt zurück (leere Anzeige bis zum nächsten PPI-Klick)."""
        self._line.set_data([], [])
        if self._fill is not None:
            try:
                self._fill.remove()
            except Exception:
                pass
            self._fill = None
        if self._line_lc is not None:
            self._line_lc.set_data([], [])
        if self._fill_lc is not None:
            try:
                self._fill_lc.remove()
            except Exception:
                pass
            self._fill_lc = None
        self._vline.set_visible(False)
        self._info_text.set_text('')
        self._az_sel_vline_s.set_visible(False)
        self._az_sel_vline_e.set_visible(False)
        self._az_sel_text.set_text('')
        if self._az_sel_fill is not None:
            try:
                self._az_sel_fill.remove()
            except Exception:
                pass
            self._az_sel_fill = None
        self._az_sel_start = None
        self._az_sel_end   = None
        self._wm_text.set_text('')
        if self._wm_fill is not None:
            try:
                self._wm_fill.remove()
            except Exception:
                pass
            self._wm_fill = None
        self._zoom_xlim      = None
        self._cursor_x       = None
        self._mode_confirmed = False
        self._update_title()
        self.fig.canvas.draw_idle()

    # ── Hilfsmethode: Event-Achsen-Prüfung ───────────────────────────────────

    def _in_axes(self, event) -> bool:
        """True wenn der Event auf ax oder ax2 (twinx) liegt."""
        return event.inaxes is self.ax or (
            self.ax2 is not None and event.inaxes is self.ax2)

    # ── Zoom ──────────────────────────────────────────────────────────────────

    def _on_scroll(self, event):
        """Scrollrad-Zoom auf der X-Achse, zentriert auf Cursor-Position."""
        if not self._in_axes(event) or event.xdata is None:
            return
        factor = 0.6 if event.step > 0 else 1.0 / 0.6
        xlo, xhi = self.ax.get_xlim()
        x = event.xdata
        new_lo = x - (x - xlo) * factor
        new_hi = x + (xhi - x) * factor
        # Grenzen des aktuellen Modus
        x_max = 360.0 if self.mode == 'azimuth' else float(
            len(self.ppi.get_spoke(self.azimuth)[0]) or 1)
        new_lo = max(0.0, new_lo)
        new_hi = min(x_max, new_hi)
        if new_hi - new_lo < 2:   # Minimalzoom
            return
        self._zoom_xlim = (new_lo, new_hi)
        if self.mode == 'range':
            data, _ = self.ppi.get_spoke(self.azimuth)
            x_arr = np.arange(len(data), dtype=float)
        else:
            data = self.ppi.get_ring(self.range_cell)
            x_arr = np.linspace(0.0, 360.0, len(data), endpoint=False)
        self._apply_zoom(data, x_arr)
        self._update_title()
        self.fig.canvas.draw_idle()

    def _apply_zoom(self, data: np.ndarray, x_arr: np.ndarray):
        """Setzt xlim auf _zoom_xlim und passt ylim an die sichtbaren Daten an."""
        if self._zoom_xlim is None:
            return
        lo, hi = self._zoom_xlim
        self.ax.set_xlim(lo, hi)
        if len(data) > 0:
            mask = (x_arr >= lo) & (x_arr <= hi)
            if mask.any():
                vmax = float(data[mask].max()) if data[mask].max() > 0 else 1.0
                self.ax.set_ylim(0, min(vmax * 1.15, 255.0))

    # ── Buttons ───────────────────────────────────────────────────────────────

    def _setup_buttons(self):
        from matplotlib.widgets import Button
        BG_BTN = '#1a1a1a'
        BG_HOV = '#1a3a1a'
        btn_h  = 0.06
        btn_y  = 0.02
        gap    = 0.01
        x0     = 0.07
        x1     = 0.77
        labels = ['Lin', 'Log', '-', '+', '<', '>'] if self._log_compress else ['-', '+', '<', '>']
        n      = len(labels)
        btn_w  = (x1 - x0 - (n - 1) * gap) / n
        self._btns: dict = {}
        for i, lbl in enumerate(labels):
            ax_b = self.fig.add_axes([x0 + i * (btn_w + gap), btn_y, btn_w, btn_h])
            b = Button(ax_b, lbl, color=BG_BTN, hovercolor=BG_HOV)
            b.label.set_color(self.GREEN)
            b.label.set_fontsize(9)
            self._btns[lbl] = b
        if self._log_compress:
            self._btns['Lin'].on_clicked(lambda e: self._toggle_linear())
            self._btns['Log'].on_clicked(lambda e: self._toggle_log())
        self._btns['-'].on_clicked(lambda e: self._zoom_step(1.0 / 0.6))
        self._btns['+'].on_clicked(lambda e: self._zoom_step(0.6))
        self._btns['<'].on_clicked(lambda e: self._pan_step(-1))
        self._btns['>'].on_clicked(lambda e: self._pan_step(+1))
        self._update_btn_colors()
        self._info_text.set_text(self._cursor_placeholder())
        self._wm_text.set_text(self._fwhm_placeholder())

    def _toggle_linear(self):
        self._show_linear = not self._show_linear
        self._update_btn_colors()
        self.render()

    def _toggle_log(self):
        self._show_log = not self._show_log
        self._update_btn_colors()
        self.render()

    def _update_btn_colors(self):
        if not self._log_compress:
            return
        active_c   = self.GREEN
        inactive_c = '#336633'
        self._btns['Lin'].label.set_color(active_c if self._show_linear else inactive_c)
        self._btns['Log'].label.set_color(active_c if self._show_log    else inactive_c)
        self.fig.canvas.draw_idle()

    def _cursor_placeholder(self) -> str:
        r = self._row
        rows = [self.CURSOR_HDR,
                r('Az:',   '--°'),
                r('Cell:', '--'),
                r('Dist:', '-- m'),
                r('',      '-- NM'),
                r('Amp:',  '--'),
                r('Rel:',  '--%')]
        if self._log_compress:
            rows.append(r('LC:', '--'))
        return '\n'.join(rows)

    def _fwhm_placeholder(self) -> str:
        r = self._row
        rows = [self.FWHM_HDR]
        if self.mode == 'range':
            rows += [r('cells:',  '--'),
                     r('Width:', '-- m'),
                     r('',        '-- NM')]
        else:
            rows += [r('Beamwidth:', '--°'),
                     r('Az count:',  '--'),
                     r('Width:', '-- NM')]
        rows += [r('peak:', '--'),
                 r('-6dB:', '--')]
        return '\n'.join(rows)

    def _zoom_step(self, factor: float):
        xlo, xhi = self.ax.get_xlim()
        center = (xlo + xhi) / 2.0
        x_max  = 360.0 if self.mode == 'azimuth' else float(
            len(self.ppi.get_spoke(self.azimuth)[0]) or 1)
        new_lo = max(0.0, center - (center - xlo) * factor)
        new_hi = min(x_max, center + (xhi - center) * factor)
        if new_hi - new_lo < 2:
            return
        self._zoom_xlim = (new_lo, new_hi)
        self.render()

    def _pan_step(self, direction: int):
        xlo, xhi = self.ax.get_xlim()
        span  = xhi - xlo
        shift = span * 0.15 * direction
        x_max = 360.0 if self.mode == 'azimuth' else float(
            len(self.ppi.get_spoke(self.azimuth)[0]) or 1)
        new_lo = max(0.0, xlo + shift)
        new_hi = min(x_max, xhi + shift)
        if new_lo == 0.0:
            new_hi = min(x_max, span)
        if new_hi == x_max:
            new_lo = max(0.0, x_max - span)
        self._zoom_xlim = (new_lo, new_hi)
        self.ax.set_xlim(new_lo, new_hi)
        self.fig.canvas.draw_idle()

    # ── Interaction ───────────────────────────────────────────────────────────

    def _on_mouse_move(self, event):
        # ── Rechts-Drag Pan ───────────────────────────────────────────────────
        if self._pan_press_px is not None and event.x is not None:
            dx_px = event.x - self._pan_press_px
            if abs(dx_px) > 3:
                self._pan_moved = True
            if self._pan_moved and self._pan_xlim_press is not None:
                ax_w = self.ax.get_window_extent().width
                if ax_w > 0:
                    lo0, hi0 = self._pan_xlim_press
                    shift = -dx_px / ax_w * (hi0 - lo0)
                    x_max = 360.0 if self.mode == 'azimuth' else float(
                        len(self.ppi.get_spoke(self.azimuth)[0]) or 1)
                    new_lo = max(0.0, lo0 + shift)
                    new_hi = min(x_max, hi0 + shift)
                    # Breite erhalten, falls an Rand angestoßen
                    if new_lo == 0.0:
                        new_hi = min(x_max, hi0 - lo0)
                    if new_hi == x_max:
                        new_lo = max(0.0, x_max - (hi0 - lo0))
                    self._zoom_xlim = (new_lo, new_hi)
                    self.ax.set_xlim(new_lo, new_hi)
                    self.fig.canvas.draw_idle()
                return   # Cursor-Overlay während Pan unterdrücken

        if not self._in_axes(event) or event.xdata is None:
            return
        self._cursor_x = event.xdata
        if self.mode == 'range':
            data, _ = self.ppi.get_spoke(self.azimuth)
            self._refresh_cursor(event.xdata, data, x_max=len(data))
        else:
            data = self.ppi.get_ring(self.range_cell)
            self._refresh_cursor(event.xdata, data, x_max=360)
        if self._cursor_change_cb:
            self._cursor_change_cb(event.xdata)
        self.fig.canvas.draw_idle()

    def _on_axes_leave(self, event):
        self._cursor_x = None
        self._vline.set_visible(False)
        self._info_text.set_text(self._cursor_placeholder())
        if self._cursor_change_cb:
            self._cursor_change_cb(None)
        self.fig.canvas.draw_idle()

    def _on_click(self, event):
        """Click handler for the A-Scope.
        Left-click       : FWHM measurement of the nearest peak (both modes).
        Left-dblclick    : Zoom zurücksetzen.
        Right-drag       : Pan (Ansicht verschieben).
        Right-click (no drag, azimuth mode) : manual span selection.
        """
        if not self._in_axes(event) or event.xdata is None:
            return

        if event.dblclick and event.button == 1:
            # Doppelklick → Zoom zurücksetzen
            self._zoom_xlim = None
            self.render()
            return

        if event.button == 3:
            # Rechte Maustaste gedrückt → Pan-Start merken
            self._pan_press_px   = float(event.x)
            self._pan_xlim_press = self.ax.get_xlim()
            self._pan_moved      = False

        if event.button == 1:
            # Left-click → FWHM
            self._measure_width_at(float(event.xdata))
            self.fig.canvas.draw_idle()

        elif event.button == 3 and self.mode == 'azimuth':
            # Right-click (ohne Drag) → manual span selection
            # wird erst in button_release ausgewertet
            pass

    def _on_button_release(self, event):
        """Rechte Maustaste losgelassen: Pan abschließen oder Span-Selection auslösen."""
        if event.button != 3:
            return
        moved = self._pan_moved
        # Pan-Zustand zurücksetzen
        self._pan_press_px   = None
        self._pan_xlim_press = None
        self._pan_moved      = False

        if moved:
            return   # War ein Drag → keine Span-Selection

        # Kein Drag → Span-Selection (azimuth mode only)
        if not self._in_axes(event) or event.xdata is None:
            return
        if self.mode != 'azimuth':
            return
        x = float(event.xdata)
        if self._az_sel_start is None or self._az_sel_end is not None:
            self._clear_az_selection()
            self._az_sel_start = x
            self._az_sel_vline_s.set_xdata([x, x])
            self._az_sel_vline_s.set_visible(True)
        else:
            self._az_sel_end = x
            self._az_sel_vline_e.set_xdata([x, x])
            self._az_sel_vline_e.set_visible(True)
            self._update_az_selection()
        self.fig.canvas.draw_idle()

    # ── Width measurement ─────────────────────────────────────────────────────

    def _measure_width_at(self, x_click: float):
        """Measures the FWHM (50 % of peak amplitude) of the nearest peak to x_click."""
        if self.mode == 'range':
            data, _ = self.ppi.get_spoke(self.azimuth)
            x_arr   = np.arange(len(data), dtype=np.float32)
        else:
            data  = self.ppi.get_ring(self.range_cell)
            x_arr = np.linspace(0.0, 360.0, len(data), endpoint=False)

        n = len(data)
        if n == 0:
            return

        # x-coordinate of the click in data units
        x_click_data = float(x_click)

        # Find all local maxima (neighbours on both sides are smaller)
        peak_indices = [i for i in range(1, n - 1)
                        if data[i] > data[i - 1] and data[i] >= data[i + 1]
                        and data[i] > 0]
        if not peak_indices:
            self._clear_width_measure()
            return

        # Pick the local maximum whose x-position is closest to the click
        peak_idx = min(peak_indices, key=lambda i: abs(float(x_arr[i]) - x_click_data))

        peak_amp  = float(data[peak_idx])
        threshold = peak_amp / 2.0   # FWHM: 50 % of peak amplitude

        # Walk left from peak until amplitude drops below threshold
        i_left = peak_idx
        while i_left > 0 and data[i_left] > threshold:
            i_left -= 1
        if i_left > 0 and data[i_left] <= threshold < data[i_left + 1]:
            frac   = (data[i_left + 1] - threshold) / (data[i_left + 1] - data[i_left])
            x_left = x_arr[i_left + 1] - frac * (x_arr[i_left + 1] - x_arr[i_left])
        else:
            x_left = x_arr[i_left]

        # Walk right from peak until amplitude drops below threshold
        i_right = peak_idx
        while i_right < n - 1 and data[i_right] > threshold:
            i_right += 1
        if i_right < n - 1 and data[i_right] <= threshold < data[i_right - 1]:
            frac    = (data[i_right - 1] - threshold) / (data[i_right - 1] - data[i_right])
            x_right = x_arr[i_right - 1] + frac * (x_arr[i_right] - x_arr[i_right - 1])
        else:
            x_right = x_arr[i_right]

        width = x_right - x_left

        # Build label (label links, Zahl rechts, gleiche Spaltenbreite wie Cursor-Readout)
        r = self._row
        rows = [self.FWHM_HDR]
        if self.mode == 'range':
            rows.append(r('cells:', f'{width:.1f}'))
            if self.ppi.cell_size_m > 0:
                w_m  = width * self.ppi.cell_size_m
                w_nm = w_m / 1852.0
                rows += [r('Width:', f'{w_m:.0f} m'),
                         r('',        f'{w_nm:.2f} NM')]
        else:
            az_count = round(width / 360.0 * self.ppi.az_bins)
            rows += [r('Beamwidth:', f'{width:.3f}°'),
                     r('Az count:',  str(az_count))]
            if self.ppi.cell_size_m > 0:
                range_m = self.range_cell * self.ppi.cell_size_m
                arc_m   = 2 * np.pi * range_m * (width / 360.0)
                arc_nm  = arc_m / 1852.0
                rows += [r('Width:', f'{arc_nm:.2f} NM')]
        rows += [r('peak:', f'{peak_amp:.0f}'),
                 r('-6dB:', f'{threshold:.0f}')]
        label = '\n'.join(rows)

        # Draw overlays
        self._clear_width_measure()
        self._wm_hline   = self.ax.axhline(y=threshold, color=self.WM,
                                            linewidth=1.0, linestyle='--', alpha=0.75)
        self._wm_vline_l = self.ax.axvline(x=x_left,    color=self.WM,
                                            linewidth=1.2, linestyle=':',  alpha=0.9)
        self._wm_vline_r = self.ax.axvline(x=x_right,   color=self.WM,
                                            linewidth=1.2, linestyle=':',  alpha=0.9)
        # Shade region under peak between the two crossings
        mask = (x_arr >= x_left) & (x_arr <= x_right)
        self._wm_fill = self.ax.fill_between(
            x_arr, threshold, data, where=mask,
            color=self.WM, alpha=0.18)
        self._wm_text.set_text(label)

    def _clear_width_measure(self):
        """Removes all width measurement overlays."""
        for attr in ('_wm_hline', '_wm_vline_l', '_wm_vline_r', '_wm_fill'):
            obj = getattr(self, attr, None)
            if obj is not None:
                try:
                    obj.remove()
                except Exception:
                    pass
                setattr(self, attr, None)
        self._wm_text.set_text(self._fwhm_placeholder())

    def _update_az_selection(self):
        """Fills the area between start and end and shows count values."""
        if self._az_sel_start is None or self._az_sel_end is None:
            return
        ring = self.ppi.get_ring(self.range_cell)
        n    = len(ring)
        if n == 0:
            return
        start = min(self._az_sel_start, self._az_sel_end)
        end   = max(self._az_sel_start, self._az_sel_end)
        x     = np.linspace(0.0, 360.0, n, endpoint=False)
        mask  = (x >= start) & (x <= end)

        if self._az_sel_fill is not None:
            try:
                self._az_sel_fill.remove()
            except Exception:
                pass
        self._az_sel_fill = self.ax.fill_between(
            x, 0, ring, where=mask, color='#ff6600', alpha=0.35)

        total_bins = int(np.sum(mask))
        echo_bins  = int(np.count_nonzero(ring[mask]))
        span_deg   = end - start
        SEL = '#ff6600'
        self._az_sel_text.set_text(
            f'Selection: {span_deg:.1f}°  |  {total_bins} azimuths  |  {echo_bins} echoes')
        self._az_sel_text.get_bbox_patch().set_alpha(0.85)
        self._az_sel_text.set_visible(True)

    def _clear_az_selection(self):
        """Resets the azimuth selection."""
        self._az_sel_start = None
        self._az_sel_end   = None
        self._az_sel_vline_s.set_visible(False)
        self._az_sel_vline_e.set_visible(False)
        if self._az_sel_fill is not None:
            try:
                self._az_sel_fill.remove()
            except Exception:
                pass
            self._az_sel_fill = None
        self._az_sel_text.set_text('')
        self._az_sel_text.get_bbox_patch().set_alpha(0.0)

    def _refresh_cursor(self, x: float, data: np.ndarray, x_max: float):
        if x is None:
            return
        r = self._row
        n = len(data)

        # Werte bestimmen — feste Größen je nach Modus immer bekannt
        if self.mode == 'range':
            idx      = int(round(x))
            az_str   = f'{self.azimuth:.1f}°'
            cell_str = str(idx) if 0 <= idx < n else '--'
            if 0 <= idx < n and self.ppi.cell_size_m > 0:
                dm = idx * self.ppi.cell_size_m
                dist_m_str  = f'{dm:.0f} m'
                dist_nm_str = f'{dm / 1852.0:.2f} NM'
            else:
                dist_m_str  = '-- m'
                dist_nm_str = '-- NM'
        else:
            idx      = int(round(x / 360.0 * n)) % n if n > 0 else -1
            az_str   = f'{x:.1f}°'
            rc       = self.range_cell
            cell_str = str(rc)
            if self.ppi.cell_size_m > 0:
                dm = rc * self.ppi.cell_size_m
                dist_m_str  = f'{dm:.0f} m'
                dist_nm_str = f'{dm / 1852.0:.2f} NM'
            else:
                dist_m_str  = '-- m'
                dist_nm_str = '-- NM'

        if 0 <= idx < n:
            amp  = data[idx]
            vmax = data.max() if data.max() > 0 else 1.0
            amp_str = f'{amp:.1f}'
            rel_str = f'{amp / vmax * 100.0:.1f}%'
            lc_str  = (f'{float(self._compress(np.array([amp]))[0]) / 255.0:.3f}'
                       if self._log_compress else None)
            self._vline.set_xdata([x, x])
            self._vline.set_visible(True)
        else:
            amp_str = '--'
            rel_str = '--%'
            lc_str  = '--' if self._log_compress else None
            self._vline.set_visible(False)

        rows = [self.CURSOR_HDR,
                r('Az:',   az_str),
                r('Cell:', cell_str),
                r('Dist:', dist_m_str),
                r('',      dist_nm_str),
                r('Amp:',  amp_str),
                r('Rel:',  rel_str)]
        if lc_str is not None:
            rows.append(r('LC:', lc_str))
        self._info_text.set_text('\n'.join(rows))

    # ── Public control ────────────────────────────────────────────────────────

    def set_azimuth(self, azimuth_deg: float):
        self.azimuth = azimuth_deg % 360.0
        self._mode_confirmed = True
        if self.mode == 'range':
            self.render()

    def set_range_cell(self, range_cell: int):
        self.range_cell = max(0, min(range_cell, self.ppi.max_range_cells - 1))
        self._mode_confirmed = True
        if self.mode == 'azimuth':
            self.render()

    def set_mode(self, mode: str):
        """Switches between 'range' and 'azimuth' mode."""
        if mode not in ('range', 'azimuth'):
            return
        if self.mode == 'azimuth' and mode != 'azimuth':
            self._clear_az_selection()
        self._clear_width_measure()
        self._mode_confirmed = False
        self.mode = mode
        self._info_text.set_text(self._cursor_placeholder())
        if self._mode_change_cb:
            self._mode_change_cb(mode)
        self._update_xlabel()
        # Reset axis so no stale fill artefacts remain
        if self._fill is not None:
            try:
                self._fill.remove()
            except Exception:
                pass
            self._fill = None
        self._line.set_data([], [])
        self._vline.set_visible(False)
        self._info_text.set_text('')
        self.render()

    def handle_ppi_click(self, x: float, y: float):
        """
        Processes a left-click in the PPI.
        In range mode: set azimuth.
        In azimuth mode: set range cell.
        Returns the new azimuth (for az_line) – None in azimuth mode.
        """
        if self.mode == 'range':
            az_deg = np.degrees(np.arctan2(x, y)) % 360.0
            self.set_azimuth(az_deg)
            return az_deg
        else:
            rc = int(round(np.sqrt(x**2 + y**2)))
            self.set_range_cell(rc)
            return None   # az_line nicht bewegen

    def is_window_visible(self) -> bool:
        """Returns True if the A-Scope window is visible."""
        win = self.fig.canvas.manager.window
        try:                          # Tk
            return bool(win.winfo_viewable())
        except AttributeError:
            pass
        try:                          # Qt
            return bool(win.isVisible())
        except AttributeError:
            pass
        return True

    def toggle_window(self):
        """Shows or hides the A-Scope window (backend-independent)."""
        win = self.fig.canvas.manager.window
        try:                          # Tk
            if win.winfo_viewable():
                win.withdraw()
            else:
                win.deiconify()
            return
        except AttributeError:
            pass
        try:                          # Qt
            if win.isVisible():
                win.hide()
            else:
                win.show()
            return
        except AttributeError:
            pass

    def show(self):
        self.fig.show()


# ─────────────────────────────────────────────────────────────────────────────
# Stream selection helper functions
# ─────────────────────────────────────────────────────────────────────────────

_MCAST_PREFIXES = tuple(f'{i}.' for i in range(224, 240))


def _is_multicast(ip: str) -> bool:
    return ip.startswith(_MCAST_PREFIXES)


def scan_pcap_streams(filepath: str) -> dict:
    """
    Fast scan of a PCAP/PCAPNG file without full ASTERIX decoding.
    Returns {(dst_ip, dst_port): (total_packets, cat240_packets)} sorted
    descending by total packet count.
    CAT240 packets are identified by first payload byte == 0xF0.
    """
    reader  = PcapReader(filepath)
    streams: dict = {}
    for _ts, udp, dst_ip, dst_port in reader.packets():
        key = (dst_ip, dst_port)
        total, cat240 = streams.get(key, (0, 0))
        is_cat240 = len(udp) > 0 and udp[0] == 0xF0
        streams[key] = (total + 1, cat240 + (1 if is_cat240 else 0))
    return dict(sorted(streams.items(), key=lambda x: -x[1][0]))


def _prompt_stream_selection(streams: dict):
    """
    Shows detected UDP streams and prompts for selection via terminal.
    streams: {(dst_ip, dst_port): (total_packets, cat240_packets)}
    Pre-filters to CAT240 streams; falls back to all streams if none found.
    Returns (dst_ip, dst_port) or None if streams dict is empty.
    """
    if not streams:
        return None

    # Vorfiltern auf CAT240-Streams
    cat240 = {k: v for k, v in streams.items() if v[1] > 0}
    if cat240:
        candidates = cat240
        label = 'CAT240 streams'
    else:
        candidates = streams
        label = 'UDP streams (no CAT240 detected)'

    keys = list(candidates.keys())
    if len(keys) == 1:
        ip, port = keys[0]
        total, n240 = candidates[keys[0]]
        mc = ' (Multicast)' if _is_multicast(ip) else ''
        print(f"\n  Single {label}: {ip}:{port}{mc}  –  {total} packets  ({n240} CAT240)")
        return keys[0]

    print(f"\n  Available {label}:")
    for i, (ip, port) in enumerate(keys, 1):
        total, n240 = candidates[(ip, port)]
        mc = ' (Multicast)' if _is_multicast(ip) else ''
        cat_hint = f'  ({n240} CAT240)' if n240 > 0 else ''
        print(f"    [{i}]  {ip}:{port}{mc}  –  {total} packets{cat_hint}")

    while True:
        try:
            choice = input(f"\n  Select stream [1–{len(keys)}]: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(keys):
                return keys[idx]
        except (ValueError, EOFError, KeyboardInterrupt):
            pass
        print(f"  Please enter a number between 1 and {len(keys)}.")


def _prompt_live_config(default_host: str = '0.0.0.0',
                        default_port: int = 5000,
                        default_multicast: str = '') -> tuple:
    """
    Interactive terminal prompt for live UDP configuration.
    Returns (host, port, multicast_group_or_None).
    """
    print("\n  ── Live UDP Configuration ──────────────────────────────────")
    try:
        port_in = input(f"  UDP port [{default_port}]: ").strip()
        port = int(port_in) if port_in else default_port

        mc_hint = default_multicast or ''
        mc_in   = input(f"  Multicast group (empty = Unicast) [{mc_hint}]: ").strip()
        multicast = mc_in if mc_in else (default_multicast if default_multicast else None)

        host_in = input(f"  Bind address [{default_host}]: ").strip()
        host    = host_in if host_in else default_host
    except (EOFError, KeyboardInterrupt):
        host, port, multicast = default_host, default_port, \
            default_multicast if default_multicast else None
    print("  ────────────────────────────────────────────────────────────")
    return host, port, multicast


# ─────────────────────────────────────────────────────────────────────────────
# PPI Toolbar-Buttons
# ─────────────────────────────────────────────────────────────────────────────

def _ascope_hide(fig) -> None:
    """
    Versteckt das A-Scope-Fenster über ObjC orderOut: ohne plt.close().
    Verhindert macOS-Crash (SIGSEGV in objc_release) bei Aufruf aus Callback.
    Auf Nicht-macOS-Systemen: plt.close() als Fallback.
    """
    import sys
    if sys.platform != 'darwin':
        import matplotlib.pyplot as plt
        try:
            plt.close(fig)
        except Exception:
            pass
        return
    try:
        import ctypes
        _lib  = ctypes.CDLL('/usr/lib/libobjc.A.dylib')
        _send = _lib.objc_msgSend
        _cls  = _lib.objc_getClass
        _sel  = _lib.sel_registerName
        _sel.restype  = ctypes.c_void_p
        _sel.argtypes = [ctypes.c_char_p]
        _cls.restype  = ctypes.c_void_p
        _cls.argtypes = [ctypes.c_char_p]

        _send.restype  = ctypes.c_void_p
        _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        app     = _send(_cls(b'NSApplication'), _sel(b'sharedApplication'))
        windows = _send(app, _sel(b'windows'))

        _send.restype  = ctypes.c_ulong
        count = _send(windows, _sel(b'count'))

        target = 'A-Scope  |  CAT240'
        for i in range(int(count)):
            _send.restype  = ctypes.c_void_p
            _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
            win = _send(windows, _sel(b'objectAtIndex:'), ctypes.c_ulong(i))

            _send.restype  = ctypes.c_void_p
            _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            title_obj  = _send(win, _sel(b'title'))
            _send.restype  = ctypes.c_char_p
            title_utf8 = _send(title_obj, _sel(b'UTF8String'))

            if title_utf8 and title_utf8.decode('utf-8', 'replace') == target:
                _send.restype  = ctypes.c_void_p
                _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
                _send(win, _sel(b'orderOut:'), None)
                return
    except Exception:
        pass  # Kein Crash; Fenster bleibt sichtbar – besser als Absturz


def _ascope_show(fig) -> None:
    """Zeigt ein via _ascope_hide verstecktes A-Scope-Fenster wieder an."""
    try:
        fig.canvas.manager.show()
        fig.canvas.draw()
    except Exception:
        pass


def _hide_ppi_toolbar_deferred(fig, win_title: str) -> None:
    """Versteckt die matplotlib-Toolbar beim ersten Draw-Event (Fenster ist dann bereit)."""
    fired = [False]
    def _on_draw(_event):
        if not fired[0]:
            fired[0] = True
            _hide_ppi_toolbar(win_title)
    fig.canvas.mpl_connect('draw_event', _on_draw)


def _hide_ppi_toolbar(win_title: str) -> None:
    """
    Versteckt die matplotlib-Navigationsleiste (NavigationToolbar2Mac) im PPI-Fenster
    via ObjC setHidden:. Das Toolbar-Objekt bleibt erhalten – Zoom/Home funktionieren
    weiterhin über die eigenen Buttons.
    """
    import sys
    if sys.platform != 'darwin':
        return
    try:
        import ctypes
        _lib  = ctypes.CDLL('/usr/lib/libobjc.A.dylib')
        _send = _lib.objc_msgSend
        _cls  = _lib.objc_getClass
        _sel  = _lib.sel_registerName
        _sel.restype  = ctypes.c_void_p
        _sel.argtypes = [ctypes.c_char_p]
        _cls.restype  = ctypes.c_void_p
        _cls.argtypes = [ctypes.c_char_p]

        _send.restype  = ctypes.c_void_p
        _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        app     = _send(_cls(b'NSApplication'), _sel(b'sharedApplication'))
        windows = _send(app, _sel(b'windows'))

        _send.restype  = ctypes.c_ulong
        count = _send(windows, _sel(b'count'))

        for i in range(int(count)):
            _send.restype  = ctypes.c_void_p
            _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
            win = _send(windows, _sel(b'objectAtIndex:'), ctypes.c_ulong(i))

            _send.restype  = ctypes.c_void_p
            _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            title_obj  = _send(win, _sel(b'title'))
            _send.restype  = ctypes.c_char_p
            title_utf8 = _send(title_obj, _sel(b'UTF8String'))

            if not (title_utf8 and title_utf8.decode('utf-8', 'replace') == win_title):
                continue

            # contentView → subviews → NavigationToolbar2Mac → setHidden:
            _send.restype  = ctypes.c_void_p
            _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            content  = _send(win, _sel(b'contentView'))
            subviews = _send(content, _sel(b'subviews'))

            _send.restype  = ctypes.c_ulong
            sv_count = _send(subviews, _sel(b'count'))

            for j in range(int(sv_count)):
                _send.restype  = ctypes.c_void_p
                _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
                sv = _send(subviews, _sel(b'objectAtIndex:'), ctypes.c_ulong(j))

                _send.restype  = ctypes.c_void_p
                _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                cn_nsstr = _send(sv, _sel(b'className'))
                _send.restype  = ctypes.c_char_p
                cn = _send(cn_nsstr, _sel(b'UTF8String'))

                if cn and b'Toolbar' in cn:
                    _send.restype  = None
                    _send.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool]
                    _send(sv, _sel(b'setHidden:'), ctypes.c_bool(True))
            return
    except Exception:
        pass


def _setup_ppi_buttons(fig_ppi, ax_ppi, ppi, ascope_ref: list,
                       toggle_ascope_fn,
                       playback_state: dict,
                       toggle_pause_fn=None):
    """
    Fügt Steuer-Buttons am unteren Rand des PPI-Fensters ein.

    ax_ppi           : Axes-Objekt des PPI (für Home-Reset)
    ascope_ref       : [AScope]  – mutable Referenz; wird durch toggle_ascope_fn ersetzt
    playback_state   : {'paused': False}
    toggle_pause_fn  : callable(paused: bool) oder None → Pause-Button wird ausgeblendet
    """
    from matplotlib.widgets import Button
    from datetime import datetime

    _BG  = '#111111'
    _FG  = '#00ff41'
    _HOV = '#1a2a1a'
    _ACT = '#0a3a0a'

    BTN_Y = 0.01
    BTN_H = 0.045
    fig_ppi.subplots_adjust(left=0.01, right=0.99, top=0.97, bottom=0.065)

    def _btn(rect, label):
        ax_b = fig_ppi.add_axes(rect)
        b = Button(ax_b, label, color=_BG, hovercolor=_HOV)
        b.label.set_color(_FG)
        b.label.set_fontsize(9)
        b.label.set_fontfamily('monospace')
        return b

    btn_pause  = _btn([0.01, BTN_Y, 0.08, BTN_H], 'Pause')
    btn_zoom   = _btn([0.10, BTN_Y, 0.07, BTN_H], 'Zoom')
    btn_ascope = _btn([0.18, BTN_Y, 0.12, BTN_H], '[ ] A-Scope')
    btn_mode   = _btn([0.31, BTN_Y, 0.09, BTN_H], 'Rng')

    # Mode-Button initial dimmen (kein A-Scope offen)
    _DIM_FG = '#336633'
    btn_mode.label.set_color(_DIM_FG)

    def _mode_label(mode: str) -> str:
        return 'Rng' if mode == 'range' else 'Az'

    def on_mode(_):
        asc = ascope_ref[0]
        if asc is None:
            return
        new_mode = 'azimuth' if asc.mode == 'range' else 'range'
        asc.set_mode(new_mode)
        btn_mode.label.set_text(_mode_label(new_mode))
        fig_ppi.canvas.draw_idle()
    btn_mode.on_clicked(on_mode)

    def sync_mode_btn(mode: str):
        btn_mode.label.set_text(_mode_label(mode))
        fig_ppi.canvas.draw_idle()

    # ── Zoom-State ────────────────────────────────────────────────────────────
    zoom_active = [False]
    _zs   = [None]   # Startpunkt (x, y) in Daten-Koordinaten
    _zlast = [None]  # zuletzt bekannte Daten-Koordinaten (auch ausserhalb der Axes)
    _zr   = [None]   # aktives Rectangle-Patch

    try:
        from matplotlib.backend_bases import cursors as _cursors
        _CUR_CROSS  = _cursors.SELECT_REGION
        _CUR_NORMAL = _cursors.POINTER
    except Exception:
        _CUR_CROSS = _CUR_NORMAL = None

    def _zoom_deactivate():
        zoom_active[0] = False
        _zs[0] = None
        _zlast[0] = None
        if _zr[0] is not None:
            try: _zr[0].remove()
            except Exception: pass
            _zr[0] = None
        btn_zoom.ax.set_facecolor(_BG)
        if _CUR_NORMAL is not None:
            try: fig_ppi.canvas.set_cursor(_CUR_NORMAL)
            except Exception: pass

    def _display_to_data(ex, ey):
        """Konvertiert Display-Pixel nach Daten-Koordinaten (klappt auch ausserhalb ax_ppi)."""
        try:
            return ax_ppi.transData.inverted().transform((ex, ey))
        except Exception:
            return None, None

    # ── Zoom (Rechteck-Zoom, toolbar-unabhängig) ──────────────────────────────
    def _zoom_press(event):
        if not zoom_active[0]: return
        if event.button != 1: return
        if getattr(event, 'dblclick', False): return
        # Nur starten wenn Klick innerhalb ax_ppi
        if event.inaxes is not ax_ppi: return
        x, y = _display_to_data(event.x, event.y)
        if x is None: return
        _zs[0] = (x, y)
        _zlast[0] = (x, y)

    def _zoom_motion(event):
        if not zoom_active[0] or _zs[0] is None: return
        # Position immer via Display-Koordinaten → klappt auch ausserhalb ax_ppi
        x, y = _display_to_data(event.x, event.y)
        if x is None: return
        _zlast[0] = (x, y)
        from matplotlib.patches import Rectangle as _Rect
        x0, y0 = _zs[0]
        if _zr[0] is not None:
            try: _zr[0].remove()
            except Exception: pass
        p = _Rect((min(x0, x), min(y0, y)), abs(x - x0), abs(y - y0),
                  linewidth=1, edgecolor='white', facecolor=(1, 1, 1, 0.06),
                  linestyle='--', zorder=10)
        ax_ppi.add_patch(p)
        _zr[0] = p
        fig_ppi.canvas.draw_idle()

    def _zoom_release(event):
        if not zoom_active[0] or _zs[0] is None: return
        if event.button != 1: return
        if _zr[0] is not None:
            try: _zr[0].remove()
            except Exception: pass
            _zr[0] = None
        x0, y0 = _zs[0]
        _zs[0] = None
        # Endpunkt: aktuelle Position oder letzte bekannte
        x1, y1 = _display_to_data(event.x, event.y)
        if x1 is None and _zlast[0] is not None:
            x1, y1 = _zlast[0]
        _zlast[0] = None
        if x1 is None or (abs(x1 - x0) < 1 and abs(y1 - y0) < 1):
            fig_ppi.canvas.draw_idle()
            return
        ax_ppi.set_xlim(min(x0, x1), max(x0, x1))
        ax_ppi.set_ylim(min(y0, y1), max(y0, y1))
        _zoom_deactivate()
        fig_ppi.canvas.draw_idle()

    fig_ppi.canvas.mpl_connect('button_press_event',   _zoom_press)
    fig_ppi.canvas.mpl_connect('motion_notify_event',  _zoom_motion)
    fig_ppi.canvas.mpl_connect('button_release_event', _zoom_release)

    def on_zoom(_):
        if zoom_active[0]:
            _zoom_deactivate()
        else:
            zoom_active[0] = True
            btn_zoom.ax.set_facecolor(_ACT)
            if _CUR_CROSS is not None:
                try: fig_ppi.canvas.set_cursor(_CUR_CROSS)
                except Exception: pass
        fig_ppi.canvas.draw_idle()
    btn_zoom.on_clicked(on_zoom)

    # ── Pause / Play ──────────────────────────────────────────────────────────
    if toggle_pause_fn is None:
        btn_pause.ax.set_visible(False)
    else:
        def on_pause(_):
            playback_state['paused'] = not playback_state['paused']
            paused = playback_state['paused']
            btn_pause.label.set_text('Play' if paused else 'Pause')
            btn_pause.ax.set_facecolor(_ACT if paused else _BG)
            toggle_pause_fn(paused)
            fig_ppi.canvas.draw_idle()
        btn_pause.on_clicked(on_pause)

    # ── A-Scope toggle ────────────────────────────────────────────────────────
    ascope_on = [False]
    def on_ascope(_):
        toggle_ascope_fn()
        is_open = ascope_ref[0] is not None
        ascope_on[0] = is_open
        btn_ascope.label.set_text('[A] A-Scope' if is_open else '[ ] A-Scope')
        if is_open and ascope_ref[0] is not None:
            btn_mode.label.set_color(_FG)
            btn_mode.label.set_text(_mode_label(ascope_ref[0].mode))
        else:
            btn_mode.label.set_color(_DIM_FG)
        fig_ppi.canvas.draw_idle()
    btn_ascope.on_clicked(on_ascope)

    def sync_ascope_btn(is_open: bool):
        """Synchronisiert den A-Scope-Button-State (z.B. bei X-Schliessen)."""
        ascope_on[0] = is_open
        btn_ascope.label.set_text('[A] A-Scope' if is_open else '[ ] A-Scope')
        if not is_open:
            btn_mode.label.set_color(_DIM_FG)
        fig_ppi.canvas.draw_idle()

    return {'sync_ascope': sync_ascope_btn, 'sync_mode': sync_mode_btn,
            'zoom_active': zoom_active}


def _attach_ppi_scroll_zoom(fig_ppi, ax_ppi, ppi):
    """
    Scroll-Zoom (Mausrad) zentriert auf Cursor-Position.
    Doppelklick setzt den Zoom auf den vollen Bereich zurück.
    """
    def on_scroll(event):
        if event.inaxes is not ax_ppi or event.xdata is None:
            return
        factor = 0.65 if event.step > 0 else 1.0 / 0.65
        xlo, xhi = ax_ppi.get_xlim()
        ylo, yhi = ax_ppi.get_ylim()
        x0, y0   = event.xdata, event.ydata
        ax_ppi.set_xlim(x0 + (xlo - x0) * factor, x0 + (xhi - x0) * factor)
        ax_ppi.set_ylim(y0 + (ylo - y0) * factor, y0 + (yhi - y0) * factor)
        fig_ppi.canvas.draw_idle()

    def on_dblclick(event):
        if event.inaxes is ax_ppi and getattr(event, 'dblclick', False):
            r = ppi.max_range_cells * 1.1
            ax_ppi.set_xlim(-r, r)
            ax_ppi.set_ylim(-r, r)
            fig_ppi.canvas.draw_idle()

    fig_ppi.canvas.mpl_connect('scroll_event',        on_scroll)
    fig_ppi.canvas.mpl_connect('button_press_event',  on_dblclick)


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis function
# ─────────────────────────────────────────────────────────────────────────────

def _toggle_ascope_mode(fig_ppi, ascope: 'AScope'):
    """Right-click in PPI: toggles A-Scope mode (range ↔ azimuth)."""
    new_mode = 'azimuth' if ascope.mode == 'range' else 'range'
    ascope.set_mode(new_mode)


def _setup_ppi_overlay(ascope: 'AScope', az_line, range_ring, ppi_tick, ppi_obj, fig_ppi,
                       on_mode_extra=None):
    """
    Registers mode and cursor callbacks for PPI overlays:
    - az_line:    Azimuth line (range mode)
    - range_ring: Range ring (azimuth mode)
    - ppi_tick:   Small crosshair at the A-Scope cursor position in the PPI
    - on_mode_extra: optional fn(mode) called after mode change (e.g. to sync PPI button)
    """
    tick_len = ppi_obj.max_range_cells * 0.03   # crosshair length in PPI units

    def on_mode_change(mode):
        # Hide only the inactive element; the active one becomes visible on first click
        if mode == 'range':
            range_ring.set_visible(False)
        else:
            az_line.set_visible(False)
        ppi_tick.set_data([], [])
        if on_mode_extra:
            on_mode_extra(mode)
        fig_ppi.canvas.draw_idle()

    def on_cursor_change(cursor_x):
        if cursor_x is None:
            ppi_tick.set_data([], [])
        elif ascope.mode == 'range':
            # cursor_x = range cell; crosshair perpendicular to azimuth line
            r  = float(cursor_x)
            az = np.deg2rad(ascope.azimuth)
            sx, sy = np.sin(az), np.cos(az)     # azimuth direction
            px, py = np.cos(az), -np.sin(az)    # perpendicular to it
            ppi_tick.set_data(
                [r*sx - tick_len*px, r*sx + tick_len*px],
                [r*sy - tick_len*py, r*sy + tick_len*py])
        else:
            # cursor_x = angle in degrees; crosshair radially on the ring
            az = np.deg2rad(float(cursor_x))
            rc = float(ascope.range_cell)
            sx, sy = np.sin(az), np.cos(az)
            ppi_tick.set_data(
                [(rc - tick_len)*sx, (rc + tick_len)*sx],
                [(rc - tick_len)*sy, (rc + tick_len)*sy])
        fig_ppi.canvas.draw_idle()

    ascope._mode_change_cb   = on_mode_change
    ascope._cursor_change_cb = on_cursor_change
    # Both overlays start invisible – appear only after first click


def _attach_ppi_readout(fig, ax, ppi):
    """Cursor readout (bearing + distance) as overlay in the top-left of the PPI axes."""
    COLOR = '#ffcc00'

    def _row(lbl: str, val: str) -> str:
        return f'{lbl:<6}{val:>9}'

    def _placeholder() -> str:
        return '\n'.join([_row('Az:', '--°'),
                          _row('Dist:', '-- NM'),
                          _row('',      '-- m')])

    txt = ax.text(
        0.01, 0.99, _placeholder(),
        transform=ax.transAxes, ha='left', va='top',
        color=COLOR, fontsize=9, fontfamily='monospace',
        bbox=dict(boxstyle='round,pad=0.3', facecolor='#1a1a00',
                  edgecolor=COLOR, alpha=0.85))

    def on_move(event):
        if event.inaxes is not ax or event.xdata is None:
            txt.set_text(_placeholder())
            fig.canvas.draw_idle()
            return
        az = np.degrees(np.arctan2(event.xdata, event.ydata)) % 360.0
        r  = np.sqrt(event.xdata**2 + event.ydata**2)
        if ppi.cell_size_m > 0:
            dist_m  = r * ppi.cell_size_m
            dist_nm = dist_m / 1852.0
            lines = [_row('Az:',   f'{az:.1f}°'),
                     _row('Dist:', f'{dist_nm:.2f} NM'),
                     _row('',      f'{dist_m:.0f} m')]
        else:
            lines = [_row('Az:',   f'{az:.1f}°'),
                     _row('Dist:', f'{r:.0f} cells')]
        txt.set_text('\n'.join(lines))
        fig.canvas.draw_idle()

    fig.canvas.mpl_connect('motion_notify_event', on_move)


def analyze_pcap(filepath: str, display: bool = True,
                 save_path: Optional[str] = None,
                 verbose: bool = True,
                 initial_azimuth: float = 0.0,
                 filter_stream: Optional[Tuple[str, int]] = None,
                 log_compress: bool = False) -> List[Cat240Message]:
    """
    Reads a PCAP file, decodes all CAT240 packets and
    optionally displays PPI + A-Scope.
    Click in PPI → A-Scope updates to that azimuth.
    filter_stream: (dst_ip, dst_port) or None → determined via scan + selection.
    """
    import matplotlib.pyplot as plt

    print(f"\n{'='*60}")
    print(f"  CAT240 Analyzer  |  {filepath}")
    print(f"{'='*60}")

    # ── Stream selection ──────────────────────────────────────────────────────
    if filter_stream is None:
        print("  Scanning streams ...")
        all_streams = scan_pcap_streams(filepath)
        filter_stream = _prompt_stream_selection(all_streams)

    sel_ip, sel_port = filter_stream
    mc = ' (Multicast)' if _is_multicast(sel_ip) else ''
    print(f"  Selected stream:     {sel_ip}:{sel_port}{mc}")
    print(f"{'='*60}")

    reader  = PcapReader(filepath)
    decoder = Cat240Decoder()
    ppi     = RadarPPI(max_range_cells=1024, az_bins=4096)

    messages = []
    pkt_count = 0
    cat240_count = 0
    errors = 0
    max_cells = 0

    for _ts, udp_payload, dst_ip, dst_port in reader.packets():
        pkt_count += 1
        if (dst_ip, dst_port) != filter_stream:
            continue
        try:
            decoded = decoder.decode_multiple(udp_payload)
            for msg in decoded:
                messages.append(msg)
                ppi.add_message(msg)
                cat240_count += 1
                max_cells = max(max_cells, len(msg.video_data))
                if verbose and cat240_count % 500 == 0:
                    print(f"  {cat240_count:6d} CAT240 messages decoded ...", end='\r')
        except Exception:
            errors += 1

    compressed_count = sum(1 for m in messages if m.compression)
    print(f"\n  Total packets:       {pkt_count}")
    print(f"  CAT240 messages:     {cat240_count}")
    print(f"  Errors:              {errors}")
    print(f"  Max. cells/azimuth:    {max_cells}")
    if compressed_count:
        print(f"  *** WARNING: {compressed_count} messages have log compression flag set ***")
        print(f"  *** Amplitude values are logarithmically encoded, not linear!        ***")
    else:
        print(f"  Compression:         none (linear amplitude)")

    if messages:
        az_values = [m.start_azimuth_deg for m in messages]
        print(f"  Azimuth range:       {min(az_values):.1f}° – {max(az_values):.1f}°")
        print(f"{'='*60}\n")

    if display or save_path:
        # ── PPI window ────────────────────────────────────────────────────────
        plt.rcParams['toolbar'] = 'None'
        fig_ppi, ax_ppi = plt.subplots(figsize=(10, 10), facecolor='#0a0a0a',
                                        num='PPI  |  CAT240')
        fig_ppi.canvas.manager.set_window_title('PPI  |  CAT240')
        ppi.render(ax_ppi, title=f"CAT240 PPI  –  {filepath}")
        _attach_ppi_readout(fig_ppi, ax_ppi, ppi)

        # Azimuth line and range ring in PPI
        az_rad0 = np.deg2rad(initial_azimuth)
        az_line, = ax_ppi.plot(
            [0, ppi.max_range_cells * np.sin(az_rad0)],
            [0, ppi.max_range_cells * np.cos(az_rad0)],
            color='#ffcc00', linewidth=1.2, linestyle='-', visible=False)
        range_ring, = ax_ppi.plot([], [], color='#00aaff', linewidth=1.5,
                                   linestyle='-', visible=False)
        ppi_tick, = ax_ppi.plot([], [], color='#ff4444', linewidth=2.0, solid_capstyle='round')

        if save_path:
            fig_ppi.savefig(save_path, dpi=150, bbox_inches='tight',
                            facecolor=fig_ppi.get_facecolor())
            print(f"  PPI saved: {save_path}")

        if display:
            ascope_ref      = [None]
            ascope_instance = [None]

            def _toggle_ascope_static():
                if ascope_ref[0] is not None:
                    old_asc = ascope_ref[0]
                    ascope_ref[0] = None
                    az_line.set_visible(False)
                    range_ring.set_visible(False)
                    ppi_tick.set_data([], [])
                    fig_ppi.canvas.draw_idle()
                    old_asc.clear()
                    _ascope_hide(old_asc.fig)
                else:
                    if ascope_instance[0] is None:
                        a = AScope(ppi, initial_azimuth=initial_azimuth, log_compress=log_compress)
                        ascope_instance[0] = a
                        def _on_x_close(_evt):
                            ascope_ref[0] = None
                            ascope_instance[0] = None
                            az_line.set_visible(False)
                            range_ring.set_visible(False)
                            ppi_tick.set_data([], [])
                            t = fig_ppi.canvas.new_timer(interval=50)
                            def _sync():
                                ppi_btns['sync_ascope'](False)
                                t.stop()
                            t.add_callback(_sync)
                            t.start()
                        a.fig.canvas.mpl_connect('close_event', _on_x_close)
                    ascope_ref[0] = ascope_instance[0]
                    _setup_ppi_overlay(ascope_ref[0], az_line, range_ring, ppi_tick, ppi, fig_ppi,
                                       on_mode_extra=ppi_btns.get('sync_mode'))
                    ascope_ref[0].render()
                    _ascope_show(ascope_ref[0].fig)

            playback_state = {'paused': False}
            ppi_btns = _setup_ppi_buttons(fig_ppi, ax_ppi, ppi, ascope_ref, _toggle_ascope_static,
                                          playback_state, toggle_pause_fn=None)

            _attach_ppi_scroll_zoom(fig_ppi, ax_ppi, ppi)

            # ── PPI click → A-Scope ──────────────────────────────────────────
            def on_ppi_click(event):
                if ppi_btns['zoom_active'][0]:
                    return
                if getattr(event, 'dblclick', False):
                    return
                if event.inaxes != ax_ppi or event.xdata is None:
                    return
                asc = ascope_ref[0]
                if asc is None:
                    return
                if event.button == 3:
                    _toggle_ascope_mode(fig_ppi, asc)
                    return
                if event.button != 1:
                    return
                new_az = asc.handle_ppi_click(event.xdata, event.ydata)
                if new_az is not None:
                    az_rad = np.deg2rad(new_az)
                    az_line.set_data(
                        [0, ppi.max_range_cells * np.sin(az_rad)],
                        [0, ppi.max_range_cells * np.cos(az_rad)])
                    az_line.set_visible(True)
                else:
                    _t = np.linspace(0, 2*np.pi, 361)
                    _rc = float(asc.range_cell)
                    range_ring.set_data(_rc*np.sin(_t), _rc*np.cos(_t))
                    range_ring.set_visible(True)
                fig_ppi.canvas.draw_idle()

            fig_ppi.canvas.mpl_connect('button_press_event', on_ppi_click)

            print("  ┌─────────────────────────────────────────────┐")
            print("  │  PPI window:  Click → update A-Scope        │")
            print("  │  A-Scope:     Mouse → measurement line + values │")
            print("  └─────────────────────────────────────────────┘\n")

            plt.show()

    return messages


# ─────────────────────────────────────────────────────────────────────────────
# Replay mode (PCAP time-controlled)
# ─────────────────────────────────────────────────────────────────────────────

def replay_pcap(filepath: str, speed: float = 1.0,
                initial_azimuth: float = 0.0,
                filter_stream: Optional[Tuple[str, int]] = None,
                log_compress: bool = False,
                loop: bool = False):
    """
    Plays back a PCAP file in a time-controlled manner.
    A background thread reads packets with original timing (× speed),
    the main thread renders PPI + A-Scope via FuncAnimation.
    filter_stream: (dst_ip, dst_port) or None → determined via scan + selection.
    """
    import queue
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation

    print(f"\n{'='*60}")
    print(f"  CAT240 Replay  |  {filepath}  (×{speed})")
    print(f"{'='*60}")

    # ── Stream selection ──────────────────────────────────────────────────────
    if filter_stream is None:
        print("  Scanning streams ...")
        all_streams = scan_pcap_streams(filepath)
        filter_stream = _prompt_stream_selection(all_streams)

    sel_ip, sel_port = filter_stream
    mc = ' (Multicast)' if _is_multicast(sel_ip) else ''
    print(f"  Selected stream:     {sel_ip}:{sel_port}{mc}")
    print(f"{'='*60}\n")

    decoder       = Cat240Decoder()
    ppi           = RadarPPI(max_range_cells=1024, az_bins=4096)
    msg_queue     = queue.Queue(maxsize=50000)
    state         = {'done': False, 'msgs': 0, 'loop': 0}
    playback_state = {'paused': False}
    pause_event   = threading.Event()
    pause_event.set()   # gesetzt = läuft; gelöscht = pausiert

    def reader_thread():
        while True:
            try:
                reader  = PcapReader(filepath)
                t0_pcap = None
                t0_real = time.time()
                for ts, udp, dst_ip, dst_port in reader.packets():
                    if (dst_ip, dst_port) != filter_stream:
                        continue
                    pause_event.wait()   # blockiert wenn pausiert
                    if t0_pcap is None:
                        t0_pcap = ts
                        t0_real = time.time()   # Zeitreferenz nach Pause neu setzen
                    # Original pause between packets scaled by speed
                    elapsed_pcap = ts - t0_pcap
                    elapsed_real = time.time() - t0_real
                    wait = elapsed_pcap / speed - elapsed_real
                    if wait > 0.001:
                        time.sleep(wait)
                    for msg in decoder.decode_multiple(udp):
                        msg_queue.put(msg)
            except Exception as e:
                print(f"\n  [Replay] Reader thread error: {e}")
                break
            print(f"\n  [Replay] Loop {state['loop'] + 1} complete. {state['msgs']} azimuths.")
            if not loop:
                break
            # Naechsten Durchlauf vorbereiten: Queue leeren lassen, dann PPI leeren
            while not msg_queue.empty():
                time.sleep(0.1)
            ppi.clear()
            state['msgs'] = 0
            state['loop'] += 1
        state['done'] = True

    threading.Thread(target=reader_thread, daemon=True).start()

    # PPI window
    plt.rcParams['toolbar'] = 'None'
    fig_ppi, ax_ppi = plt.subplots(figsize=(10, 10), facecolor='#0a0a0a',
                                    num='PPI  |  CAT240 Replay')
    fig_ppi.canvas.manager.set_window_title('PPI  |  CAT240 Replay')
    # Initial render – creates mesh and calls ax.clear() ONCE.
    # All overlays must be added to the axis AFTERWARDS.
    ppi.render(ax_ppi, title=f"CAT240 Replay  |  {speed}x")
    _attach_ppi_readout(fig_ppi, ax_ppi, ppi)

    ascope_ref      = [None]
    ascope_instance = [None]

    # Selection line (click) + range ring + cursor crosshair
    az_rad0 = np.deg2rad(initial_azimuth)
    az_sel_line, = ax_ppi.plot(
        [0, ppi.max_range_cells * np.sin(az_rad0)],
        [0, ppi.max_range_cells * np.cos(az_rad0)],
        color='#ffcc00', linewidth=1.2, linestyle='-', visible=False)
    range_ring, = ax_ppi.plot([], [], color='#00aaff', linewidth=1.5,
                               linestyle='-', visible=False)
    ppi_tick, = ax_ppi.plot([], [], color='#ff4444', linewidth=2.0, solid_capstyle='round')

    def _hide_ppi_overlays_replay():
        az_sel_line.set_visible(False)
        range_ring.set_visible(False)
        ppi_tick.set_data([], [])

    def _toggle_ascope_replay():
        if ascope_ref[0] is not None:
            old_asc = ascope_ref[0]
            ascope_ref[0] = None
            _hide_ppi_overlays_replay()
            old_asc.clear()
            _ascope_hide(old_asc.fig)
        else:
            if ascope_instance[0] is None:
                a = AScope(ppi, initial_azimuth=initial_azimuth, log_compress=log_compress)
                ascope_instance[0] = a
                def _on_x_close(_evt):
                    ascope_ref[0] = None
                    ascope_instance[0] = None
                    _hide_ppi_overlays_replay()
                    t = fig_ppi.canvas.new_timer(interval=50)
                    def _sync():
                        ppi_btns['sync_ascope'](False)
                        t.stop()
                    t.add_callback(_sync)
                    t.start()
                a.fig.canvas.mpl_connect('close_event', _on_x_close)
            ascope_ref[0] = ascope_instance[0]
            _setup_ppi_overlay(ascope_ref[0], az_sel_line, range_ring, ppi_tick, ppi, fig_ppi,
                               on_mode_extra=ppi_btns.get('sync_mode'))
            ascope_ref[0].render()
            _ascope_show(ascope_ref[0].fig)

    def _toggle_pause_replay(paused: bool):
        if paused:
            pause_event.clear()
        else:
            pause_event.set()

    ppi_btns = _setup_ppi_buttons(fig_ppi, ax_ppi, ppi, ascope_ref, _toggle_ascope_replay,
                                  playback_state, toggle_pause_fn=_toggle_pause_replay)
    _attach_ppi_scroll_zoom(fig_ppi, ax_ppi, ppi)

    def on_ppi_click(event):
        if ppi_btns['zoom_active'][0]:
            return
        if getattr(event, 'dblclick', False):
            return
        if event.inaxes != ax_ppi or event.xdata is None:
            return
        asc = ascope_ref[0]
        if asc is None:
            return
        if event.button == 3:
            _toggle_ascope_mode(fig_ppi, asc)
            return
        if event.button == 1:
            new_az = asc.handle_ppi_click(event.xdata, event.ydata)
            if new_az is not None:
                az_rad = np.deg2rad(new_az)
                az_sel_line.set_data(
                    [0, ppi.max_range_cells * np.sin(az_rad)],
                    [0, ppi.max_range_cells * np.cos(az_rad)])
                az_sel_line.set_visible(True)
            else:
                _t = np.linspace(0, 2*np.pi, 361)
                _rc = float(asc.range_cell)
                range_ring.set_data(_rc*np.sin(_t), _rc*np.cos(_t))
                range_ring.set_visible(True)
            fig_ppi.canvas.draw_idle()

    fig_ppi.canvas.mpl_connect('button_press_event', on_ppi_click)

    def update(_):
        if playback_state['paused']:
            return []
        try:
            while True:
                msg = msg_queue.get_nowait()
                ppi.add_message(msg)
                state['msgs'] += 1
        except Exception:
            pass

        if state['done']:
            status = " [DONE]"
        elif loop and state['loop'] > 0:
            status = f" [Loop {state['loop'] + 1}]"
        else:
            status = ""
        ppi.render(ax_ppi,
                   title=f"CAT240 Replay  |  {speed}x{status}")
        asc = ascope_ref[0]
        if asc is not None:
            asc.render()
        return []

    print(f"\n  Replay: {filepath}")
    print(f"  Speed: {speed}x")
    if speed < 10:
        print(f"  Tip: Use --speed 50 for 50× faster playback.")
    print(f"  Close window to quit.\n")

    ani = animation.FuncAnimation(fig_ppi, update,   # noqa: F841
                                  interval=200,
                                  cache_frame_data=False)
    plt.show()


# ─────────────────────────────────────────────────────────────────────────────
# Live stream mode (UDP)
# ─────────────────────────────────────────────────────────────────────────────

def live_stream(host: str = '0.0.0.0', port: int = 5000,
                multicast_group: Optional[str] = None,
                update_interval: float = 0.5,
                initial_azimuth: float = 0.0,
                log_compress: bool = False):
    """
    Receives CAT240 datagrams live via UDP and updates
    PPI + A-Scope in real-time.
    multicast_group: multicast group address (e.g. '239.1.1.1') or None for unicast.
    host: bind address (interface IP or '0.0.0.0').
    """
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation

    decoder = Cat240Decoder()
    ppi     = RadarPPI(max_range_cells=1024, az_bins=4096)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # For multicast: bind to 0.0.0.0 (or group address), then join the group
    bind_addr = '0.0.0.0' if multicast_group else host
    sock.bind((bind_addr, port))
    if multicast_group:
        mreq = struct.pack('4s4s',
                           socket.inet_aton(multicast_group),
                           socket.inet_aton(host if host != '0.0.0.0' else '0.0.0.0'))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(0.05)

    if multicast_group:
        mc_info = f"  Multicast group:     {multicast_group}\n  Bind interface:      {host}"
        print(f"\n  Live reception on UDP port {port}")
        print(mc_info)
    else:
        print(f"\n  Live reception on UDP {host}:{port}")
    print(f"  Close window to quit.\n")

    stats = {'pkts': 0, 'msgs': 0}

    def recv_loop():
        while True:
            try:
                data, _ = sock.recvfrom(65535)
                stats['pkts'] += 1
                for msg in decoder.decode_multiple(data):
                    ppi.add_message(msg)
                    stats['msgs'] += 1
            except socket.timeout:
                pass
            except Exception:
                pass

    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()

    # PPI window
    plt.rcParams['toolbar'] = 'None'
    fig_ppi, ax_ppi = plt.subplots(figsize=(10, 10), facecolor='#0a0a0a',
                                    num='PPI  |  CAT240 Live')
    fig_ppi.canvas.manager.set_window_title('PPI  |  CAT240 Live')

    # Initial render – ax.clear() is called only once here.
    # Add all overlays AFTERWARDS.
    ppi.render(ax_ppi, title=f"CAT240 Live PPI  |  Port {port}")

    ascope_ref      = [None]
    ascope_instance = [None]
    playback_state  = {'paused': False}

    # Azimuth line + range ring (after initial render!)
    az_rad0 = np.deg2rad(initial_azimuth)
    az_line, = ax_ppi.plot(
        [0, ppi.max_range_cells * np.sin(az_rad0)],
        [0, ppi.max_range_cells * np.cos(az_rad0)],
        color='#ffcc00', linewidth=1.2, linestyle='-', visible=False)
    range_ring, = ax_ppi.plot([], [], color='#00aaff', linewidth=1.5,
                               linestyle='-', visible=False)
    ppi_tick, = ax_ppi.plot([], [], color='#ff4444', linewidth=2.0, solid_capstyle='round')

    def _hide_ppi_overlays_live():
        az_line.set_visible(False)
        range_ring.set_visible(False)
        ppi_tick.set_data([], [])

    def _toggle_ascope_live():
        if ascope_ref[0] is not None:
            old_asc = ascope_ref[0]
            ascope_ref[0] = None
            _hide_ppi_overlays_live()
            old_asc.clear()
            _ascope_hide(old_asc.fig)
        else:
            if ascope_instance[0] is None:
                a = AScope(ppi, initial_azimuth=initial_azimuth, log_compress=log_compress)
                ascope_instance[0] = a
                def _on_x_close(_evt):
                    ascope_ref[0] = None
                    ascope_instance[0] = None
                    _hide_ppi_overlays_live()
                    t = fig_ppi.canvas.new_timer(interval=50)
                    def _sync():
                        ppi_btns['sync_ascope'](False)
                        t.stop()
                    t.add_callback(_sync)
                    t.start()
                a.fig.canvas.mpl_connect('close_event', _on_x_close)
            ascope_ref[0] = ascope_instance[0]
            _setup_ppi_overlay(ascope_ref[0], az_line, range_ring, ppi_tick, ppi, fig_ppi,
                               on_mode_extra=ppi_btns.get('sync_mode'))
            ascope_ref[0].render()
            _ascope_show(ascope_ref[0].fig)

    ppi_btns = _setup_ppi_buttons(fig_ppi, ax_ppi, ppi, ascope_ref, _toggle_ascope_live,
                                  playback_state, toggle_pause_fn=lambda p: None)
    _attach_ppi_scroll_zoom(fig_ppi, ax_ppi, ppi)

    def on_ppi_click(event):
        if ppi_btns['zoom_active'][0]:
            return
        if getattr(event, 'dblclick', False):
            return
        if event.inaxes != ax_ppi or event.xdata is None:
            return
        asc = ascope_ref[0]
        if asc is None:
            return
        if event.button == 3:
            _toggle_ascope_mode(fig_ppi, asc)
            return
        if event.button != 1:
            return
        new_az = asc.handle_ppi_click(event.xdata, event.ydata)
        if new_az is not None:
            az_rad = np.deg2rad(new_az)
            az_line.set_data(
                [0, ppi.max_range_cells * np.sin(az_rad)],
                [0, ppi.max_range_cells * np.cos(az_rad)])
            az_line.set_visible(True)
        else:
            _t = np.linspace(0, 2*np.pi, 361)
            _rc = float(asc.range_cell)
            range_ring.set_data(_rc*np.sin(_t), _rc*np.cos(_t))
            range_ring.set_visible(True)
        fig_ppi.canvas.draw_idle()

    fig_ppi.canvas.mpl_connect('button_press_event', on_ppi_click)
    _attach_ppi_readout(fig_ppi, ax_ppi, ppi)

    def update(_):
        if playback_state['paused']:
            return az_line,
        ppi.render(ax_ppi, title=f"CAT240 Live PPI  |  Port {port}")
        asc = ascope_ref[0]
        if asc is not None:
            asc.render()
        return az_line,

    ani = animation.FuncAnimation(fig_ppi, update,
                                  interval=int(update_interval * 1000),
                                  cache_frame_data=False)
    plt.show()


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CAT240 ASTERIX Radar Video Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file',   metavar='PCAP', help='Analyze a PCAP/PCAPNG file (static)')
    group.add_argument('--replay', metavar='PCAP', help='Play back a PCAP/PCAPNG file in a time-controlled manner')
    group.add_argument('--live',   action='store_true', help='Live UDP reception')

    parser.add_argument('--port',       type=int,   default=None,      help='UDP port (live, default: interactive)')
    parser.add_argument('--host',       type=str,   default='0.0.0.0', help='Bind address/interface (default: 0.0.0.0)')
    parser.add_argument('--multicast',  type=str,   default=None,      help='Multicast group (live, e.g. 239.1.1.1)')
    parser.add_argument('--stream',     type=str,   default=None,      help='Stream filter IP:PORT for --file/--replay')
    parser.add_argument('--azimuth',    type=float, default=0.0,       help='Start azimuth for A-Scope in degrees (default: 0)')
    parser.add_argument('--speed',      type=float, default=1.0,       help='Playback speed for --replay (default: 1.0)')
    parser.add_argument('--loop',       action='store_true',           help='Loop --replay continuously (clears PPI on each restart)')
    parser.add_argument('--no-display',   action='store_true',         help='Do not show PPI/A-Scope window')
    parser.add_argument('--save',         metavar='PNG',               help='Save PPI as PNG file')
    parser.add_argument('--log-compress', action='store_true',         help='Show log-compressed A-Scope overlay (0–255, P₀ auto-estimated)')
    parser.add_argument('--verbose',      action='store_true', default=True)

    args = parser.parse_args()

    try:
        import matplotlib
        import numpy
    except ImportError:
        print("Missing dependencies! Please install:")
        print("  pip install matplotlib numpy")
        sys.exit(1)

    # ── Stream filter (--file / --replay) ────────────────────────────────────
    filter_stream: Optional[Tuple[str, int]] = None
    if args.stream:
        try:
            ip, p = args.stream.rsplit(':', 1)
            filter_stream = (ip.strip(), int(p.strip()))
        except ValueError:
            print(f"  Error: --stream expects format IP:PORT, e.g. 239.1.1.1:4379")
            sys.exit(1)

    if args.live:
        # ── Live: prompt interactively if port/multicast not provided ─────────
        default_port = args.port if args.port is not None else 5000
        host, port, multicast = _prompt_live_config(
            default_host      = args.host,
            default_port      = default_port,
            default_multicast = args.multicast or '',
        )
        live_stream(host=host, port=port, multicast_group=multicast,
                    initial_azimuth=args.azimuth,
                    log_compress=args.log_compress)
    elif args.replay:
        replay_pcap(filepath=args.replay, speed=args.speed,
                    initial_azimuth=args.azimuth,
                    filter_stream=filter_stream,
                    log_compress=args.log_compress,
                    loop=args.loop)
    else:
        analyze_pcap(
            filepath         = args.file,
            display          = not args.no_display,
            save_path        = args.save,
            verbose          = args.verbose,
            initial_azimuth  = args.azimuth,
            filter_stream    = filter_stream,
            log_compress     = args.log_compress,
        )


if __name__ == '__main__':
    main()
