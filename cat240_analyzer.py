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
        header = f.read(20)  # remaining 20 bytes of the Global Header
        link_type = struct.unpack(endian + 'I', header[16:20])[0] if len(header) >= 20 else 1

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
        """Extracts UDP payload + destination IP + destination port from an Ethernet/IP packet."""
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
            ihl = (ip_hdr[0] & 0x0F) * 4
            protocol = ip_hdr[9]
            if protocol != 17:  # UDP only
                return None
            dst_ip = '.'.join(str(b) for b in ip_hdr[16:20])
            udp_start = ip_start + ihl
            udp_hdr = raw[udp_start:udp_start + 8]
            if len(udp_hdr) < 8:
                return None
            dst_port = struct.unpack('>H', udp_hdr[2:4])[0]
            udp_len = struct.unpack('>H', udp_hdr[4:6])[0]
            return raw[udp_start + 8: udp_start + udp_len], dst_ip, dst_port
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
            ax.set_facecolor('black')
            self._mesh = ax.pcolormesh(self._X, self._Y, grid_copy, cmap=colormap,
                                       norm=norm, shading='nearest', rasterized=True)
            self._mesh_ax = ax

            # Range rings
            for r_frac in [0.25, 0.5, 0.75, 1.0]:
                circle = plt.Circle((0, 0), self.max_range_cells * r_frac,
                                     color='#00ff41', fill=False, linewidth=0.5, alpha=0.4)
                ax.add_patch(circle)

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

        reset_info = f'  |  {self.range_resets}× Range-Reset' if self.range_resets > 0 else ''
        ax.set_title(f'{title}  |  {msg_count} azimuths{reset_info}', color='white', fontsize=10)
        return self._mesh

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

    GREEN  = '#00ff41'
    BG     = '#0a0a0a'
    GRID   = '#1a3a1a'
    CURSOR = '#ffcc00'
    WM     = '#ff44ff'   # width measurement colour

    def __init__(self, ppi: 'RadarPPI', initial_azimuth: float = 0.0):
        import matplotlib.pyplot as plt
        import matplotlib.gridspec as gridspec

        self.ppi             = ppi
        self.azimuth         = initial_azimuth
        self.range_cell      = 0
        self.mode            = 'range'   # 'range' | 'azimuth'
        self._cursor_x: Optional[float] = None
        self._mode_change_cb   = None    # fn(mode)     – PPI overlay mode change
        self._cursor_change_cb = None    # fn(x | None) – PPI overlay cursor position

        self.fig = plt.figure(figsize=(12, 4), facecolor=self.BG,
                              num='A-Scope  |  CAT240')
        self.fig.canvas.manager.set_window_title('A-Scope  |  CAT240')

        gs = gridspec.GridSpec(1, 1, figure=self.fig,
                               left=0.07, right=0.97, top=0.88, bottom=0.13)
        self.ax = self.fig.add_subplot(gs[0])
        self._style_axes()

        self._line,     = self.ax.plot([], [], color=self.GREEN,
                                       linewidth=1.2, alpha=0.95)
        self._fill      = None
        self._vline     = self.ax.axvline(x=0, color=self.CURSOR,
                                          linewidth=1.0, linestyle='--',
                                          visible=False)
        self._info_text = self.ax.text(
            0.99, 0.97, '', transform=self.ax.transAxes,
            color=self.CURSOR, fontsize=8, va='top', ha='right',
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
        self._wm_text    = self.ax.text(
            0.01, 0.97, '', transform=self.ax.transAxes,
            color=self.WM, fontsize=9, va='top', ha='left',
            fontfamily='monospace',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#1a001a',
                      edgecolor=self.WM, linewidth=1.2, alpha=0.0))

        self._mode_confirmed = True   # False until user clicks in PPI after a mode change
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
        ax.grid(True, color=self.GRID, linewidth=0.5, linestyle=':')
        self._update_xlabel()

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
                detail = f'Range Cell {rc}  ({dist_m:,.0f} m / {dist_m/1852:.1f} nm)'
            else:
                detail = f'Range Cell {rc}'
        mode_lbl = 'Amp vs. Range' if self.mode == 'range' else 'Amp vs. Angle'
        zoom_hint = '  |  Scroll: zoom  |  Dbl-click: reset' if self._zoom_xlim is not None else '  |  Scroll: zoom'
        self.fig.suptitle(
            f'A-Scope  [{mode_lbl}]  |  {detail}  |  L-click: FWHM  |  R-click: span selection{zoom_hint}',
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
            self._update_title()
            self.fig.canvas.draw_idle()
            return
        cells, _ = self.ppi.get_spoke(self.azimuth)
        n = len(cells)
        if n == 0:
            return
        x = np.arange(n)
        self._line.set_data(x, cells)
        if self._fill is not None:
            self._fill.remove()
        self._fill = self.ax.fill_between(x, 0, cells, color=self.GREEN, alpha=0.18)
        vmax = cells.max() if cells.max() > 0 else 1.0
        self.ax.set_xlim(0, n)
        self.ax.set_ylim(0, vmax * 1.12)
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
        if self._fill is not None:
            self._fill.remove()
        self._fill = self.ax.fill_between(x, 0, ring, color=self.GREEN, alpha=0.18)
        vmax = ring.max() if ring.max() > 0 else 1.0
        self.ax.set_xlim(0, 360)
        self.ax.set_ylim(0, vmax * 1.12)
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

    # ── Zoom ──────────────────────────────────────────────────────────────────

    def _on_scroll(self, event):
        """Scrollrad-Zoom auf der X-Achse, zentriert auf Cursor-Position."""
        if event.inaxes != self.ax or event.xdata is None:
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
                self.ax.set_ylim(0, vmax * 1.15)

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

        if event.inaxes != self.ax or event.xdata is None:
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
        self._info_text.set_text('')
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
        if event.inaxes != self.ax or event.xdata is None:
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
        if event.inaxes != self.ax or event.xdata is None:
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

        # Build label (multi-line for readability)
        if self.mode == 'range':
            if self.ppi.cell_size_m > 0:
                w_m  = width * self.ppi.cell_size_m
                w_nm = w_m / 1852.0
                label = (f'── FWHM ──────────────────\n'
                         f'  {width:.1f} cells\n'
                         f'  {w_m:>10,.0f} m\n'
                         f'  {w_nm:>10.3f} nm\n'
                         f'  peak={peak_amp:.0f}  @-6dB={threshold:.0f}')
            else:
                label = (f'── FWHM ──────────────────\n'
                         f'  {width:.1f} cells\n'
                         f'  peak={peak_amp:.0f}  @-6dB={threshold:.0f}')
        else:
            az_count = round(width / 360.0 * self.ppi.az_bins)
            if self.ppi.cell_size_m > 0:
                range_m  = self.range_cell * self.ppi.cell_size_m
                arc_m    = 2 * np.pi * range_m * (width / 360.0)
                arc_nm   = arc_m / 1852.0
                label = (f'── FWHM ──────────────────\n'
                         f'  {width:.3f}°\n'
                         f'  {az_count} azimuths\n'
                         f'  arc  {arc_m:>8,.0f} m\n'
                         f'       {arc_nm:>8.3f} nm\n'
                         f'  peak={peak_amp:.0f}  @-6dB={threshold:.0f}')
            else:
                label = (f'── FWHM ──────────────────\n'
                         f'  {width:.3f}°\n'
                         f'  {az_count} azimuths\n'
                         f'  peak={peak_amp:.0f}  @-6dB={threshold:.0f}')

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
        # Box in die dem Peak gegenüberliegende Ecke stellen
        xlo, xhi = self.ax.get_xlim()
        peak_axes_x = (float(x_arr[peak_idx]) - xlo) / (xhi - xlo) if xhi > xlo else 0.5
        if peak_axes_x < 0.5:
            self._wm_text.set_position((0.99, 0.97))
            self._wm_text.set_ha('right')
        else:
            self._wm_text.set_position((0.01, 0.97))
            self._wm_text.set_ha('left')
        self._wm_text.set_text(label)
        self._wm_text.get_bbox_patch().set_alpha(0.85)

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
        self._wm_text.set_text('')
        self._wm_text.get_bbox_patch().set_alpha(0.0)

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
        n = len(data)
        if self.mode == 'range':
            idx = int(round(x))
            label = f'Cell  : {idx}'
        else:
            # x is angle in degrees → compute index
            idx = int(round(x / 360.0 * n)) % n
            label = f'Az    : {x:.1f}°'

        if 0 <= idx < n:
            amp  = data[idx]
            vmax = data.max() if data.max() > 0 else 1.0
            self._vline.set_xdata([x, x])
            self._vline.set_visible(True)
            self._info_text.set_text(
                f'{label}\n'
                f'Amp   : {amp:.1f}\n'
                f'Rel   : {amp / vmax * 100.0:.1f}%'
            )
        else:
            self._vline.set_visible(False)
            self._info_text.set_text('')

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
    Fast scan of a PCAP/PCAPNG file without ASTERIX decoding.
    Returns {(dst_ip, dst_port): packet_count} sorted descending.
    """
    reader  = PcapReader(filepath)
    streams: dict = {}
    for _ts, _udp, dst_ip, dst_port in reader.packets():
        key = (dst_ip, dst_port)
        streams[key] = streams.get(key, 0) + 1
    return dict(sorted(streams.items(), key=lambda x: -x[1]))


def _prompt_stream_selection(streams: dict):
    """
    Shows detected UDP streams and prompts for selection via terminal.
    Returns (dst_ip, dst_port) or None if streams dict is empty.
    """
    if not streams:
        return None
    keys = list(streams.keys())
    if len(keys) == 1:
        ip, port = keys[0]
        mc = ' (Multicast)' if _is_multicast(ip) else ''
        print(f"\n  Single stream: {ip}:{port}{mc}  –  {streams[keys[0]]} packets")
        return keys[0]

    print(f"\n  Available UDP streams:")
    for i, (ip, port) in enumerate(keys, 1):
        mc = ' (Multicast)' if _is_multicast(ip) else ''
        print(f"    [{i}]  {ip}:{port}{mc}  –  {streams[(ip, port)]} packets")

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
# Main analysis function
# ─────────────────────────────────────────────────────────────────────────────

def _toggle_ascope_mode(fig_ppi, ascope: 'AScope'):
    """Right-click in PPI: toggles A-Scope mode (range ↔ azimuth)."""
    new_mode = 'azimuth' if ascope.mode == 'range' else 'range'
    ascope.set_mode(new_mode)


def _setup_ppi_overlay(ascope: 'AScope', az_line, range_ring, ppi_tick, ppi_obj, fig_ppi):
    """
    Registers mode and cursor callbacks for PPI overlays:
    - az_line:    Azimuth line (range mode)
    - range_ring: Range ring (azimuth mode)
    - ppi_tick:   Small crosshair at the A-Scope cursor position in the PPI
    """
    tick_len = ppi_obj.max_range_cells * 0.03   # crosshair length in PPI units

    def on_mode_change(mode):
        # Hide only the inactive element; the active one becomes visible on first click
        if mode == 'range':
            range_ring.set_visible(False)
        else:
            az_line.set_visible(False)
        ppi_tick.set_data([], [])
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
    """Adds cursor readout (angle + distance) below the PPI."""
    txt = fig.text(0.5, 0.005, 'Bearing: —   Dist: —',
                   ha='center', va='bottom', color='#00ff41',
                   fontsize=10, fontfamily='monospace',
                   transform=fig.transFigure)

    def on_move(event):
        if event.inaxes is not ax or event.xdata is None:
            txt.set_text('Bearing: —   Dist: —')
            fig.canvas.draw_idle()
            return
        az = np.degrees(np.arctan2(event.xdata, event.ydata)) % 360.0
        r  = np.sqrt(event.xdata**2 + event.ydata**2)
        if ppi.cell_size_m > 0:
            dist_nm = r * ppi.cell_size_m / 1852.0
            txt.set_text(f'Bearing: {az:6.1f}°   {dist_nm:.1f} nm')
        else:
            txt.set_text(f'Bearing: {az:6.1f}°   {r:.0f} cells')
        fig.canvas.draw_idle()

    fig.canvas.mpl_connect('motion_notify_event', on_move)


def analyze_pcap(filepath: str, display: bool = True,
                 save_path: Optional[str] = None,
                 verbose: bool = True,
                 initial_azimuth: float = 0.0,
                 filter_stream: Optional[Tuple[str, int]] = None) -> List[Cat240Message]:
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

    print(f"\n  Total packets:       {pkt_count}")
    print(f"  CAT240 messages:     {cat240_count}")
    print(f"  Errors:              {errors}")
    print(f"  Max. cells/azimuth:    {max_cells}")

    if messages:
        az_values = [m.start_azimuth_deg for m in messages]
        print(f"  Azimuth range:       {min(az_values):.1f}° – {max(az_values):.1f}°")
        print(f"{'='*60}\n")

    if display or save_path:
        # ── PPI window ────────────────────────────────────────────────────────
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
            # ── A-Scope window ────────────────────────────────────────────────
            ascope = AScope(ppi, initial_azimuth=initial_azimuth)
            _setup_ppi_overlay(ascope, az_line, range_ring, ppi_tick, ppi, fig_ppi)
            ascope.render()

            # ── PPI click → A-Scope ──────────────────────────────────────────
            def on_ppi_click(event):
                if event.inaxes != ax_ppi or event.xdata is None:
                    return
                if event.button == 3:
                    _toggle_ascope_mode(fig_ppi, ascope)
                    return
                if event.button != 1:
                    return
                new_az = ascope.handle_ppi_click(event.xdata, event.ydata)
                if new_az is not None:
                    az_rad = np.deg2rad(new_az)
                    az_line.set_data(
                        [0, ppi.max_range_cells * np.sin(az_rad)],
                        [0, ppi.max_range_cells * np.cos(az_rad)])
                    az_line.set_visible(True)
                else:
                    _t = np.linspace(0, 2*np.pi, 361)
                    _rc = float(ascope.range_cell)
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
                filter_stream: Optional[Tuple[str, int]] = None):
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

    decoder    = Cat240Decoder()
    ppi        = RadarPPI(max_range_cells=1024, az_bins=4096)
    msg_queue  = queue.Queue(maxsize=50000)
    state      = {'done': False, 'msgs': 0}

    def reader_thread():
        try:
            reader  = PcapReader(filepath)
            t0_pcap = None
            t0_real = time.time()
            for ts, udp, dst_ip, dst_port in reader.packets():
                if (dst_ip, dst_port) != filter_stream:
                    continue
                if t0_pcap is None:
                    t0_pcap = ts
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
        state['done'] = True
        print(f"\n  [Replay] File read complete. {state['msgs']} azimuths.")

    threading.Thread(target=reader_thread, daemon=True).start()

    # PPI window
    fig_ppi, ax_ppi = plt.subplots(figsize=(10, 10), facecolor='#0a0a0a',
                                    num='PPI  |  CAT240 Replay')
    fig_ppi.canvas.manager.set_window_title('PPI  |  CAT240 Replay')
    _attach_ppi_readout(fig_ppi, ax_ppi, ppi)

    # Initial render – creates mesh and calls ax.clear() ONCE.
    # All overlays must be added to the axis AFTERWARDS.
    ppi.render(ax_ppi, title=f"CAT240 Replay  |  {speed}x")

    ascope = AScope(ppi, initial_azimuth=initial_azimuth)

    # Selection line (click) + range ring + cursor crosshair
    az_rad0 = np.deg2rad(initial_azimuth)
    az_sel_line, = ax_ppi.plot(
        [0, ppi.max_range_cells * np.sin(az_rad0)],
        [0, ppi.max_range_cells * np.cos(az_rad0)],
        color='#ffcc00', linewidth=1.2, linestyle='-', visible=False)
    range_ring, = ax_ppi.plot([], [], color='#00aaff', linewidth=1.5,
                               linestyle='-', visible=False)
    ppi_tick, = ax_ppi.plot([], [], color='#ff4444', linewidth=2.0, solid_capstyle='round')
    _setup_ppi_overlay(ascope, az_sel_line, range_ring, ppi_tick, ppi, fig_ppi)

    def on_ppi_click(event):
        if event.inaxes != ax_ppi or event.xdata is None:
            return
        if event.button == 3:
            _toggle_ascope_mode(fig_ppi, ascope)
            return
        if event.button == 1:
            new_az = ascope.handle_ppi_click(event.xdata, event.ydata)
            if new_az is not None:
                az_rad = np.deg2rad(new_az)
                az_sel_line.set_data(
                    [0, ppi.max_range_cells * np.sin(az_rad)],
                    [0, ppi.max_range_cells * np.cos(az_rad)])
                az_sel_line.set_visible(True)
            else:
                _t = np.linspace(0, 2*np.pi, 361)
                _rc = float(ascope.range_cell)
                range_ring.set_data(_rc*np.sin(_t), _rc*np.cos(_t))
                range_ring.set_visible(True)
            fig_ppi.canvas.draw_idle()

    fig_ppi.canvas.mpl_connect('button_press_event', on_ppi_click)

    def update(_):
        try:
            while True:
                msg = msg_queue.get_nowait()
                ppi.add_message(msg)
                state['msgs'] += 1
        except Exception:
            pass

        status = " [DONE]" if state['done'] else ""
        ppi.render(ax_ppi,
                   title=f"CAT240 Replay  |  {speed}x{status}")
        ascope.render()
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
                initial_azimuth: float = 0.0):
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
    fig_ppi, ax_ppi = plt.subplots(figsize=(10, 10), facecolor='#0a0a0a',
                                    num='PPI  |  CAT240 Live')

    # Initial render – ax.clear() is called only once here.
    # Add all overlays AFTERWARDS.
    ppi.render(ax_ppi, title=f"CAT240 Live PPI  |  Port {port}")

    # A-Scope window
    ascope = AScope(ppi, initial_azimuth=initial_azimuth)

    # Azimuth line + range ring (after initial render!)
    az_rad0 = np.deg2rad(initial_azimuth)
    az_line, = ax_ppi.plot(
        [0, ppi.max_range_cells * np.sin(az_rad0)],
        [0, ppi.max_range_cells * np.cos(az_rad0)],
        color='#ffcc00', linewidth=1.2, linestyle='-', visible=False)
    range_ring, = ax_ppi.plot([], [], color='#00aaff', linewidth=1.5,
                               linestyle='-', visible=False)
    ppi_tick, = ax_ppi.plot([], [], color='#ff4444', linewidth=2.0, solid_capstyle='round')
    _setup_ppi_overlay(ascope, az_line, range_ring, ppi_tick, ppi, fig_ppi)

    def on_ppi_click(event):
        if event.inaxes != ax_ppi or event.xdata is None:
            return
        if event.button == 3:
            _toggle_ascope_mode(fig_ppi, ascope)
            return
        if event.button != 1:
            return
        new_az = ascope.handle_ppi_click(event.xdata, event.ydata)
        if new_az is not None:
            az_rad = np.deg2rad(new_az)
            az_line.set_data(
                [0, ppi.max_range_cells * np.sin(az_rad)],
                [0, ppi.max_range_cells * np.cos(az_rad)])
            az_line.set_visible(True)
        else:
            _t = np.linspace(0, 2*np.pi, 361)
            _rc = float(ascope.range_cell)
            range_ring.set_data(_rc*np.sin(_t), _rc*np.cos(_t))
            range_ring.set_visible(True)
        fig_ppi.canvas.draw_idle()

    fig_ppi.canvas.mpl_connect('button_press_event', on_ppi_click)
    _attach_ppi_readout(fig_ppi, ax_ppi, ppi)

    def update(_):
        ppi.render(ax_ppi, title=f"CAT240 Live PPI  |  Port {port}")
        ascope.render()
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
    parser.add_argument('--no-display', action='store_true',           help='Do not show PPI/A-Scope window')
    parser.add_argument('--save',       metavar='PNG',                 help='Save PPI as PNG file')
    parser.add_argument('--verbose',    action='store_true', default=True)

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
                    initial_azimuth=args.azimuth)
    elif args.replay:
        replay_pcap(filepath=args.replay, speed=args.speed,
                    initial_azimuth=args.azimuth,
                    filter_stream=filter_stream)
    else:
        analyze_pcap(
            filepath         = args.file,
            display          = not args.no_display,
            save_path        = args.save,
            verbose          = args.verbose,
            initial_azimuth  = args.azimuth,
            filter_stream    = filter_stream,
        )


if __name__ == '__main__':
    main()
