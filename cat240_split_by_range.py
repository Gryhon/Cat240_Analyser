#!/usr/bin/env python3
"""
cat240_split_by_range.py — Split a CAT240 PCAPNG file into one file per
CELL_DUR value (pulse length / range scale).

Usage:
    python cat240_split_by_range.py <input.pcapng> [--output-dir DIR]
"""

import struct
import argparse
from pathlib import Path

SPEED_OF_LIGHT = 299_792_458  # m/s
NM_TO_M = 1852.0

BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 0x00000001
BLOCK_EPB = 0x00000006


# ── PCAPNG block reader ────────────────────────────────────────────────────────

def read_pcapng_blocks(filepath):
    """Read entire PCAPNG file; yield (block_type, raw_bytes, endian) per block."""
    with open(filepath, 'rb') as f:
        data = f.read()

    endian = '<'
    pos = 0

    while pos + 8 <= len(data):
        btype_le = struct.unpack_from('<I', data, pos)[0]

        if btype_le == BLOCK_SHB:
            # Block total length is in the file's native byte order.
            # Read it as little-endian (safe: SHB magic follows immediately).
            btl = struct.unpack_from('<I', data, pos + 4)[0]
            if btl < 28 or pos + btl > len(data):
                break
            raw = data[pos:pos + btl]
            # Byte order magic at offset +8 inside the block
            magic = struct.unpack_from('<I', data, pos + 8)[0]
            endian = '>' if magic == 0x4D3C2B1A else '<'
            yield ('SHB', raw, endian)
            pos += btl

        else:
            btl = struct.unpack_from(endian + 'I', data, pos + 4)[0]
            if btl < 12 or pos + btl > len(data):
                break
            btype = struct.unpack_from(endian + 'I', data, pos)[0]
            raw = data[pos:pos + btl]
            yield (btype, raw, endian)
            pos += btl


# ── Packet decoding ────────────────────────────────────────────────────────────

def _epb_packet_data(raw, endian):
    """Return packet bytes from an Enhanced Packet Block."""
    # EPB: type(4)+total_len(4)+iface_id(4)+ts_hi(4)+ts_lo(4)+cap_len(4)+orig_len(4)+data
    if len(raw) < 28:
        return None
    cap_len = struct.unpack_from(endian + 'I', raw, 20)[0]
    return raw[28:28 + cap_len]


def _udp_payload(pkt):
    """Parse Ethernet/IP/UDP; return UDP payload bytes or None."""
    if not pkt or len(pkt) < 14:
        return None

    ethertype = struct.unpack_from('>H', pkt, 12)[0]
    ip_off = 14
    while ethertype in (0x8100, 0x88A8):          # VLAN tags
        if ip_off + 4 > len(pkt):
            return None
        ethertype = struct.unpack_from('>H', pkt, ip_off + 2)[0]
        ip_off += 4

    if ethertype != 0x0800:                        # not IPv4
        return None
    if ip_off + 20 > len(pkt):
        return None

    ihl = (pkt[ip_off] & 0x0F) * 4
    if pkt[ip_off + 9] != 17:                     # not UDP
        return None

    # Drop IP fragments (only unfragmented or last frag without offset handled here)
    flags_frag = struct.unpack_from('>H', pkt, ip_off + 6)[0]
    if (flags_frag & 0x1FFF) != 0 or (flags_frag & 0x2000):
        return None                                # fragmented – skip

    udp_off = ip_off + ihl
    if udp_off + 8 > len(pkt):
        return None
    return pkt[udp_off + 8:]


def _cat240_cell_dur(payload):
    """
    Return CELL_DUR (int, femtoseconds) from a CAT240 UDP payload, or None.

    Parses the FSPEC and advances field-by-field until I240/040 or I240/041.
    CELL_DUR sits at bytes [8..11] (big-endian uint32) inside those 12-byte fields.
    """
    if not payload or payload[0] != 0xF0:
        return None
    if len(payload) < 5:
        return None

    # --- parse FSPEC ---------------------------------------------------------
    fspec = []
    pos = 3                                        # skip CAT(1) + LEN(2)
    while pos < len(payload):
        b = payload[pos]
        fspec.append(b)
        pos += 1
        if not (b & 0x01):                         # FX=0 → last FSPEC byte
            break

    # --- build active FRN set ------------------------------------------------
    active = set()
    frn = 1
    for fb in fspec:
        for bit in range(7, 0, -1):               # bits 7..1 → FRN
            if fb & (1 << bit):
                active.add(frn)
            frn += 1
        # bit 0 = FX continuation flag, not a FRN

    # --- field sizes for fixed-length FRNs -----------------------------------
    fixed = {
        1: 2,   # I240/010  Data Source Identifier
        2: 1,   # I240/000  Message Type
        3: 4,   # I240/020  Video Record Header
        # 4: variable  I240/030 Video Summary
        5: 12,  # I240/040  Video Header Nano   ← CELL_DUR here
        6: 12,  # I240/041  Video Header Femto  ← CELL_DUR here
        7: 2,   # I240/048  Cell Resolution
        8: 5,   # I240/049  Counters
        # 9..11: variable video blocks
        12: 3,  # I240/140  Time of Day
        # 13: RE variable
        # 14: SP variable
    }

    # --- walk fields in FRN order --------------------------------------------
    pos = 3 + len(fspec)

    for frn in range(1, 15):
        if frn not in active:
            continue

        if frn == 4:                               # I240/030 variable: 1+n bytes
            if pos >= len(payload):
                return None
            pos += 1 + payload[pos]
            continue

        if frn in (9, 10, 11):                    # video blocks variable
            if pos >= len(payload):
                return None
            rep = payload[pos]
            strides = {9: 4, 10: 64, 11: 256}
            pos += 1 + rep * strides[frn]
            continue

        if frn in (13, 14):                        # RE / SP: length-prefixed
            if pos >= len(payload):
                return None
            pos += payload[pos]
            continue

        if frn in (5, 6):                          # I240/040 or I240/041
            if pos + 12 > len(payload):
                return None
            # layout: START_AZ(2) END_AZ(2) START_RG(4) CELL_DUR(4)
            return struct.unpack_from('>I', payload, pos + 8)[0]

        size = fixed.get(frn)
        if size is None:
            return None
        pos += size

    return None


# ── Range label ───────────────────────────────────────────────────────────────

def _range_nm(cell_dur_fs, num_cells=1024):
    cell_m = SPEED_OF_LIGHT * cell_dur_fs * 1e-15 / 2
    return cell_m * num_cells / NM_TO_M


def _range_label(range_nm):
    if range_nm < 1.0:
        return f"{range_nm:.2f}nm"
    elif range_nm < 10.0:
        return f"{range_nm:.1f}nm"
    else:
        return f"{range_nm:.0f}nm"


# ── Main split logic ──────────────────────────────────────────────────────────

def split(input_path, output_dir):
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Lese {input_path.name} …")
    blocks = list(read_pcapng_blocks(input_path))
    print(f"  {len(blocks)} Blöcke gelesen.")

    # Detect file endianness
    endian = '<'
    for btype, _, bend in blocks:
        if btype == 'SHB':
            endian = bend
            break

    # ── Pass 1: collect header blocks + identify unique CELL_DURs ──────────
    header_blocks = []   # SHB + IDB blocks (written verbatim to every output)
    cell_dur_counts = {} # cell_dur_fs → packet count

    for btype, raw, bend in blocks:
        if btype in ('SHB', BLOCK_IDB):
            header_blocks.append(raw)
            continue
        if btype != BLOCK_EPB:
            continue
        pkt = _epb_packet_data(raw, endian)
        udp = _udp_payload(pkt) if pkt else None
        cd = _cat240_cell_dur(udp) if udp else None
        if cd is not None:
            cell_dur_counts[cd] = cell_dur_counts.get(cd, 0) + 1

    if not cell_dur_counts:
        print("Keine CAT240-Pakete mit CELL_DUR gefunden – Abbruch.")
        return

    # ── Print summary & build output file map ──────────────────────────────
    stem = input_path.stem
    print(f"\nGefundene Reichweitenstufen ({len(cell_dur_counts)}):\n")
    print(f"  {'CELL_DUR (fs)':>15}  {'Range':>8}  {'Pakete':>8}  Dateiname")
    print(f"  {'-'*15}  {'-'*8}  {'-'*8}  {'-'*40}")

    output_map = {}   # cell_dur → Path
    for cd in sorted(cell_dur_counts):
        rnm = _range_nm(cd)
        label = _range_label(rnm)
        count = cell_dur_counts[cd]
        fname = f"{stem}_{label}.pcapng"
        fpath = output_dir / fname
        output_map[cd] = fpath
        print(f"  {cd:>15}  {rnm:>7.2f}nm  {count:>8}  {fname}")

    # ── Pass 2: open outputs, write headers, route EPBs ───────────────────
    handles = {}
    for cd, fpath in output_map.items():
        fh = open(fpath, 'wb')
        for hraw in header_blocks:
            fh.write(hraw)
        handles[cd] = fh

    routed = {cd: 0 for cd in cell_dur_counts}
    skipped = 0

    for btype, raw, bend in blocks:
        if btype not in (BLOCK_EPB,):
            continue
        pkt = _epb_packet_data(raw, endian)
        udp = _udp_payload(pkt) if pkt else None
        cd = _cat240_cell_dur(udp) if udp else None
        if cd is not None and cd in handles:
            handles[cd].write(raw)
            routed[cd] += 1
        else:
            skipped += 1

    for fh in handles.values():
        fh.close()

    # ── Result ─────────────────────────────────────────────────────────────
    total = sum(routed.values())
    print(f"\nErgebnis: {total} Pakete geschrieben, {skipped} übersprungen.")
    print(f"Ausgabeverzeichnis: {output_dir}/")


def main():
    p = argparse.ArgumentParser(
        description='Split CAT240 PCAPNG by CELL_DUR (pulse length / range scale)'
    )
    p.add_argument('input', help='Input PCAPNG file')
    p.add_argument('--output-dir', '-o', default=None,
                   help='Output directory (default: same directory as input file)')
    args = p.parse_args()

    out = args.output_dir or Path(args.input).parent
    split(args.input, out)


if __name__ == '__main__':
    main()
