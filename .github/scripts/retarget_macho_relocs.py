#!/usr/bin/env python3
import argparse
import json
import struct
from pathlib import Path


ARM64_RELOC_TYPES = {
    0: "UNSIGNED",
    1: "SUBTRACTOR",
    2: "BRANCH26",
    3: "PAGE21",
    4: "PAGEOFF12",
    5: "GOT_LOAD_PAGE21",
    6: "GOT_LOAD_PAGEOFF12",
    7: "POINTER_TO_GOT",
    8: "TLVP_LOAD_PAGE21",
    9: "TLVP_LOAD_PAGEOFF12",
    10: "ADDEND",
}


def cstr(raw):
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def load_commands(data):
    if len(data) < 32:
        raise ValueError("file too small for mach_header_64")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xFEEDFACF:
        raise ValueError(f"unexpected Mach-O magic 0x{magic:08x}")
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            raise ValueError(f"bad load command at 0x{off:x}")
        yield off, cmd, cmdsize
        off += cmdsize


def sections(data):
    result = []
    for off, cmd, _cmdsize in load_commands(data):
        if cmd != 0x19:  # LC_SEGMENT_64
            continue
        nsects, = struct.unpack_from("<I", data, off + 64)
        sec_off = off + 72
        for _ in range(nsects):
            sect = cstr(data[sec_off:sec_off + 16])
            seg = cstr(data[sec_off + 16:sec_off + 32])
            addr, size = struct.unpack_from("<QQ", data, sec_off + 32)
            file_offset, align, reloff, nreloc = struct.unpack_from("<IIII", data, sec_off + 48)
            result.append(
                {
                    "seg": seg,
                    "sect": sect,
                    "addr": addr,
                    "size": size,
                    "offset": file_offset,
                    "align": align,
                    "reloff": reloff,
                    "nreloc": nreloc,
                }
            )
            sec_off += 80
    return result


def symtab_command(data):
    for off, cmd, _cmdsize in load_commands(data):
        if cmd == 0x2:  # LC_SYMTAB
            return struct.unpack_from("<IIII", data, off + 8)
    raise ValueError("missing LC_SYMTAB")


def symbols(data):
    symoff, nsyms, stroff, strsize = symtab_command(data)
    result = []
    for idx in range(nsyms):
        entry_off = symoff + idx * 16
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", data, entry_off)
        name = ""
        if n_strx:
            name_off = stroff + n_strx
            if stroff <= name_off < min(stroff + strsize, len(data)):
                end = data.find(b"\0", name_off, min(stroff + strsize, len(data)))
                if end >= 0:
                    name = data[name_off:end].decode("utf-8", "replace")
        result.append(
            {
                "index": idx,
                "name": name,
                "type": n_type,
                "sect": n_sect,
                "desc": n_desc,
                "value": n_value,
            }
        )
    return result


def relocation_kind(word):
    return {
        "symbolnum": word & 0x00FFFFFF,
        "pcrel": (word >> 24) & 1,
        "length": (word >> 25) & 3,
        "extern": (word >> 27) & 1,
        "type": (word >> 28) & 15,
    }


def parse_mapping(raw):
    if "=" not in raw:
        raise argparse.ArgumentTypeError(f"mapping must be INDEX=SYMBOL, got {raw!r}")
    left, right = raw.split("=", 1)
    return int(left, 0), right


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--map", action="append", required=True, type=parse_mapping)
    parser.add_argument("--section", default="__TEXT,__text")
    parser.add_argument("--out-json", type=Path)
    args = parser.parse_args()

    data = bytearray(args.input.read_bytes())
    sec_seg, sec_name = args.section.split(",", 1)
    sect = next((s for s in sections(data) if s["seg"] == sec_seg and s["sect"] == sec_name), None)
    if sect is None:
        raise SystemExit(f"missing section {args.section}")
    syms = symbols(data)
    sym_by_name = {}
    for sym in syms:
        sym_by_name.setdefault(sym["name"], []).append(sym)

    changes = []
    for reloc_index, new_name in args.map:
        matches = sym_by_name.get(new_name, [])
        if not matches:
            raise SystemExit(f"missing symbol {new_name}")
        new_sym = matches[0]
        if new_sym["index"] > 0x00FFFFFF:
            raise SystemExit(f"symbol index too large for relocation: {new_sym['index']}")
        if reloc_index < 0 or reloc_index >= sect["nreloc"]:
            raise SystemExit(f"relocation index {reloc_index} outside section count {sect['nreloc']}")
        rel_off = sect["reloff"] + reloc_index * 8
        r_address, r_word = struct.unpack_from("<II", data, rel_off)
        if (r_address >> 31) & 1:
            raise SystemExit(f"refusing scattered relocation at index {reloc_index}")
        bits = relocation_kind(r_word)
        old_sym = syms[bits["symbolnum"]] if bits["symbolnum"] < len(syms) else None
        new_word = (r_word & 0xFF000000) | new_sym["index"]
        struct.pack_into("<I", data, rel_off + 4, new_word)
        changes.append(
            {
                "relocation_index": reloc_index,
                "address": f"0x{r_address:x}",
                "type": bits["type"],
                "type_name": ARM64_RELOC_TYPES.get(bits["type"], f"type{bits['type']}"),
                "pcrel": bits["pcrel"],
                "length": bits["length"],
                "extern": bits["extern"],
                "old_symbol_index": bits["symbolnum"],
                "old_symbol_name": "" if old_sym is None else old_sym["name"],
                "old_symbol_value": None if old_sym is None else f"0x{old_sym['value']:x}",
                "new_symbol_index": new_sym["index"],
                "new_symbol_name": new_sym["name"],
                "new_symbol_value": f"0x{new_sym['value']:x}",
                "old_raw_word": f"0x{r_word:08x}",
                "new_raw_word": f"0x{new_word:08x}",
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    result = {
        "input": str(args.input),
        "output": str(args.output),
        "section": args.section,
        "changes": changes,
    }
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
