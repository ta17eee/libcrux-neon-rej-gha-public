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


def relocation_kind(word):
    return {
        "symbolnum": word & 0x00FFFFFF,
        "pcrel": (word >> 24) & 1,
        "length": (word >> 25) & 3,
        "extern": (word >> 27) & 1,
        "type": (word >> 28) & 15,
    }


def parse_set(raw):
    if "=" not in raw:
        raise argparse.ArgumentTypeError(f"set must be INDEX=ADDRESS, got {raw!r}")
    index, address = raw.split("=", 1)
    return int(index, 0), int(address, 0)


def parse_word(raw):
    if "=" not in raw:
        raise argparse.ArgumentTypeError(f"word must be ADDRESS=WORD, got {raw!r}")
    address, word = raw.split("=", 1)
    return int(address, 0), int(word, 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--set", action="append", required=True, type=parse_set)
    parser.add_argument("--word", action="append", default=[], type=parse_word)
    parser.add_argument("--section", default="__TEXT,__text")
    parser.add_argument("--out-json", type=Path)
    args = parser.parse_args()

    data = bytearray(args.input.read_bytes())
    sec_seg, sec_name = args.section.split(",", 1)
    sect = next((s for s in sections(data) if s["seg"] == sec_seg and s["sect"] == sec_name), None)
    if sect is None:
        raise SystemExit(f"missing section {args.section}")

    changes = []
    for reloc_index, new_address in args.set:
        if reloc_index < 0 or reloc_index >= sect["nreloc"]:
            raise SystemExit(f"relocation index {reloc_index} outside section count {sect['nreloc']}")
        if new_address < 0 or new_address > 0x00FFFFFF:
            raise SystemExit(f"new relocation address out of range: 0x{new_address:x}")
        if new_address + 4 > sect["size"]:
            raise SystemExit(
                f"new relocation address 0x{new_address:x} outside section size 0x{sect['size']:x}"
            )
        rel_off = sect["reloff"] + reloc_index * 8
        old_address, r_word = struct.unpack_from("<II", data, rel_off)
        if (old_address >> 31) & 1:
            raise SystemExit(f"refusing scattered relocation at index {reloc_index}")
        bits = relocation_kind(r_word)
        struct.pack_into("<I", data, rel_off, new_address)
        changes.append(
            {
                "relocation_index": reloc_index,
                "old_address": f"0x{old_address:x}",
                "new_address": f"0x{new_address:x}",
                "old_section_addr": f"0x{sect['addr'] + old_address:x}",
                "new_section_addr": f"0x{sect['addr'] + new_address:x}",
                "type": bits["type"],
                "type_name": ARM64_RELOC_TYPES.get(bits["type"], f"type{bits['type']}"),
                "pcrel": bits["pcrel"],
                "length": bits["length"],
                "extern": bits["extern"],
                "symbolnum": bits["symbolnum"],
                "raw_word": f"0x{r_word:08x}",
            }
        )

    word_changes = []
    for address, new_word in args.word:
        if address < 0 or address + 4 > sect["size"]:
            raise SystemExit(f"word address 0x{address:x} outside section size 0x{sect['size']:x}")
        if new_word < 0 or new_word > 0xFFFFFFFF:
            raise SystemExit(f"word value out of range: 0x{new_word:x}")
        word_off = sect["offset"] + address
        old_word, = struct.unpack_from("<I", data, word_off)
        struct.pack_into("<I", data, word_off, new_word)
        word_changes.append(
            {
                "address": f"0x{address:x}",
                "section_addr": f"0x{sect['addr'] + address:x}",
                "old_word": f"0x{old_word:08x}",
                "new_word": f"0x{new_word:08x}",
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    result = {
        "input": str(args.input),
        "output": str(args.output),
        "section": args.section,
        "changes": changes,
        "word_changes": word_changes,
    }
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
