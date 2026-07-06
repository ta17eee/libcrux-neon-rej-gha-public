#!/usr/bin/env python3
import argparse
import json
import struct
from pathlib import Path


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
                "entry_offset": entry_off,
                "name": name,
                "type": n_type,
                "sect": n_sect,
                "desc": n_desc,
                "value": n_value,
            }
        )
    return result


def parse_set(raw):
    if "=" not in raw:
        raise argparse.ArgumentTypeError(f"set must be SYMBOL=VALUE, got {raw!r}")
    name, value = raw.split("=", 1)
    return name, int(value, 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--set", action="append", required=True, type=parse_set)
    parser.add_argument("--out-json", type=Path)
    args = parser.parse_args()

    data = bytearray(args.input.read_bytes())
    syms = symbols(data)
    by_name = {}
    for sym in syms:
        by_name.setdefault(sym["name"], []).append(sym)

    changes = []
    for name, new_value in args.set:
        matches = by_name.get(name, [])
        if not matches:
            raise SystemExit(f"missing symbol {name}")
        if len(matches) != 1:
            raise SystemExit(f"symbol {name} is ambiguous: {len(matches)} matches")
        if new_value < 0 or new_value > 0xFFFFFFFFFFFFFFFF:
            raise SystemExit(f"symbol value out of range: 0x{new_value:x}")
        sym = matches[0]
        struct.pack_into("<Q", data, sym["entry_offset"] + 8, new_value)
        changes.append(
            {
                "symbol_index": sym["index"],
                "symbol_name": sym["name"],
                "type": sym["type"],
                "sect": sym["sect"],
                "desc": sym["desc"],
                "old_value": f"0x{sym['value']:x}",
                "new_value": f"0x{new_value:x}",
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    result = {
        "input": str(args.input),
        "output": str(args.output),
        "changes": changes,
    }
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
