#!/usr/bin/env python3
import argparse
import json
import struct
from pathlib import Path


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


def unique_symbol(by_name, name):
    matches = by_name.get(name, [])
    if not matches:
        raise SystemExit(f"missing symbol {name}")
    if len(matches) != 1:
        raise SystemExit(f"symbol {name} is ambiguous: {len(matches)} matches")
    return matches[0]


def parse_copy(raw):
    if "=" not in raw:
        raise argparse.ArgumentTypeError(f"copy must be TARGET=SOURCE, got {raw!r}")
    target, source = raw.split("=", 1)
    return target, source


def parse_fields(raw):
    fields = [field.strip() for field in raw.split(",") if field.strip()]
    allowed = {"type", "sect", "desc", "value"}
    unknown = sorted(set(fields) - allowed)
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown field(s): {', '.join(unknown)}")
    if not fields:
        raise argparse.ArgumentTypeError("at least one field is required")
    return fields


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--copy", action="append", required=True, type=parse_copy)
    parser.add_argument("--fields", default="type,sect,desc", type=parse_fields)
    parser.add_argument("--out-json", type=Path)
    args = parser.parse_args()

    data = bytearray(args.input.read_bytes())
    syms = symbols(data)
    by_name = {}
    for sym in syms:
        by_name.setdefault(sym["name"], []).append(sym)

    changes = []
    for target_name, source_name in args.copy:
        target = unique_symbol(by_name, target_name)
        source = unique_symbol(by_name, source_name)
        old = dict(target)
        if "type" in args.fields:
            struct.pack_into("<B", data, target["entry_offset"] + 4, source["type"])
            target["type"] = source["type"]
        if "sect" in args.fields:
            struct.pack_into("<B", data, target["entry_offset"] + 5, source["sect"])
            target["sect"] = source["sect"]
        if "desc" in args.fields:
            struct.pack_into("<H", data, target["entry_offset"] + 6, source["desc"])
            target["desc"] = source["desc"]
        if "value" in args.fields:
            struct.pack_into("<Q", data, target["entry_offset"] + 8, source["value"])
            target["value"] = source["value"]
        changes.append(
            {
                "symbol_index": old["index"],
                "symbol_name": old["name"],
                "source_symbol_index": source["index"],
                "source_symbol_name": source["name"],
                "fields": args.fields,
                "old_type": old["type"],
                "new_type": target["type"],
                "old_sect": old["sect"],
                "new_sect": target["sect"],
                "old_desc": old["desc"],
                "new_desc": target["desc"],
                "old_value": f"0x{old['value']:x}",
                "new_value": f"0x{target['value']:x}",
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
