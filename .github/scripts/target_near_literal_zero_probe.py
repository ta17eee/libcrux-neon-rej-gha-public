#!/usr/bin/env python3
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


def run(argv, *, cwd=None, env=None, stdout=None, stderr=None, check=False):
    print("+ " + " ".join(str(a) for a in argv), flush=True)
    proc = subprocess.run(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(proc.returncode)
    return proc


def output(argv, *, cwd=None, env=None):
    proc = subprocess.run(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(argv)}\n{proc.stdout}")
    return proc.stdout.strip()


def append(path, text):
    with open(path, "a") as f:
        f.write(text)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def count_bytes(path, pattern):
    data = Path(path).read_bytes()
    needle = bytes(int(x, 16) for x in pattern.split())
    count = 0
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            return count
        count += 1
        start = idx + 1


def cstr(raw):
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")


def macho_sections(data):
    if len(data) < 32:
        raise ValueError("file too small for mach_header_64")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xfeedfacf:
        raise ValueError(f"unexpected Mach-O magic 0x{magic:08x}")
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    sections = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise ValueError("truncated load command")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects, = struct.unpack_from("<I", data, off + 64)
            sec_off = off + 72
            for _ in range(nsects):
                sect = cstr(data[sec_off:sec_off + 16])
                seg = cstr(data[sec_off + 16:sec_off + 32])
                addr, size = struct.unpack_from("<QQ", data, sec_off + 32)
                file_offset, = struct.unpack_from("<I", data, sec_off + 48)
                sections.append((seg, sect, addr, size, file_offset))
                sec_off += 80
        off += cmdsize
    return sections


def macho_section_records(data):
    if len(data) < 32:
        raise ValueError("file too small for mach_header_64")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xfeedfacf:
        raise ValueError(f"unexpected Mach-O magic 0x{magic:08x}")
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    sections = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise ValueError("truncated load command")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects, = struct.unpack_from("<I", data, off + 64)
            sec_off = off + 72
            for _ in range(nsects):
                sect = cstr(data[sec_off:sec_off + 16])
                seg = cstr(data[sec_off + 16:sec_off + 32])
                addr, size = struct.unpack_from("<QQ", data, sec_off + 32)
                file_offset, align, reloff, nreloc = struct.unpack_from("<IIII", data, sec_off + 48)
                flags, reserved1, reserved2, reserved3 = struct.unpack_from("<IIII", data, sec_off + 64)
                sections.append({
                    "seg": seg,
                    "sect": sect,
                    "addr": addr,
                    "size": size,
                    "offset": file_offset,
                    "align": align,
                    "reloff": reloff,
                    "nreloc": nreloc,
                    "flags": flags,
                    "reserved1": reserved1,
                    "reserved2": reserved2,
                    "reserved3": reserved3,
                })
                sec_off += 80
        off += cmdsize
    return sections


def macho_symtab(data):
    if len(data) < 32:
        raise ValueError("file too small for mach_header_64")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xfeedfacf:
        raise ValueError(f"unexpected Mach-O magic 0x{magic:08x}")
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise ValueError("truncated load command")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
            return symoff, nsyms, stroff, strsize
        off += cmdsize
    raise ValueError("missing LC_SYMTAB")


def same_len_name(name, marker):
    if len(marker) > len(name):
        raise ValueError(f"marker too long for {name}: {marker}")
    return marker + name[len(marker):]


def rename_symbols_same_length(src, dst, mapping, log_path):
    data = bytearray(Path(src).read_bytes())
    symoff, nsyms, stroff, strsize = macho_symtab(data)
    found = {}
    lines = []
    for i in range(nsyms):
        entry_off = symoff + i * 16
        if entry_off + 16 > len(data):
            Path(log_path).write_text(f"truncated nlist at index {i}\n")
            return 2
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", data, entry_off)
        if n_strx == 0:
            continue
        name_off = stroff + n_strx
        if name_off < stroff or name_off >= stroff + strsize or name_off >= len(data):
            continue
        end = data.find(b"\0", name_off, min(stroff + strsize, len(data)))
        if end < 0:
            continue
        name = data[name_off:end].decode("ascii", "replace")
        if name not in mapping:
            continue
        new_name = mapping[name]
        old = data[name_off:end]
        new = new_name.encode("ascii")
        if len(new) != len(old):
            lines.append(f"{name}: refusing non-same-length rename to {new_name}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        data[name_off:end] = new
        found[name] = (new_name, i, n_type, n_sect, n_desc, n_value)
        lines.append(
            f"renamed {name} -> {new_name} sym_index={i} type=0x{n_type:02x} "
            f"sect={n_sect} desc=0x{n_desc:04x} value=0x{n_value:x}"
        )
    missing = sorted(set(mapping) - set(found))
    if missing:
        lines.append("missing symbols: " + " ".join(missing))
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 44
    Path(dst).write_bytes(data)
    Path(log_path).write_text("\n".join(lines) + "\n")
    return 0


def nlist_symbols_by_name(data, names):
    symoff, nsyms, stroff, strsize = macho_symtab(data)
    wanted = set(names)
    out = {}
    for i in range(nsyms):
        entry_off = symoff + i * 16
        if entry_off + 16 > len(data):
            raise ValueError(f"truncated nlist at index {i}")
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", data, entry_off)
        if n_strx == 0:
            continue
        name_off = stroff + n_strx
        if name_off < stroff or name_off >= stroff + strsize or name_off >= len(data):
            continue
        end = data.find(b"\0", name_off, min(stroff + strsize, len(data)))
        if end < 0:
            continue
        name = data[name_off:end].decode("ascii", "replace")
        if name in wanted:
            out[name] = {
                "index": i,
                "entry_off": entry_off,
                "entry": bytes(data[entry_off:entry_off + 16]),
                "strx": n_strx,
                "type": n_type,
                "sect": n_sect,
                "desc": n_desc,
                "value": n_value,
            }
    return out


def transform_cpi_nlists(src, dst, symbols, mode, log_path):
    data = bytearray(Path(src).read_bytes())
    found = nlist_symbols_by_name(data, symbols)
    missing = sorted(set(symbols) - set(found))
    lines = []
    if missing:
        lines.append("missing symbols: " + " ".join(missing))
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 44
    s0, s1, s2 = symbols[:3]

    def describe(name):
        info = found[name]
        return (
            f"{name}: index={info['index']} type=0x{info['type']:02x} "
            f"sect={info['sect']} desc=0x{info['desc']:04x} "
            f"value=0x{info['value']:x} strx={info['strx']}"
        )

    for name in symbols:
        lines.append("old " + describe(name))

    def set_value(name, value):
        info = found[name]
        struct.pack_into("<Q", data, info["entry_off"] + 8, value)
        lines.append(f"set_value {name}: 0x{info['value']:x} -> 0x{value:x}")

    def set_entry(dst_name, src_name):
        data[found[dst_name]["entry_off"]:found[dst_name]["entry_off"] + 16] = found[src_name]["entry"]
        lines.append(f"set_entry {dst_name} <- {src_name}")

    if mode == "swap_values_01":
        set_value(s0, found[s1]["value"])
        set_value(s1, found[s0]["value"])
    elif mode == "equal_value0_01":
        set_value(s1, found[s0]["value"])
    elif mode == "equal_value1_01":
        set_value(s0, found[s1]["value"])
    elif mode == "equal_value1_12":
        set_value(s2, found[s1]["value"])
    elif mode == "swap_entries_01":
        e0 = found[s0]["entry"]
        e1 = found[s1]["entry"]
        data[found[s0]["entry_off"]:found[s0]["entry_off"] + 16] = e1
        data[found[s1]["entry_off"]:found[s1]["entry_off"] + 16] = e0
        lines.append(f"swap_entries {s0} <-> {s1}")
    elif mode == "duplicate_entry0_01":
        set_entry(s1, s0)
    elif mode == "duplicate_entry1_01":
        set_entry(s0, s1)
    elif mode == "swap_entries_12":
        e1 = found[s1]["entry"]
        e2 = found[s2]["entry"]
        data[found[s1]["entry_off"]:found[s1]["entry_off"] + 16] = e2
        data[found[s2]["entry_off"]:found[s2]["entry_off"] + 16] = e1
        lines.append(f"swap_entries {s1} <-> {s2}")
    else:
        lines.append(f"unknown nlist transform mode: {mode}")
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 2

    updated = nlist_symbols_by_name(data, symbols)
    for name in symbols:
        if name in updated:
            info = updated[name]
            lines.append(
                f"new {name}: index={info['index']} type=0x{info['type']:02x} "
                f"sect={info['sect']} desc=0x{info['desc']:04x} "
                f"value=0x{info['value']:x} strx={info['strx']}"
            )
        else:
            lines.append(f"new {name}: not found by name")
    Path(dst).write_bytes(data)
    Path(log_path).write_text("\n".join(lines) + "\n")
    return 0


def object_symbol_addr(path, target_hash):
    nm_text = output(["nm", "-nm", str(path)])
    for line in nm_text.splitlines():
        if target_hash in line:
            return int(line.split()[0], 16)
    return None


def relocation_kind(word):
    return {
        "symbolnum": word & 0x00ffffff,
        "pcrel": (word >> 24) & 1,
        "length": (word >> 25) & 3,
        "extern": (word >> 27) & 1,
        "type": (word >> 28) & 15,
    }


def transform_cpi_text_relocs(src, dst, symbols, mode, target_hash, target_offset_hex, log_path):
    data = bytearray(Path(src).read_bytes())
    found = nlist_symbols_by_name(data, symbols)
    missing = sorted(set(symbols) - set(found))
    lines = []
    if missing:
        lines.append("missing symbols: " + " ".join(missing))
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 44

    sections = macho_section_records(data)
    text = next((s for s in sections if s["seg"] == "__TEXT" and s["sect"] == "__text"), None)
    if text is None:
        lines.append("missing __TEXT,__text")
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 44

    s0, s1, s2 = symbols[:3]
    names_by_ordinal = {str(i): name for i, name in enumerate(symbols)}
    single_match = re.fullmatch(r"single_([0-9]+)_to_([0-9]+)_(\d+)", mode)
    set_match = re.fullmatch(r"(set|except)_([0-9]+)_to_([0-9]+)_([0-9_]+)", mode)
    map_match = re.fullmatch(r"map_([0-9]+)_((?:[0-9]+to[0-9]+)(?:_[0-9]+to[0-9]+)*)", mode)
    addrdup_match = re.fullmatch(r"addrdup_([0-9]+)_((?:[0-9]+from[0-9]+)(?:_[0-9]+from[0-9]+)*)", mode)
    addrswap_match = re.fullmatch(r"addrswap_([0-9]+)_([0-9]+)_([0-9]+)", mode)
    rules = {
        "all_1_to_0": (s1, s0, "all"),
        "all_0_to_1": (s0, s1, "all"),
        "all_2_to_1": (s2, s1, "all"),
        "all_1_to_2": (s1, s2, "all"),
        "all_2_to_0": (s2, s0, "all"),
        "nonnear_1_to_0": (s1, s0, "nonnear"),
        "nonnear_1_to_2": (s1, s2, "nonnear"),
        "near_1_to_0": (s1, s0, "near"),
        "near_1_to_2": (s1, s2, "near"),
        "near_2_to_1": (s2, s1, "near"),
        "near_2_to_0": (s2, s0, "near"),
        "early_0_to_1": (s0, s1, "early"),
    }
    single_ordinal = None
    ordinal_set = None
    ordinal_set_kind = None
    ordinal_dst_indexes = {}
    ordinal_dst_names = {}
    address_dup_map = {}
    address_swap_pair = None
    if single_match:
        if single_match.group(1) not in names_by_ordinal or single_match.group(2) not in names_by_ordinal:
            lines.append(f"unknown CPI ordinal in mode: {mode}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        src_name = names_by_ordinal[single_match.group(1)]
        dst_name = names_by_ordinal[single_match.group(2)]
        scope = "single"
        single_ordinal = int(single_match.group(3))
    elif set_match:
        if set_match.group(2) not in names_by_ordinal or set_match.group(3) not in names_by_ordinal:
            lines.append(f"unknown CPI ordinal in mode: {mode}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        ordinal_set_kind = set_match.group(1)
        src_name = names_by_ordinal[set_match.group(2)]
        dst_name = names_by_ordinal[set_match.group(3)]
        scope = "ordinal_set"
        ordinal_set = {int(part) for part in set_match.group(4).split("_") if part}
    elif map_match:
        if map_match.group(1) not in names_by_ordinal:
            lines.append(f"unknown CPI ordinal in mode: {mode}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        src_name = names_by_ordinal[map_match.group(1)]
        dst_name = src_name
        scope = "ordinal_map"
        for part in map_match.group(2).split("_"):
            source_text, dest_text = part.split("to", 1)
            if dest_text not in names_by_ordinal:
                lines.append(f"unknown CPI destination ordinal in mode: {mode}")
                Path(log_path).write_text("\n".join(lines) + "\n")
                return 2
            source_ordinal = int(source_text)
            dest_name = names_by_ordinal[dest_text]
            ordinal_dst_names[source_ordinal] = dest_name
    elif addrdup_match:
        if addrdup_match.group(1) not in names_by_ordinal:
            lines.append(f"unknown CPI ordinal in mode: {mode}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        src_name = names_by_ordinal[addrdup_match.group(1)]
        dst_name = src_name
        scope = "address_edit"
        for part in addrdup_match.group(2).split("_"):
            target_text, source_text = part.split("from", 1)
            address_dup_map[int(target_text)] = int(source_text)
    elif addrswap_match:
        if addrswap_match.group(1) not in names_by_ordinal:
            lines.append(f"unknown CPI ordinal in mode: {mode}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        src_name = names_by_ordinal[addrswap_match.group(1)]
        dst_name = src_name
        scope = "address_edit"
        address_swap_pair = (int(addrswap_match.group(2)), int(addrswap_match.group(3)))
    elif mode in rules:
        src_name, dst_name, scope = rules[mode]
    else:
        lines.append(f"unknown text relocation transform mode: {mode}")
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 2
    src_index = found[src_name]["index"]
    dst_index = found[dst_name]["index"]
    for source_ordinal, dest_name in ordinal_dst_names.items():
        ordinal_dst_indexes[source_ordinal] = found[dest_name]["index"]

    symbol_addr = object_symbol_addr(src, target_hash)
    target_addr = None
    if symbol_addr is not None:
        target_addr = symbol_addr + int(target_offset_hex, 16)

    def in_scope(rel_addr):
        if scope == "all":
            return True
        if target_addr is None:
            return False
        delta = target_addr - rel_addr
        if scope == "near":
            return 0 < delta <= 0x60
        if scope == "nonnear":
            return not (0 < delta <= 0x60)
        if scope == "early":
            return delta > 0x100
        if scope == "single":
            return True
        if scope == "ordinal_set":
            return True
        if scope == "ordinal_map":
            return True
        if scope == "address_edit":
            return True
        return False

    lines.append(f"mode={mode} src={src_name}[{src_index}] dst={dst_name}[{dst_index}] scope={scope}")
    if single_ordinal is not None:
        lines.append(f"single_ordinal={single_ordinal}")
    if ordinal_set is not None:
        ordinal_text = ",".join(str(i) for i in sorted(ordinal_set))
        lines.append(f"ordinal_set_kind={ordinal_set_kind} ordinal_set={ordinal_text}")
    if ordinal_dst_names:
        mapping_text = ", ".join(
            f"{source}->{dest}[{found[dest]['index']}]"
            for source, dest in sorted(ordinal_dst_names.items())
        )
        lines.append(f"ordinal_dst_map={mapping_text}")
    if address_dup_map:
        dup_text = ", ".join(f"{target}<-{source}" for target, source in sorted(address_dup_map.items()))
        lines.append(f"address_dup_map={dup_text}")
    if address_swap_pair is not None:
        lines.append(f"address_swap_pair={address_swap_pair[0]}<->{address_swap_pair[1]}")
    lines.append(
        f"text addr=0x{text['addr']:x} size=0x{text['size']:x} "
        f"reloff=0x{text['reloff']:x} nreloc={text['nreloc']}"
    )
    if target_addr is None:
        lines.append(f"target_hash {target_hash} not found")
    else:
        lines.append(f"target_addr=0x{target_addr:x}")
    lines.append(
        f"src_symbol {src_name}: index={found[src_name]['index']} "
        f"value=0x{found[src_name]['value']:x}"
    )
    lines.append(
        f"dst_symbol {dst_name}: index={found[dst_name]['index']} "
        f"value=0x{found[dst_name]['value']:x}"
    )
    for source, dest_name in sorted(ordinal_dst_names.items()):
        lines.append(
            f"map_dst_symbol source_ordinal={source} {dest_name}: "
            f"index={found[dest_name]['index']} value=0x{found[dest_name]['value']:x}"
        )
    for name in symbols[:3]:
        info = found[name]
        lines.append(f"symbol {name}: index={info['index']} value=0x{info['value']:x}")

    if scope == "address_edit":
        source_entries = []
        for i in range(text["nreloc"]):
            rel_off = text["reloff"] + i * 8
            if rel_off + 8 > len(data):
                lines.append(f"truncated relocation entry {i} at 0x{rel_off:x}")
                Path(log_path).write_text("\n".join(lines) + "\n")
                return 2
            r_address_u, r_word = struct.unpack_from("<II", data, rel_off)
            if r_address_u & 0x80000000:
                continue
            bits = relocation_kind(r_word)
            if not bits["extern"] or bits["symbolnum"] != src_index:
                continue
            source_ordinal = len(source_entries)
            source_entries.append({
                "rel_index": i,
                "rel_off": rel_off,
                "address": r_address_u,
                "word": r_word,
                "bits": bits,
                "ordinal": source_ordinal,
            })
        needed = set(address_dup_map) | set(address_dup_map.values())
        if address_swap_pair is not None:
            needed.update(address_swap_pair)
        missing_ordinals = sorted(i for i in needed if i < 0 or i >= len(source_entries))
        if missing_ordinals:
            lines.append("missing source ordinals: " + " ".join(str(i) for i in missing_ordinals))
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 44
        changed = 0
        if address_swap_pair is not None:
            left, right = address_swap_pair
            left_entry = source_entries[left]
            right_entry = source_entries[right]
            struct.pack_into("<I", data, left_entry["rel_off"], right_entry["address"])
            struct.pack_into("<I", data, right_entry["rel_off"], left_entry["address"])
            changed += 2
            lines.append(
                f"swap_address ordinal={left} rel[{left_entry['rel_index']}] "
                f"0x{left_entry['address']:x}->0x{right_entry['address']:x}; "
                f"ordinal={right} rel[{right_entry['rel_index']}] "
                f"0x{right_entry['address']:x}->0x{left_entry['address']:x}"
            )
        for target_ordinal, source_ordinal in sorted(address_dup_map.items()):
            target_entry = source_entries[target_ordinal]
            source_entry = source_entries[source_ordinal]
            struct.pack_into("<I", data, target_entry["rel_off"], source_entry["address"])
            changed += 1
            lines.append(
                f"dup_address ordinal={target_ordinal} rel[{target_entry['rel_index']}] "
                f"0x{target_entry['address']:x}->0x{source_entry['address']:x} "
                f"from ordinal={source_ordinal} rel[{source_entry['rel_index']}]"
            )
        for entry in source_entries:
            if entry["ordinal"] <= 12:
                rel_addr = text["addr"] + entry["address"]
                delta_text = "NA" if target_addr is None else f"0x{target_addr - rel_addr:x}"
                bits = entry["bits"]
                lines.append(
                    f"old_source ordinal={entry['ordinal']} rel[{entry['rel_index']}] "
                    f"section_off=0x{entry['address']:x} addr=0x{rel_addr:x} "
                    f"delta_to_target={delta_text} type={bits['type']} "
                    f"pcrel={bits['pcrel']} word=0x{entry['word']:08x}"
                )
        lines.append(f"changed={changed} source_seen={len(source_entries)}")
        Path(dst).write_bytes(data)
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 0

    changed = 0
    candidates = 0
    source_seen = 0
    for i in range(text["nreloc"]):
        rel_off = text["reloff"] + i * 8
        if rel_off + 8 > len(data):
            lines.append(f"truncated relocation entry {i} at 0x{rel_off:x}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        r_address_u, r_word = struct.unpack_from("<II", data, rel_off)
        if r_address_u & 0x80000000:
            continue
        bits = relocation_kind(r_word)
        if not bits["extern"] or bits["symbolnum"] != src_index:
            continue
        source_ordinal = source_seen
        source_seen += 1
        if single_ordinal is not None and source_ordinal != single_ordinal:
            continue
        if ordinal_set is not None:
            in_set = source_ordinal in ordinal_set
            if ordinal_set_kind == "set" and not in_set:
                continue
            if ordinal_set_kind == "except" and in_set:
                continue
        current_dst_index = dst_index
        current_dst_name = dst_name
        if ordinal_dst_indexes:
            if source_ordinal not in ordinal_dst_indexes:
                continue
            current_dst_index = ordinal_dst_indexes[source_ordinal]
            current_dst_name = ordinal_dst_names[source_ordinal]
        rel_addr = text["addr"] + r_address_u
        if not in_scope(rel_addr):
            continue
        candidates += 1
        new_word = (r_word & 0xff000000) | current_dst_index
        struct.pack_into("<I", data, rel_off + 4, new_word)
        changed += 1
        if changed <= 80:
            delta_text = "NA" if target_addr is None else f"0x{target_addr - rel_addr:x}"
            lines.append(
                f"retarget rel[{i}] section_off=0x{r_address_u:x} addr=0x{rel_addr:x} "
                f"source_ordinal={source_ordinal} delta_to_target={delta_text} "
                f"type={bits['type']} len={bits['length']} "
                f"pcrel={bits['pcrel']} dst={current_dst_name}[{current_dst_index}] "
                f"word=0x{r_word:08x}->0x{new_word:08x}"
            )
    lines.append(f"changed={changed} candidates={candidates} source_seen={source_seen}")
    if changed == 0:
        lines.append("no relocation entries matched")
    Path(dst).write_bytes(data)
    Path(log_path).write_text("\n".join(lines) + "\n")
    return 0


def zero_symbols(src, dst, symbols, size, log_path):
    data = bytearray(Path(src).read_bytes())
    sections = macho_sections(data)
    nm_out = output(["xcrun", "llvm-nm", "-nm", str(src)])
    nm_re = re.compile(r"^([0-9a-fA-F]+) \(([^,]+),([^)]+)\) .* ([^ ]+)$")
    found = {}
    for line in nm_out.splitlines():
        match = nm_re.match(line.strip())
        if not match:
            continue
        name = match.group(4)
        if name in symbols:
            found[name] = (int(match.group(1), 16), match.group(2), match.group(3))
    missing = sorted(set(symbols) - set(found))
    lines = []
    if missing:
        lines.append("missing symbols: " + " ".join(missing))
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 44
    for name in symbols:
        value, sym_seg, sym_sect = found[name]
        candidates = [s for s in sections if s[0] == sym_seg and s[1] == sym_sect and s[2] <= value < s[2] + s[3]]
        if not candidates:
            lines.append(f"{name}: no containing section for value=0x{value:x} {sym_seg},{sym_sect}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        seg, sect, addr, sect_size, file_offset = candidates[0]
        rel = value - addr
        start = file_offset + rel
        end = start + size
        if rel + size > sect_size or end > len(data):
            lines.append(f"{name}: zero range out of section/file value=0x{value:x} rel={rel} size={size}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        data[start:end] = b"\0" * size
        lines.append(f"zeroed {name} {seg},{sect} value=0x{value:x} file_offset={start} size={size}")
    Path(dst).write_bytes(data)
    Path(log_path).write_text("\n".join(lines) + "\n")
    return 0


def zero_symbol_ranges(src, dst, ranges, log_path):
    data = bytearray(Path(src).read_bytes())
    sections = macho_sections(data)
    wanted = {name for name, _offset, _size in ranges}
    nm_out = output(["xcrun", "llvm-nm", "-nm", str(src)])
    nm_re = re.compile(r"^([0-9a-fA-F]+) \(([^,]+),([^)]+)\) .* ([^ ]+)$")
    found = {}
    for line in nm_out.splitlines():
        match = nm_re.match(line.strip())
        if not match:
            continue
        name = match.group(4)
        if name in wanted:
            found[name] = (int(match.group(1), 16), match.group(2), match.group(3))
    missing = sorted(wanted - set(found))
    lines = []
    if missing:
        lines.append("missing symbols: " + " ".join(missing))
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 44
    for name, offset, size in ranges:
        value, sym_seg, sym_sect = found[name]
        candidates = [s for s in sections if s[0] == sym_seg and s[1] == sym_sect and s[2] <= value < s[2] + s[3]]
        if not candidates:
            lines.append(f"{name}: no containing section for value=0x{value:x} {sym_seg},{sym_sect}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        seg, sect, addr, sect_size, file_offset = candidates[0]
        rel = value - addr
        start = file_offset + rel + offset
        end = start + size
        if offset < 0 or size <= 0 or rel + offset + size > sect_size or end > len(data):
            lines.append(f"{name}: zero range out of section/file value=0x{value:x} rel={rel} offset={offset} size={size}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return 2
        old = bytes(data[start:end])
        data[start:end] = b"\0" * size
        lines.append(f"zeroed {name}+{offset}:{offset + size} {seg},{sect} value=0x{value:x} file_offset={start} old={old.hex()}")
    Path(dst).write_bytes(data)
    Path(log_path).write_text("\n".join(lines) + "\n")
    return 0


def symbol_ranges(src, symbols, size, log_path):
    data = bytearray(Path(src).read_bytes())
    sections = macho_sections(data)
    wanted = set(symbols)
    nm_out = output(["xcrun", "llvm-nm", "-nm", str(src)])
    nm_re = re.compile(r"^([0-9a-fA-F]+) \(([^,]+),([^)]+)\) .* ([^ ]+)$")
    found = {}
    for line in nm_out.splitlines():
        match = nm_re.match(line.strip())
        if not match:
            continue
        name = match.group(4)
        if name in wanted:
            found[name] = (int(match.group(1), 16), match.group(2), match.group(3))
    missing = sorted(wanted - set(found))
    lines = []
    if missing:
        lines.append("missing symbols: " + " ".join(missing))
        Path(log_path).write_text("\n".join(lines) + "\n")
        return None, data, 44
    ranges = {}
    for name in symbols:
        value, sym_seg, sym_sect = found[name]
        candidates = [s for s in sections if s[0] == sym_seg and s[1] == sym_sect and s[2] <= value < s[2] + s[3]]
        if not candidates:
            lines.append(f"{name}: no containing section for value=0x{value:x} {sym_seg},{sym_sect}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return None, data, 2
        seg, sect, addr, sect_size, file_offset = candidates[0]
        rel = value - addr
        start = file_offset + rel
        end = start + size
        if rel + size > sect_size or end > len(data):
            lines.append(f"{name}: range out of section/file value=0x{value:x} rel={rel} size={size}")
            Path(log_path).write_text("\n".join(lines) + "\n")
            return None, data, 2
        ranges[name] = (start, end, value, seg, sect)
        lines.append(f"{name}: {seg},{sect} value=0x{value:x} file_offset={start} size={size} old={bytes(data[start:end]).hex()}")
    Path(log_path).write_text("\n".join(lines) + "\n")
    return ranges, data, 0


def transform_cpi01_pair(src, dst, s0, s1, mode, log_path):
    ranges, data, status = symbol_ranges(src, [s0, s1], 16, log_path)
    if status != 0:
        return status
    a0, b0, *_ = ranges[s0]
    a1, b1, *_ = ranges[s1]
    v0 = bytes(data[a0:b0])
    v1 = bytes(data[a1:b1])
    pair = v0 + v1
    if mode == "zero_full":
        new0 = b"\0" * 16
        new1 = b"\0" * 16
    elif mode == "swap_entries":
        new0, new1 = v1, v0
    elif mode == "reverse_pair":
        rev = pair[::-1]
        new0, new1 = rev[:16], rev[16:]
    elif mode == "reverse_each_entry":
        new0, new1 = v0[::-1], v1[::-1]
    elif mode == "swap_first_word":
        new0 = v1[:4] + v0[4:]
        new1 = v0[:4] + v1[4:]
    elif mode == "swap_last_word":
        new0 = v0[:12] + v1[12:]
        new1 = v1[:12] + v0[12:]
    elif mode == "duplicate_0":
        new0, new1 = v0, v0
    elif mode == "duplicate_1":
        new0, new1 = v1, v1
    elif mode == "both_ff":
        new0 = b"\xff" * 16
        new1 = b"\xff" * 16
    elif mode == "both_00_0f":
        new0 = bytes(range(16))
        new1 = bytes(range(16))
    elif mode == "zero_ff":
        new0 = b"\0" * 16
        new1 = b"\xff" * 16
    elif mode == "ff_zero":
        new0 = b"\xff" * 16
        new1 = b"\0" * 16
    elif mode == "duplicate_0_flip_s1_last":
        s1_mut = bytearray(v0)
        s1_mut[-1] ^= 1
        new0, new1 = v0, bytes(s1_mut)
    elif mode == "duplicate_1_flip_s0_last":
        s0_mut = bytearray(v1)
        s0_mut[-1] ^= 1
        new0, new1 = bytes(s0_mut), v1
    else:
        Path(log_path).write_text(f"unknown transform mode: {mode}\n")
        return 2
    data[a0:b0] = new0
    data[a1:b1] = new1
    with open(log_path, "a") as f:
        f.write(f"mode={mode}\n")
        f.write(f"{s0}: new={new0.hex()}\n")
        f.write(f"{s1}: new={new1.hex()}\n")
    Path(dst).write_bytes(data)
    return 0


def zero_section(src, dst, section_name, log_path):
    target_seg, target_sect = section_name.split(",", 1)
    data = bytearray(Path(src).read_bytes())
    found = False
    lines = []
    for seg, sect, _addr, size, file_offset in macho_sections(data):
        if seg == target_seg and sect == target_sect:
            data[file_offset:file_offset + size] = b"\0" * size
            lines.append(f"zeroed {section_name} offset={file_offset} size={size}")
            found = True
    if not found:
        lines.append(f"missing section {section_name}")
        Path(log_path).write_text("\n".join(lines) + "\n")
        return 44
    Path(dst).write_bytes(data)
    Path(log_path).write_text("\n".join(lines) + "\n")
    return 0


def symbols_with_prefix(src, prefix):
    if not prefix:
        return []
    nm_out = output(["xcrun", "llvm-nm", "-nm", str(src)])
    nm_re = re.compile(r"^([0-9a-fA-F]+) \(([^,]+),([^)]+)\) .* ([^ ]+)$")
    names = []
    for line in nm_out.splitlines():
        match = nm_re.match(line.strip())
        if not match:
            continue
        name = match.group(4)
        seg = match.group(2)
        sect = match.group(3)
        if name.startswith(prefix) and seg == "__TEXT" and sect == "__literal16":
            names.append(name)
    return sorted(names, key=lambda s: [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", s)])


def cpi_subsets(prefix, symbols, mode):
    if not symbols:
        return []
    n = len(symbols)
    if mode in ("cpi01_words", "cpi01_asym", "cpi01_omit", "cpi01_byte_omit", "cpi01_permute", "cpi012_equal_pairs", "cpi01_symbol_names", "cpi01_nlists", "cpi01_relocs", "cpi01_reloc_singles", "cpi01_reloc_pairs", "cpi01_reloc_pair_sweep", "cpi01_reloc_pair_mixed", "cpi01_reloc_addr"):
        return []
    if mode == "q1_detail":
        q1_hi = (n + 3) // 4
        q1 = symbols[:q1_hi]
        cuts = [
            ("q1", 0, q1_hi),
            ("q1_left", 0, min(5, q1_hi)),
            ("q1_right", min(5, q1_hi), q1_hi),
            ("q1_0_2", 0, min(3, q1_hi)),
            ("q1_3_4", min(3, q1_hi), min(5, q1_hi)),
            ("q1_5_6", min(5, q1_hi), min(7, q1_hi)),
            ("q1_7_8", min(7, q1_hi), q1_hi),
        ]
        out = []
        seen = set()
        for label, lo, hi in cuts:
            subset = q1[lo:hi]
            key = tuple(subset)
            if subset and key not in seen:
                seen.add(key)
                out.append((f"zero_{prefix}{label}", subset))
        for idx in [0, 3, 4, 5, 6, 7, 8]:
            if idx < len(q1):
                sym = q1[idx]
                out.append((f"zero_{sym}", [sym]))
        return out

    if mode == "q1_triplet":
        q1_hi = min(3, (n + 3) // 4)
        q1 = symbols[:q1_hi]
        cuts = [
            ("q1_0_1", [0, 1]),
            ("q1_0_2", [0, 2]),
            ("q1_1_2", [1, 2]),
            ("q1_0_1_2", [0, 1, 2]),
        ]
        out = []
        for label, indexes in cuts:
            subset = [q1[i] for i in indexes if i < len(q1)]
            if subset:
                out.append((f"zero_{prefix}{label}", subset))
        return out

    cuts = {
        "first_half": (0, (n + 1) // 2),
        "second_half": ((n + 1) // 2, n),
        "q1": (0, (n + 3) // 4),
        "q2": ((n + 3) // 4, (n + 1) // 2),
        "q3": ((n + 1) // 2, (3 * n + 3) // 4),
        "q4": ((3 * n + 3) // 4, n),
    }
    out = []
    for label, (lo, hi) in cuts.items():
        subset = symbols[lo:hi]
        if subset:
            out.append((f"zero_{prefix}{label}", subset))
    out.append((f"zero_{prefix}all", symbols))
    return out


def cpi_range_subsets(prefix, symbols, mode):
    if mode not in ("cpi01_words", "cpi01_asym", "cpi01_omit", "cpi01_byte_omit") or len(symbols) < 2:
        return []
    s0 = symbols[0]
    s1 = symbols[1]
    out = [(f"zero_{prefix}cpi01_full", [(s0, 0, 16), (s1, 0, 16)])]
    pair_words = [(s0, 0, 4), (s0, 4, 4), (s0, 8, 4), (s0, 12, 4), (s1, 0, 4), (s1, 4, 4), (s1, 8, 4), (s1, 12, 4)]
    pair_halves = [(s0, 0, 8), (s0, 8, 8), (s1, 0, 8), (s1, 8, 8)]
    pair_bytes = [(s0, i, 1) for i in range(16)] + [(s1, i, 1) for i in range(16)]
    if mode == "cpi01_byte_omit":
        for idx, (name, offset, _size) in enumerate(pair_bytes):
            ranges = [r for j, r in enumerate(pair_bytes) if j != idx]
            out.append((f"zero_{prefix}cpi01_omit_{name}_b{offset}", ranges))
        return out
    if mode == "cpi01_omit":
        for idx, (name, offset, _size) in enumerate(pair_halves):
            ranges = [r for j, r in enumerate(pair_halves) if j != idx]
            out.append((f"zero_{prefix}cpi01_omit_{name}_h{offset // 8}", ranges))
        for idx, (name, offset, _size) in enumerate(pair_words):
            ranges = [r for j, r in enumerate(pair_words) if j != idx]
            out.append((f"zero_{prefix}cpi01_omit_{name}_w{offset // 4}", ranges))
        return out
    if mode == "cpi01_asym":
        for b_off in (0, 8):
            out.append((
                f"zero_{prefix}cpi01_s0full_s1h{b_off // 8}",
                [(s0, 0, 16), (s1, b_off, 8)],
            ))
        for a_off in (0, 8):
            out.append((
                f"zero_{prefix}cpi01_s1full_s0h{a_off // 8}",
                [(s1, 0, 16), (s0, a_off, 8)],
            ))
        for b_idx in range(4):
            out.append((
                f"zero_{prefix}cpi01_s0full_s1w{b_idx}",
                [(s0, 0, 16), (s1, b_idx * 4, 4)],
            ))
        for a_idx in range(4):
            out.append((
                f"zero_{prefix}cpi01_s1full_s0w{a_idx}",
                [(s1, 0, 16), (s0, a_idx * 4, 4)],
            ))
        return out
    for a_off in (0, 8):
        for b_off in (0, 8):
            out.append((
                f"zero_{prefix}cpi01_h{a_off // 8}{b_off // 8}",
                [(s0, a_off, 8), (s1, b_off, 8)],
            ))
    for a_idx in range(4):
        for b_idx in range(4):
            out.append((
                f"zero_{prefix}cpi01_w{a_idx}{b_idx}",
                [(s0, a_idx * 4, 4), (s1, b_idx * 4, 4)],
            ))
    return out


def cpi_pair_transforms(prefix, symbols, mode):
    if mode not in ("cpi01_permute", "cpi012_equal_pairs"):
        return []
    if mode == "cpi01_permute":
        if len(symbols) < 2:
            return []
        s0 = symbols[0]
        s1 = symbols[1]
        modes = [
            "zero_full",
            "swap_entries",
            "reverse_pair",
            "reverse_each_entry",
            "swap_first_word",
            "swap_last_word",
            "duplicate_0",
            "duplicate_1",
            "both_ff",
            "both_00_0f",
            "zero_ff",
            "ff_zero",
            "duplicate_0_flip_s1_last",
            "duplicate_1_flip_s0_last",
        ]
        return [(f"{prefix}cpi01_{m}", s0, s1, m) for m in modes]
    if len(symbols) < 3:
        return []
    modes = [
        "duplicate_0",
        "duplicate_1",
        "both_ff",
        "duplicate_0_flip_s1_last",
    ]
    pairs = [
        ("cpi01", symbols[0], symbols[1]),
        ("cpi02", symbols[0], symbols[2]),
        ("cpi12", symbols[1], symbols[2]),
    ]
    return [
        (f"{prefix}{pair_label}_{m}", left, right, m)
        for pair_label, left, right in pairs
        for m in modes
    ]


def cpi_symbol_name_transforms(prefix, symbols, mode):
    if mode != "cpi01_symbol_names" or len(symbols) < 3:
        return []
    s0, s1, s2 = symbols[0], symbols[1], symbols[2]
    transforms = [
        ("cpi0_rename", {s0: same_len_name(s0, "m")}),
        ("cpi1_rename", {s1: same_len_name(s1, "m")}),
        ("cpi2_rename", {s2: same_len_name(s2, "m")}),
        ("cpi01_rename_distinct", {s0: same_len_name(s0, "m"), s1: same_len_name(s1, "n")}),
        ("cpi01_swap_names", {s0: s1, s1: s0}),
        ("cpi01_equal_name0", {s1: s0}),
        ("cpi01_equal_name1", {s0: s1}),
        ("cpi12_equal_name1", {s2: s1}),
    ]
    return [(f"{prefix}{label}", mapping) for label, mapping in transforms]


def cpi_nlist_transforms(prefix, symbols, mode):
    if mode != "cpi01_nlists" or len(symbols) < 3:
        return []
    modes = [
        "swap_values_01",
        "equal_value0_01",
        "equal_value1_01",
        "equal_value1_12",
        "swap_entries_01",
        "duplicate_entry0_01",
        "duplicate_entry1_01",
        "swap_entries_12",
    ]
    return [(f"{prefix}cpi01_nlist_{m}", symbols[:3], m) for m in modes]


def cpi_reloc_transforms(prefix, symbols, mode):
    if mode not in ("cpi01_relocs", "cpi01_reloc_singles", "cpi01_reloc_pairs", "cpi01_reloc_pair_sweep", "cpi01_reloc_pair_mixed", "cpi01_reloc_addr") or len(symbols) < 3:
        return []
    if mode == "cpi01_reloc_addr":
        modes = [
            "addrswap_1_3_0",
            "addrswap_1_3_1",
            "addrswap_1_3_2",
            "addrswap_1_3_10",
            "addrswap_1_4_5",
            "addrswap_1_4_6",
            "addrswap_1_4_7",
            "addrswap_1_4_11",
            "addrswap_1_3_4",
            "addrdup_1_3from0",
            "addrdup_1_3from1",
            "addrdup_1_3from2",
            "addrdup_1_3from10",
            "addrdup_1_4from5",
            "addrdup_1_4from6",
            "addrdup_1_4from7",
            "addrdup_1_4from11",
            "addrdup_1_3from0_4from5",
            "addrdup_1_3from10_4from11",
        ]
        return [(f"{prefix}cpi01_reloc_{m}", symbols[:3], m) for m in modes]
    if mode == "cpi01_reloc_pair_mixed":
        max_dst = min(5, len(symbols) - 1)
        subset = symbols[:max_dst + 1]
        out = []
        for dst3 in range(max_dst + 1):
            for dst4 in range(max_dst + 1):
                mode_name = f"map_1_3to{dst3}_4to{dst4}"
                out.append((f"{prefix}cpi01_reloc_{mode_name}", subset, mode_name))
        return out
    if mode == "cpi01_reloc_pair_sweep":
        max_dst = min(15, len(symbols) - 1)
        subset = symbols[:max_dst + 1]
        return [
            (f"{prefix}cpi01_reloc_set_1_to_{dst}_3_4", subset, f"set_1_to_{dst}_3_4")
            for dst in range(max_dst + 1)
        ]
    if mode == "cpi01_reloc_pairs":
        ordinal_modes = [
            "set_1_to_0_3_4",
            "set_1_to_2_3_4",
            "set_1_to_0_0_1_2",
            "set_1_to_2_0_1_2",
            "set_1_to_0_5_6_7_8_9_10_11",
            "set_1_to_2_5_6_7_8_9_10_11",
            "except_1_to_0_3",
            "except_1_to_2_3",
            "except_1_to_0_4",
            "except_1_to_2_4",
            "except_1_to_0_3_4",
            "except_1_to_2_3_4",
        ]
        return [(f"{prefix}cpi01_reloc_{m}", symbols[:3], m) for m in ordinal_modes]
    if mode == "cpi01_reloc_singles":
        modes = [
            "nonnear_1_to_0",
            "nonnear_1_to_2",
        ]
        modes.extend(f"single_1_to_0_{i}" for i in range(12))
        modes.extend(f"single_1_to_2_{i}" for i in range(12))
        return [(f"{prefix}cpi01_reloc_{m}", symbols[:3], m) for m in modes]
    modes = [
        "all_1_to_0",
        "all_0_to_1",
        "all_2_to_1",
        "all_1_to_2",
        "all_2_to_0",
        "near_1_to_0",
        "near_1_to_2",
        "near_2_to_1",
        "near_2_to_0",
        "early_0_to_1",
    ]
    return [(f"{prefix}cpi01_reloc_{m}", symbols[:3], m) for m in modes]


def add_hex(a, b):
    return int(a, 16) + int(b, 16)


def macho_bytes_at_addr(path, addr, size):
    data = Path(path).read_bytes()
    for seg, sect, sect_addr, sect_size, file_offset in macho_sections(data):
        if sect_addr <= addr and addr + size <= sect_addr + sect_size:
            off = file_offset + (addr - sect_addr)
            return bytes(data[off:off + size]), seg, sect, off
    return None, None, None, None


def target_line(path, target_hash, target_offset_hex, out_dir, prefix, developer_dir, compact):
    nm_path = out_dir / f"{prefix}.nm.txt"
    nm_text = output(["nm", "-nm", str(path)])
    if not compact:
        nm_path.write_text(nm_text + "\n")
    symbol_addr = None
    for line in nm_text.splitlines():
        if target_hash in line:
            symbol_addr = int(line.split()[0], 16)
            break
    if symbol_addr is None:
        return "missing"
    target = add_hex(hex(symbol_addr), target_offset_hex)
    raw, seg, sect, file_offset = macho_bytes_at_addr(path, target, 4)
    if raw is None:
        return f"{target:x}: missing-section"
    byte_text = " ".join(f"{b:02x}" for b in raw)
    word, = struct.unpack("<I", raw)
    direct_line = f"{target:x}: {byte_text} word=0x{word:08x} ({seg},{sect}) file_offset={file_offset}"
    if compact:
        return direct_line
    start_addr = hex(max(0, target - 0x40))
    stop_addr = hex(target + 0x50)
    dis_path = out_dir / f"{prefix}.disassembly.txt"
    env = os.environ.copy()
    env["DEVELOPER_DIR"] = developer_dir
    proc = subprocess.run(
        [
            "xcrun", "llvm-objdump",
            "--macho", "--arch=arm64", "--demangle", "--disassemble",
            "--start-address", start_addr,
            "--stop-address", stop_addr,
            str(path),
        ],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if not compact:
        dis_path.write_text(proc.stdout)
    lines = proc.stdout.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"\s*([0-9a-fA-F]+):\s*(.*)", line)
        if m and int(m.group(1), 16) == target:
            lo = max(0, i - 10)
            hi = min(len(lines), i + 11)
            (out_dir / f"{prefix}.target-window.txt").write_text("\n".join(lines[lo:hi]) + "\n")
            return f"{direct_line} | {line.strip()}"
    return direct_line


def find_target_object(target_root, target_hash, preferred_prefix, out_dir, compact):
    candidates = []
    for obj in sorted(Path(target_root).rglob("*.o")):
        proc = subprocess.run(["nm", "-nm", str(obj)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        nm_text = proc.stdout
        if not compact:
            (out_dir / f"{obj.name}.nm.txt").write_text(nm_text)
        if target_hash in nm_text:
            candidates.append(obj)
    (out_dir / "object-candidates.txt").write_text("\n".join(str(c) for c in candidates) + ("\n" if candidates else ""))
    for obj in candidates:
        if obj.name.startswith(preferred_prefix):
            return obj
    return candidates[0] if candidates else None


def parse_extra_link_variants(spec):
    variants = []
    for item in spec.split(";"):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            label, args = item.split(":", 1)
            link_args = [a for a in args.split(",") if a]
        else:
            label = item
            link_args = []
        if not re.match(r"^[A-Za-z0-9_.-]+$", label):
            raise ValueError(f"unsafe link variant label: {label!r}")
        variants.append((label, link_args))
    return variants


def link_object(object_path, variant, link_label, link_args, cfg, out_dir):
    link_dir = out_dir / variant / link_label
    link_dir.mkdir(parents=True, exist_ok=True)
    bin_path = link_dir / f"test.{variant}.{link_label}"
    map_path = link_dir / f"{bin_path.name}.map"
    args = [
        "xcrun", "ld",
        "-demangle",
        "-dynamic",
        "-arch", "arm64",
        "-platform_version", "macos", "14.0.0", "14.0",
        "-syslibroot", cfg["sdkroot"],
        "-o", str(bin_path),
        "-L", str(Path(cfg["target_root"]) / "deps"),
        "-L", cfg["rustlib"],
        "-L", "/usr/local/lib",
        str(object_path),
        cfg["compiler_builtins"],
        "-liconv",
        "-lSystem",
        "-lc",
        "-lm",
        "-dead_strip",
    ]
    if not cfg["compact_artifacts"]:
        args += ["-map", str(map_path)]
    args += link_args
    (link_dir / "ld-command.txt").write_text("DEVELOPER_DIR={} {}\n".format(cfg["developer_dir"], " ".join(args)))
    env = os.environ.copy()
    env["DEVELOPER_DIR"] = cfg["developer_dir"]
    proc = subprocess.run(args, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (link_dir / "link.log").write_text(proc.stdout)
    (link_dir / "status.txt").write_text(str(proc.returncode) + "\n")
    return bin_path, proc.returncode, link_dir


def main():
    cfg = {
        "label": os.environ["PROBE_LABEL"],
        "target_feature_flags": os.environ.get("PROBE_TARGET_FEATURE_FLAGS", ""),
        "target_hash": os.environ["PROBE_TARGET_HASH"],
        "target_offset_hex": os.environ["PROBE_TARGET_OFFSET_HEX"],
        "preferred_object_prefix": os.environ["PROBE_PREFERRED_OBJECT_PREFIX"],
        "cargo_args": os.environ["PROBE_CARGO_ARGS"].split(),
        "expected_bytes": os.environ["PROBE_EXPECTED_BYTES"],
        "corrupt_bytes": os.environ["PROBE_CORRUPT_BYTES"],
        "near_literals": [s for s in os.environ["PROBE_NEAR_LITERALS"].split(",") if s],
        "cpi_prefix": os.environ.get("PROBE_CPI_PREFIX", ""),
        "cpi_subset_mode": os.environ.get("PROBE_CPI_SUBSET_MODE", "range"),
        "compact_artifacts": os.environ.get("PROBE_COMPACT_ARTIFACTS", "") == "1",
        "extra_link_variants": os.environ.get("PROBE_EXTRA_LD_VARIANTS", ""),
        "developer_dir": "/Applications/Xcode_15.0.1.app/Contents/Developer",
        "target_root": str(Path.cwd() / "target" / "release"),
    }
    out_dir = Path("neon-rej-diagnostics") / f"target-near-literal-zero-{os.environ['PROBE_ARTIFACT_SUFFIX']}"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = out_dir / "summary.md"
    rows = out_dir / "summary.rows.tsv"
    summary.write_text(f"# target-near literal zero probe\n\nLabel: `{cfg['label']}`\n\n")
    rows.write_text("case\tobject_variant\ttransform_status\tlink_variant\tlink_status\tobject_line\tfinal_line\tobject_expected_count\tvariant_expected_count\tfinal_expected_count\tfinal_corrupt_count\tobject_sha256\tvariant_sha256\tfinal_sha256\ttransform_log\n")

    with open(summary, "a") as f:
        f.write("## Toolchain\n\n```text\n")
        for cmd in (["sw_vers"], ["uname", "-a"], ["rustc", "+1.78.0", "--version"], ["cargo", "+1.78.0", "--version"]):
            proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            f.write("$ " + " ".join(cmd) + "\n" + proc.stdout)
        env = os.environ.copy()
        env["DEVELOPER_DIR"] = cfg["developer_dir"]
        for cmd in (["xcodebuild", "-version"], ["xcrun", "--find", "ld"], ["xcrun", "--show-sdk-path"], ["ld", "-v"]):
            proc = subprocess.run(cmd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            f.write("$ " + " ".join(cmd) + "\n" + proc.stdout)
        f.write("```\n\n")

    cfg["rustlib"] = output(["rustc", "+1.78.0", "--print", "target-libdir"])
    cfg["sdkroot"] = output(["xcrun", "--show-sdk-path"], env=dict(os.environ, DEVELOPER_DIR=cfg["developer_dir"]))
    compiler_builtins = sorted(Path(cfg["rustlib"]).glob("libcompiler_builtins-*.rlib"))
    if not compiler_builtins:
        raise SystemExit("missing compiler_builtins")
    cfg["compiler_builtins"] = str(compiler_builtins[0])

    rustflags = "-C save-temps"
    if cfg["target_feature_flags"]:
        rustflags += " " + cfg["target_feature_flags"]
    env = os.environ.copy()
    env["DEVELOPER_DIR"] = cfg["developer_dir"]
    env["RUSTFLAGS"] = rustflags
    build_log = out_dir / "build.log"
    print(f"::group::build {cfg['label']}", flush=True)
    print(f"RUSTFLAGS={rustflags}", flush=True)
    with open(build_log, "w") as f:
        proc = run(["cargo", "+1.78.0", "test"] + cfg["cargo_args"], env=env, stdout=f, stderr=subprocess.STDOUT)
    print(f"build status={proc.returncode}", flush=True)
    print("::endgroup::", flush=True)
    append(summary, f"## Build\n\n- RUSTFLAGS: `{rustflags}`\n- status: `{proc.returncode}`\n\n")
    if proc.returncode != 0:
        raise SystemExit(0)

    selected = find_target_object(cfg["target_root"], cfg["target_hash"], cfg["preferred_object_prefix"], out_dir, cfg["compact_artifacts"])
    append(summary, f"- selected object: `{selected}`\n\n")
    print(f"selected object={selected}", flush=True)
    if selected is None:
        raise SystemExit(0)

    link_variants = [
        ("ld_new_no_lto", []),
        ("ld_classic_no_lto", ["-ld_classic"]),
    ] + parse_extra_link_variants(cfg["extra_link_variants"])
    append(summary, "- link variants: `" + "`, `".join(label for label, _args in link_variants) + "`\n\n")

    variants = [("original", selected, 0, "copied original")]
    obj_dir = out_dir / "objects"
    obj_dir.mkdir(exist_ok=True)

    literal16 = obj_dir / "zero_literal16.o"
    status = zero_section(selected, literal16, "__TEXT,__literal16", obj_dir / "zero_literal16.log")
    variants.append(("zero_literal16", literal16, status, (obj_dir / "zero_literal16.log").read_text(errors="replace").strip()))

    for i, sym in enumerate(cfg["near_literals"]):
        dst = obj_dir / f"zero_near_literal_{i + 1}.o"
        log = obj_dir / f"zero_near_literal_{i + 1}.log"
        status = zero_symbols(selected, dst, [sym], 16, log)
        variants.append((f"zero_{sym}", dst, status, log.read_text(errors="replace").strip()))

    if len(cfg["near_literals"]) > 1:
        dst = obj_dir / "zero_near_literals_pair.o"
        log = obj_dir / "zero_near_literals_pair.log"
        status = zero_symbols(selected, dst, cfg["near_literals"], 16, log)
        variants.append(("zero_near_literals_pair", dst, status, log.read_text(errors="replace").strip()))

    cpi_symbols = symbols_with_prefix(selected, cfg["cpi_prefix"])
    if cpi_symbols:
        (obj_dir / "cpi-prefix-symbols.txt").write_text("\n".join(cpi_symbols) + "\n")
        for subset_label, subset_symbols in cpi_subsets(cfg["cpi_prefix"], cpi_symbols, cfg["cpi_subset_mode"]):
            dst = obj_dir / f"{subset_label}.o"
            log = obj_dir / f"{subset_label}.log"
            status = zero_symbols(selected, dst, subset_symbols, 16, log)
            variants.append((subset_label, dst, status, log.read_text(errors="replace").strip()))
        for subset_label, ranges in cpi_range_subsets(cfg["cpi_prefix"], cpi_symbols, cfg["cpi_subset_mode"]):
            dst = obj_dir / f"{subset_label}.o"
            log = obj_dir / f"{subset_label}.log"
            status = zero_symbol_ranges(selected, dst, ranges, log)
            variants.append((subset_label, dst, status, log.read_text(errors="replace").strip()))
        for subset_label, s0, s1, mode in cpi_pair_transforms(cfg["cpi_prefix"], cpi_symbols, cfg["cpi_subset_mode"]):
            dst = obj_dir / f"{subset_label}.o"
            log = obj_dir / f"{subset_label}.log"
            status = transform_cpi01_pair(selected, dst, s0, s1, mode, log)
            variants.append((subset_label, dst, status, log.read_text(errors="replace").strip()))
        for subset_label, mapping in cpi_symbol_name_transforms(cfg["cpi_prefix"], cpi_symbols, cfg["cpi_subset_mode"]):
            dst = obj_dir / f"{subset_label}.o"
            log = obj_dir / f"{subset_label}.log"
            status = rename_symbols_same_length(selected, dst, mapping, log)
            variants.append((subset_label, dst, status, log.read_text(errors="replace").strip()))
        for subset_label, subset_symbols, mode in cpi_nlist_transforms(cfg["cpi_prefix"], cpi_symbols, cfg["cpi_subset_mode"]):
            dst = obj_dir / f"{subset_label}.o"
            log = obj_dir / f"{subset_label}.log"
            status = transform_cpi_nlists(selected, dst, subset_symbols, mode, log)
            variants.append((subset_label, dst, status, log.read_text(errors="replace").strip()))
        for subset_label, subset_symbols, mode in cpi_reloc_transforms(cfg["cpi_prefix"], cpi_symbols, cfg["cpi_subset_mode"]):
            dst = obj_dir / f"{subset_label}.o"
            log = obj_dir / f"{subset_label}.log"
            status = transform_cpi_text_relocs(
                selected,
                dst,
                subset_symbols,
                mode,
                cfg["target_hash"],
                cfg["target_offset_hex"],
                log,
            )
            variants.append((subset_label, dst, status, log.read_text(errors="replace").strip()))

    print(f"prepared variants={len(variants)} mode={cfg['cpi_subset_mode']}", flush=True)
    for variant, obj_path, transform_status, transform_log in variants:
        print(f"::group::variant {variant}", flush=True)
        print(f"transform status={transform_status}", flush=True)
        if transform_status != 0 or not Path(obj_path).exists():
            append(rows, f"{cfg['label']}\t{variant}\t{transform_status}\tNA\tNA\tmissing\tmissing\tNA\tNA\tNA\tNA\tNA\tNA\tNA\t{transform_log}\n")
            print("missing transformed object", flush=True)
            print("::endgroup::", flush=True)
            continue
        obj_line = target_line(obj_path, cfg["target_hash"], cfg["target_offset_hex"], out_dir, f"{variant}.object", cfg["developer_dir"], cfg["compact_artifacts"])
        print(f"object target={obj_line}", flush=True)
        obj_expected = str(count_bytes(selected, cfg["expected_bytes"]))
        variant_expected = str(count_bytes(obj_path, cfg["expected_bytes"]))
        obj_hash = sha256(selected)
        variant_hash = sha256(obj_path)
        for link_variant, link_args in link_variants:
            print(f"linking {link_variant}", flush=True)
            bin_path, link_status, _link_dir = link_object(obj_path, variant, link_variant, link_args, cfg, out_dir)
            final_line = "missing"
            final_expected = "NA"
            final_corrupt = "NA"
            final_hash = "NA"
            if link_status == 0:
                final_line = target_line(bin_path, cfg["target_hash"], cfg["target_offset_hex"], out_dir, f"{variant}.{link_variant}.final", cfg["developer_dir"], cfg["compact_artifacts"])
                final_expected = str(count_bytes(bin_path, cfg["expected_bytes"]))
                final_corrupt = str(count_bytes(bin_path, cfg["corrupt_bytes"]))
                final_hash = sha256(bin_path)
                if cfg["compact_artifacts"]:
                    bin_path.unlink(missing_ok=True)
            print(f"{link_variant} status={link_status} target={final_line}", flush=True)
            append(rows, "\t".join([
                cfg["label"],
                variant,
                str(transform_status),
                link_variant,
                str(link_status),
                obj_line.replace("\t", " "),
                final_line.replace("\t", " "),
                obj_expected,
                variant_expected,
                final_expected,
                final_corrupt,
                obj_hash,
                variant_hash,
                final_hash,
                transform_log.replace("\t", " ").replace("\n", "; "),
            ]) + "\n")
        if cfg["compact_artifacts"] and obj_path != selected:
            Path(obj_path).unlink(missing_ok=True)
        print("::endgroup::", flush=True)

    append(summary, "## Rows\n\n```tsv\n" + rows.read_text() + "```\n")


if __name__ == "__main__":
    main()
