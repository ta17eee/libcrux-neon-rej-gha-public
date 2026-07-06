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
        if off + 8 > len(data):
            raise ValueError("truncated load command")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            raise ValueError(f"bad load command size at 0x{off:x}")
        yield off, cmd, cmdsize
        off += cmdsize


def sections(data):
    result = []
    ordinal = 1
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
            flags, reserved1, reserved2, reserved3 = struct.unpack_from("<IIII", data, sec_off + 64)
            result.append(
                {
                    "ordinal": ordinal,
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
                }
            )
            ordinal += 1
            sec_off += 80
    return result


def symtab_command(data):
    for off, cmd, _cmdsize in load_commands(data):
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
            return symoff, nsyms, stroff, strsize
    return None


def symbols(data):
    symcmd = symtab_command(data)
    if symcmd is None:
        return []
    symoff, nsyms, stroff, strsize = symcmd
    result = []
    for idx in range(nsyms):
        entry_off = symoff + idx * 16
        if entry_off + 16 > len(data):
            break
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


def read_word(data, sec, sec_addr):
    rel = sec_addr - sec["addr"]
    if rel < 0 or rel + 4 > sec["size"]:
        return None
    file_off = sec["offset"] + rel
    if file_off < 0 or file_off + 4 > len(data):
        return None
    word, = struct.unpack_from("<I", data, file_off)
    return word


def parse_relocations(data, sec, syms, sects):
    result = []
    for idx in range(sec["nreloc"]):
        off = sec["reloff"] + idx * 8
        if off + 8 > len(data):
            break
        r_address, r_word = struct.unpack_from("<II", data, off)
        scattered = (r_address >> 31) & 1
        if scattered:
            # scattered_relocation_info has a different bit layout. It should
            # not be common for arm64 external relocations, but record it
            # explicitly instead of silently mis-decoding it.
            r_type = (r_address >> 24) & 0xF
            address = r_address & 0x00FFFFFF
            entry = {
                "index": idx,
                "address": address,
                "section_addr": sec["addr"] + address,
                "scattered": 1,
                "type": r_type,
                "type_name": ARM64_RELOC_TYPES.get(r_type, f"type{r_type}"),
                "raw_address": r_address,
                "raw_word": r_word,
                "symbolnum": None,
                "symbol_name": "",
                "symbol_value": None,
                "pcrel": None,
                "length": None,
                "extern": None,
                "word": read_word(data, sec, sec["addr"] + address),
            }
        else:
            bits = relocation_kind(r_word)
            symbol_name = ""
            symbol_value = None
            if bits["extern"] and bits["symbolnum"] < len(syms):
                sym = syms[bits["symbolnum"]]
                symbol_name = sym["name"]
                symbol_value = sym["value"]
            elif not bits["extern"]:
                sec_ord = bits["symbolnum"]
                match = next((s for s in sects if s["ordinal"] == sec_ord), None)
                symbol_name = f"section:{match['seg']},{match['sect']}" if match else f"section:{sec_ord}"
            entry = {
                "index": idx,
                "address": r_address,
                "section_addr": sec["addr"] + r_address,
                "scattered": 0,
                "type": bits["type"],
                "type_name": ARM64_RELOC_TYPES.get(bits["type"], f"type{bits['type']}"),
                "raw_address": r_address,
                "raw_word": r_word,
                "symbolnum": bits["symbolnum"],
                "symbol_name": symbol_name,
                "symbol_value": symbol_value,
                "pcrel": bits["pcrel"],
                "length": bits["length"],
                "extern": bits["extern"],
                "word": read_word(data, sec, sec["addr"] + r_address),
            }
        result.append(entry)
    return result


def find_context_match(scan, object_path):
    object_path = str(object_path)
    obj_name = Path(object_path).name
    for entry in scan["interesting_files"]:
        if "Mach-O 64-bit object" not in entry.get("kind", ""):
            continue
        path = entry.get("path", "")
        if path == object_path or Path(path).name == obj_name:
            matches = entry.get("wildcard_context_matches", [])
            if matches:
                return matches[0]
    for entry in scan["interesting_files"]:
        if "Mach-O 64-bit object" in entry.get("kind", ""):
            matches = entry.get("wildcard_context_matches", [])
            if matches:
                return matches[0]
    raise ValueError("no object wildcard context match in scan JSON")


def parse_intish(value):
    if isinstance(value, int):
        return value
    return int(value, 16 if isinstance(value, str) and value.startswith("0x") else 10)


def section_for_file_offset(sects, file_off):
    for sec in sects:
        if sec["offset"] <= file_off < sec["offset"] + sec["size"]:
            return sec
    return None


def reg_summary(word, reloc_type):
    if word is None:
        return ""
    if reloc_type == 3:  # ADRP PAGE21
        return f"Rd=x{word & 0x1f}"
    if reloc_type == 4:  # PAGEOFF12 consumer, commonly LDR/ADD
        return f"Rn=x{(word >> 5) & 0x1f} Rt/Rd={word & 0x1f} imm12={(word >> 10) & 0xfff}"
    if reloc_type == 2:
        imm26 = word & 0x03FFFFFF
        if imm26 & (1 << 25):
            imm26 -= 1 << 26
        return f"imm26={imm26} byte_delta={imm26 * 4}"
    return ""


def fmt_word(word):
    return "None" if word is None else f"0x{word:08x}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--object", required=True, type=Path)
    parser.add_argument("--scan-json", required=True, type=Path)
    parser.add_argument("--out-json", required=True, type=Path)
    parser.add_argument("--out-md", required=True, type=Path)
    parser.add_argument("--window", default="0x3000")
    args = parser.parse_args()

    data = args.object.read_bytes()
    scan = json.loads(args.scan_json.read_text())
    sects = sections(data)
    syms = symbols(data)
    match = find_context_match(scan, args.object)
    context_file_off = parse_intish(match["offset"])
    bad_index = int(scan["bad_index"])
    victim_file_off = context_file_off + bad_index * 4
    sec = section_for_file_offset(sects, victim_file_off)
    if sec is None:
        raise SystemExit(f"victim file offset 0x{victim_file_off:x} is outside all sections")
    victim_addr = sec["addr"] + (victim_file_off - sec["offset"])
    text = next((s for s in sects if s["seg"] == "__TEXT" and s["sect"] == "__text"), sec)
    relocs = parse_relocations(data, text, syms, sects)
    window = int(args.window, 0)
    near = [
        r for r in relocs
        if victim_addr - window <= r["section_addr"] <= victim_addr + window
    ]
    near.sort(key=lambda r: (r["section_addr"], r["index"]))

    before_page21 = [
        r for r in near
        if r["type"] == 3 and r["section_addr"] < victim_addr and r["symbol_name"]
    ]
    after_pageoff = [
        r for r in near
        if r["type"] == 4 and r["section_addr"] > victim_addr and r["symbol_name"]
    ]
    candidate_pairs = []
    for left in before_page21:
        for right in after_pageoff:
            if left["symbol_name"] != right["symbol_name"]:
                continue
            left_rd = left["word"] & 0x1F if left["word"] is not None else None
            right_rn = (right["word"] >> 5) & 0x1F if right["word"] is not None else None
            candidate_pairs.append(
                {
                    "page21_index": left["index"],
                    "page21_addr": left["section_addr"],
                    "page21_delta": left["section_addr"] - victim_addr,
                    "page21_word": left["word"],
                    "pageoff_index": right["index"],
                    "pageoff_addr": right["section_addr"],
                    "pageoff_delta": right["section_addr"] - victim_addr,
                    "pageoff_word": right["word"],
                    "symbol": left["symbol_name"],
                    "symbol_value": left["symbol_value"],
                    "matched_base_reg": left_rd == right_rn,
                    "page21_rd": left_rd,
                    "pageoff_rn": right_rn,
                }
            )

    result = {
        "object": str(args.object),
        "bad_word": scan["bad_word"],
        "bad_index": bad_index,
        "context_file_offset": f"0x{context_file_off:x}",
        "victim_file_offset": f"0x{victim_file_off:x}",
        "victim_section_addr": f"0x{victim_addr:x}",
        "victim_word": fmt_word(read_word(data, sec, victim_addr)),
        "section": sec,
        "text_section": text,
        "near_relocations": [
            {
                **r,
                "address": f"0x{r['address']:x}",
                "section_addr": f"0x{r['section_addr']:x}",
                "raw_address": f"0x{r['raw_address']:08x}",
                "raw_word": f"0x{r['raw_word']:08x}",
                "symbol_value": None if r["symbol_value"] is None else f"0x{r['symbol_value']:x}",
                "word": fmt_word(r["word"]),
                "delta": r["section_addr"] - victim_addr,
                "reg_summary": reg_summary(r["word"], r["type"]),
            }
            for r in near
        ],
        "candidate_page21_pageoff_pairs": [
            {
                **p,
                "page21_addr": f"0x{p['page21_addr']:x}",
                "page21_word": fmt_word(p["page21_word"]),
                "pageoff_addr": f"0x{p['pageoff_addr']:x}",
                "pageoff_word": fmt_word(p["pageoff_word"]),
                "symbol_value": None if p["symbol_value"] is None else f"0x{p['symbol_value']:x}",
            }
            for p in candidate_pairs
        ],
    }

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    lines = []
    lines.append("# PR287 relocation context")
    lines.append("")
    lines.append(f"Object: `{args.object}`")
    lines.append(f"Bad word: `{scan['bad_word']}`")
    lines.append(f"Context file offset: `{result['context_file_offset']}`")
    lines.append(f"Victim file offset: `{result['victim_file_offset']}`")
    lines.append(f"Victim section address: `{result['victim_section_addr']}`")
    lines.append(f"Victim object word: `{result['victim_word']}`")
    lines.append("")
    lines.append("## Nearby Relocations")
    lines.append("")
    lines.append("| idx | delta | addr | type | sym | word | decoded |")
    lines.append("| ---: | ---: | --- | --- | --- | --- | --- |")
    for r in result["near_relocations"]:
        lines.append(
            f"| {r['index']} | {r['delta']:+#x} | `{r['section_addr']}` | "
            f"{r['type_name']} | `{r['symbol_name']}` | `{r['word']}` | "
            f"{r['reg_summary']} |"
        )
    lines.append("")
    lines.append("## PAGE21/PAGEOFF12 Same-Symbol Pairs")
    lines.append("")
    lines.append("| PAGE21 idx/delta | PAGEOFF12 idx/delta | sym | regs | words |")
    lines.append("| --- | --- | --- | --- | --- |")
    for p in result["candidate_page21_pageoff_pairs"]:
        regs = f"x{p['page21_rd']} -> x{p['pageoff_rn']} matched={p['matched_base_reg']}"
        words = f"{p['page21_word']} / {p['pageoff_word']}"
        lines.append(
            f"| {p['page21_index']} / {p['page21_delta']:+#x} | "
            f"{p['pageoff_index']} / {p['pageoff_delta']:+#x} | "
            f"`{p['symbol']}` | {regs} | `{words}` |"
        )
    args.out_md.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
