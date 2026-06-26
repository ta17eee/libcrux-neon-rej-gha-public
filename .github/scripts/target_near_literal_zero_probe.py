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
    if mode in ("cpi01_words", "cpi01_asym", "cpi01_omit", "cpi01_byte_omit"):
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


def add_hex(a, b):
    return int(a, 16) + int(b, 16)


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
    dis_path = out_dir / f"{prefix}.disassembly.txt"
    env = os.environ.copy()
    env["DEVELOPER_DIR"] = developer_dir
    proc = subprocess.run(
        ["xcrun", "llvm-objdump", "--macho", "--arch=arm64", "--demangle", "--disassemble", str(path)],
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
            return line.strip()
    return "missing"


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


def link_object(object_path, variant, classic, cfg, out_dir):
    link_dir = out_dir / variant / ("ld_classic_no_lto" if classic else "ld_new_no_lto")
    link_dir.mkdir(parents=True, exist_ok=True)
    bin_path = link_dir / f"test.{variant}.{'classic' if classic else 'new'}"
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
    if classic:
        args.append("-ld_classic")
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
        for classic in (False, True):
            link_variant = "ld_classic_no_lto" if classic else "ld_new_no_lto"
            print(f"linking {link_variant}", flush=True)
            bin_path, link_status, _link_dir = link_object(obj_path, variant, classic, cfg, out_dir)
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
