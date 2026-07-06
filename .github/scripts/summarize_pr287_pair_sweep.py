#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


SYMBOL_RE = re.compile(r"lCPI233_(\d+)$")


def load_json(path):
    return json.loads(path.read_text())


def first_executable_entry(scan):
    entries = [
        entry
        for entry in scan.get("interesting_files", [])
        if "Mach-O 64-bit executable" in entry.get("kind", "")
    ]
    if not entries:
        return None
    # scan_pr287_bad_word.py can report the same binary via relative and
    # absolute spellings. Prefer the shorter path for stable summaries.
    return sorted(entries, key=lambda entry: len(entry.get("path", "")))[0]


def wildcard_word(entry):
    matches = entry.get("wildcard_context_matches", []) if entry else []
    if not matches:
        return None
    return matches[0]["wildcard_word"]


def payload_bits(word_text):
    if not word_text:
        return None
    return (int(word_text, 16) >> 10) & 0xFFF


def target_symbol(variant_name, retarget):
    if variant_name == "original":
        return "lCPI233_2"
    changes = retarget.get("changes", [])
    if not changes:
        return ""
    names = {change["new_symbol_name"] for change in changes}
    if len(names) == 1:
        return names.pop()
    return ",".join(sorted(names))


def target_value(retarget):
    changes = retarget.get("changes", [])
    values = {change["new_symbol_value"] for change in changes}
    if len(values) == 1:
        return values.pop()
    return "" if not values else ",".join(sorted(values))


def symbol_number(name):
    match = SYMBOL_RE.search(name)
    return int(match.group(1)) if match else -1


def summarize(root):
    rows = []
    for variant_dir in sorted(root.iterdir()):
        if not variant_dir.is_dir():
            continue
        scan_path = variant_dir / "scan.json"
        retarget_path = variant_dir / "retarget.json"
        meta_path = variant_dir / "meta.log"
        if not scan_path.exists() or not retarget_path.exists():
            continue
        scan = load_json(scan_path)
        retarget = load_json(retarget_path)
        entry = first_executable_entry(scan)
        word = wildcard_word(entry)
        symbol = target_symbol(variant_dir.name, retarget)
        row = {
            "variant": variant_dir.name,
            "target_symbol": symbol,
            "target_symbol_number": symbol_number(symbol),
            "target_symbol_value": target_value(retarget),
            "final_context_word": word,
            "payload_bits_21_10": None if word is None else f"0x{payload_bits(word):03x}",
            "exact_bad_word_count": None if entry is None else entry.get("exact_bad_word_count"),
            "wildcard_context_match_count": None if entry is None else entry.get("wildcard_context_match_count"),
            "manual_link_status": "",
        }
        if meta_path.exists():
            for line in meta_path.read_text(errors="replace").splitlines():
                if line.startswith("manual_link_status="):
                    row["manual_link_status"] = line.split("=", 1)[1]
        rows.append(row)
    return sorted(rows, key=lambda row: (row["target_symbol_number"], row["variant"]))


def write_markdown(rows, path):
    lines = [
        "# PR287 pair retarget sweep summary",
        "",
        "| Variant | Target | n_value | Final word | bits[21:10] | Exact bad count | Wildcard matches | Link status |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| {variant} | `{target_symbol}` | `{target_symbol_value}` | `{final_context_word}` | "
            "`{payload_bits_21_10}` | {exact_bad_word_count} | {wildcard_context_match_count} | "
            "{manual_link_status} |".format(**row)
        )
    lines.append("")
    path.write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variants-root", required=True, type=Path)
    parser.add_argument("--out-json", required=True, type=Path)
    parser.add_argument("--out-md", required=True, type=Path)
    args = parser.parse_args()

    rows = summarize(args.variants_root)
    result = {"variants_root": str(args.variants_root), "rows": rows}
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    write_markdown(rows, args.out_md)
    print(args.out_md.read_text())


if __name__ == "__main__":
    main()
