#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


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


def retarget_symbol(retarget):
    names = {change["new_symbol_name"] for change in retarget.get("changes", [])}
    if len(names) == 1:
        return names.pop()
    return "" if not names else ",".join(sorted(names))


def retarget_value(retarget):
    values = {change["new_symbol_value"] for change in retarget.get("changes", [])}
    if len(values) == 1:
        return values.pop()
    return "" if not values else ",".join(sorted(values))


def patched_value(patch):
    changes = patch.get("changes", [])
    if not changes:
        return ""
    values = {change["new_value"] for change in changes}
    if len(values) == 1:
        return values.pop()
    return ",".join(sorted(values))


def metadata_delta(patch):
    changes = patch.get("changes", [])
    if not changes:
        return ""
    parts = []
    for change in changes:
        fields = change.get("fields", [])
        if not fields:
            continue
        field_parts = []
        for field in fields:
            old_key = f"old_{field}"
            new_key = f"new_{field}"
            if old_key in change and new_key in change:
                field_parts.append(f"{field}:{change[old_key]}->{change[new_key]}")
        source = change.get("source_symbol_name", "")
        suffix = f" from {source}" if source else ""
        parts.append(",".join(field_parts) + suffix)
    return "; ".join(part for part in parts if part)


def summarize(root):
    rows = []
    for variant_dir in sorted(root.iterdir()):
        if not variant_dir.is_dir():
            continue
        scan_path = variant_dir / "scan.json"
        retarget_path = variant_dir / "retarget.json"
        patch_path = variant_dir / "symbol-patch.json"
        meta_path = variant_dir / "meta.log"
        if not retarget_path.exists():
            continue
        retarget = load_json(retarget_path)
        patch = load_json(patch_path) if patch_path.exists() else {"changes": []}
        scan = load_json(scan_path) if scan_path.exists() else {"interesting_files": []}
        entry = first_executable_entry(scan)
        word = wildcard_word(entry)
        row = {
            "variant": variant_dir.name,
            "target_symbol": retarget_symbol(retarget),
            "retarget_original_value": retarget_value(retarget),
            "patched_value": patched_value(patch),
            "effective_value": patched_value(patch) or retarget_value(retarget),
            "metadata_delta": metadata_delta(patch),
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
    return rows


def write_markdown(rows, path):
    lines = [
        "# PR287 n_value patch sweep summary",
        "",
        "| Variant | Target | Original n_value | Patched n_value | Effective n_value | Metadata delta | Final word | bits[21:10] | Exact bad count | Link status |",
        "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| {variant} | `{target_symbol}` | `{retarget_original_value}` | `{patched_value}` | "
            "`{effective_value}` | `{metadata_delta}` | `{final_context_word}` | `{payload_bits_21_10}` | "
            "{exact_bad_word_count} | {manual_link_status} |".format(**row)
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
