#!/usr/bin/env python3
import argparse
import json
import re
import struct
import subprocess
from pathlib import Path


WORD_RE = re.compile(r"0x[0-9a-fA-F]+:\s+((?:0x[0-9a-fA-F]{8}\s*)+)")
SUBCODE_RE = re.compile(r"subcode=0x([0-9a-fA-F]+)")


def u32le_words(data):
    return struct.unpack("<" + "I" * (len(data) // 4), data[: len(data) // 4 * 4])


def parse_lldb_words(path):
    text = path.read_text(errors="replace")
    subcodes = [int(m.group(1), 16) for m in SUBCODE_RE.finditer(text)]
    memory_words = []
    for line in text.splitlines():
        m = WORD_RE.search(line)
        if not m:
            continue
        for word in re.findall(r"0x([0-9a-fA-F]{8})", m.group(1)):
            memory_words.append(int(word, 16))
    if not memory_words:
        raise SystemExit(f"no lldb memory-read words found in {path}")
    bad_word = subcodes[-1] if subcodes else None
    if bad_word is None:
        for word in memory_words:
            # The observed bad word is not decoded by LLDB. Prefer a word that
            # appears once in the captured window if no subcode was emitted.
            if memory_words.count(word) == 1:
                bad_word = word
                break
    if bad_word is None:
        raise SystemExit("could not infer bad word")
    try:
        bad_index = memory_words.index(bad_word)
    except ValueError as exc:
        raise SystemExit(f"bad word 0x{bad_word:08x} not present in memory window") from exc
    return text, memory_words, bad_word, bad_index


def parse_pattern_words(pattern_text, bad_word_text, bad_index_text):
    words = [int(word, 16) for word in re.findall(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{8}", pattern_text)]
    if not words:
        raise SystemExit("--pattern-words did not contain any words")
    bad_word = int(bad_word_text, 16) if bad_word_text else None
    if bad_index_text is not None:
        bad_index = int(bad_index_text, 0)
        if bad_index < 0 or bad_index >= len(words):
            raise SystemExit(f"--bad-index {bad_index} outside pattern length {len(words)}")
        if bad_word is None:
            bad_word = words[bad_index]
    elif bad_word is not None:
        try:
            bad_index = words.index(bad_word)
        except ValueError as exc:
            raise SystemExit(f"--bad-word 0x{bad_word:08x} not present in pattern") from exc
    else:
        raise SystemExit("pattern mode requires --bad-word or --bad-index")
    return "", words, bad_word, bad_index


def file_description(path):
    try:
        return subprocess.run(
            ["file", str(path)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ).stdout.strip()
    except OSError as exc:
        return f"file(1) failed: {exc}"


def scan_file(path, pattern_words, wildcard_index, bad_word):
    data = path.read_bytes()
    words = u32le_words(data)
    pattern_len = len(pattern_words)
    matches = []
    exact_offsets = []

    for idx, word in enumerate(words):
        if word == bad_word:
            exact_offsets.append(idx * 4)

    if len(words) >= pattern_len:
        for start in range(0, len(words) - pattern_len + 1):
            ok = True
            for off, expected in enumerate(pattern_words):
                if off == wildcard_index:
                    continue
                if words[start + off] != expected:
                    ok = False
                    break
            if ok:
                matches.append(
                    {
                        "offset": start * 4,
                        "wildcard_word": f"0x{words[start + wildcard_index]:08x}",
                        "context": [f"0x{w:08x}" for w in words[start : start + pattern_len]],
                    }
                )
    return exact_offsets, matches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--bin", required=True, type=Path)
    parser.add_argument("--lldb-log", type=Path)
    parser.add_argument("--pattern-words")
    parser.add_argument("--bad-word")
    parser.add_argument("--bad-index")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    if args.pattern_words:
        lldb_text, pattern_words, bad_word, bad_index = parse_pattern_words(
            args.pattern_words,
            args.bad_word,
            args.bad_index,
        )
    elif args.lldb_log:
        lldb_text, pattern_words, bad_word, bad_index = parse_lldb_words(args.lldb_log)
    else:
        raise SystemExit("either --lldb-log or --pattern-words is required")
    candidates = [p for p in args.root.rglob("*") if p.is_file()]
    # Ensure the final binary is scanned even if it is outside the candidate
    # root or appears through a different path spelling.
    if args.bin.is_file() and args.bin not in candidates:
        candidates.append(args.bin)

    interesting = []
    for path in candidates:
        try:
            exact_offsets, matches = scan_file(path, pattern_words, bad_index, bad_word)
        except OSError:
            continue
        if exact_offsets or matches:
            interesting.append(
                {
                    "path": str(path),
                    "kind": file_description(path),
                    "exact_bad_word_offsets": [f"0x{o:x}" for o in exact_offsets[:32]],
                    "exact_bad_word_count": len(exact_offsets),
                    "wildcard_context_matches": matches[:16],
                    "wildcard_context_match_count": len(matches),
                }
            )

    result = {
        "bad_word": f"0x{bad_word:08x}",
        "bad_index": bad_index,
        "pattern_words": [f"0x{w:08x}" for w in pattern_words],
        "final_binary": str(args.bin),
        "lldb_log": "" if args.lldb_log is None else str(args.lldb_log),
        "interesting_files": interesting,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    print(f"bad_word=0x{bad_word:08x}")
    print(f"bad_index={bad_index}")
    print("pattern_words=" + " ".join(f"0x{w:08x}" for w in pattern_words))
    print(f"interesting_file_count={len(interesting)}")
    for entry in interesting:
        print(f"FILE {entry['path']}")
        print(f"  {entry['kind']}")
        print(
            "  exact_bad_word_count="
            f"{entry['exact_bad_word_count']} offsets={entry['exact_bad_word_offsets']}"
        )
        print(f"  wildcard_context_match_count={entry['wildcard_context_match_count']}")
        for match in entry["wildcard_context_matches"][:4]:
            print(
                f"    match offset=0x{match['offset']:x} "
                f"wildcard_word={match['wildcard_word']}"
            )


if __name__ == "__main__":
    main()
