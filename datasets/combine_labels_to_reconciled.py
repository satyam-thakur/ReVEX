#!/usr/bin/env python3
"""
Combine all JSON label files per image folder into a single JSON file per folder.

Input structure:
  datasets/vulnerability-match-labels-main/labels/<folder>/[*.json]

Output:
  datasets/reconciled_data/<folder>.json  # each is a JSON array of objects

The <folder> name is preserved exactly (e.g., anchore+test_images@sha256_08dbfa...).
"""
from __future__ import annotations
import json
from pathlib import Path
import os
from typing import List, Any


def _long_path(p: Path) -> str:
    """Return a string path safe for Windows long paths.

    On Windows, prefix with '\\?\\' (or '\\?\\UNC\\' for UNC paths) to bypass MAX_PATH.
    On other OSes, return the normal string.
    """
    s = str(p)
    if os.name == 'nt':
        s = s.replace('/', '\\')
        if not s.startswith('\\\\?\\'):
            if s.startswith('\\\\'):  # UNC path \\server\share
                s = '\\\\?\\UNC\\' + s[2:]
            else:
                s = '\\\\?\\' + s
    return s


def collect_folder_items(folder: Path) -> List[Any]:
    items: List[Any] = []
    # Sort for deterministic output
    for f in sorted(folder.glob('*.json')):
        try:
            # Use long-path-safe open on Windows
            path_str = _long_path(f)
            with open(path_str, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
                items.append(data)
        except Exception as e:
            print(f"WARN: Skipping {f} due to error: {e}")
    return items


def main() -> None:
    base = Path(__file__).parent
    labels_dir = base / 'vulnerability-match-labels-main' / 'labels'
    out_dir = base / 'reconciled_data'
    out_dir.mkdir(parents=True, exist_ok=True)

    if not labels_dir.exists():
        print(f"ERROR: Labels directory not found: {labels_dir}")
        raise SystemExit(1)

    print(f"Scanning labels from: {labels_dir}")
    print(f"Writing reconciled outputs to: {out_dir}")

    total_folders = 0
    total_items = 0

    for sub in sorted(labels_dir.iterdir()):
        if not sub.is_dir():
            continue
        folder_name = sub.name  # preserve exactly
        items = collect_folder_items(sub)
        total_folders += 1
        total_items += len(items)

        out_path = out_dir / f"{folder_name}.json"
        try:
            out_path_str = _long_path(out_path)
            with open(out_path_str, 'w', encoding='utf-8') as out:
                json.dump(items, out, indent=2)
            print(f"- Wrote {len(items):4d} items -> {out_path.relative_to(base)}")
        except Exception as e:
            print(f"ERROR: Failed to write {out_path}: {e}")

    print(f"Done. Folders processed: {total_folders}, total items: {total_items}")


if __name__ == '__main__':
    main()
