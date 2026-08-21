#!/usr/bin/env python3
import argparse
import ast
import contextlib
import csv
import glob
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import IO, Any

csv.field_size_limit(sys.maxsize)


def _open_file(path: str, mode: str = "r") -> IO[Any]:
    return Path(path).open(mode, encoding="utf-8")


def _find_report_files(folder: str) -> list[str]:
    # glob.glob (unlike pathlib.Path.glob, pre-3.13) follows symlinked directories during "**"
    # recursion, which matters for combined-wave folders that symlink in other waves' groups.
    return glob.glob(f"**/{folder}/**/report_*.csv", recursive=True)


def deep_update[KeyType](mapping: dict[KeyType, Any], *updating_mappings: dict[KeyType, Any]) -> dict[KeyType, Any]:
    updated_mapping = mapping.copy()
    for updating_mapping in updating_mappings:
        for k, v in updating_mapping.items():
            if k in updated_mapping and isinstance(updated_mapping[k], dict):
                if not isinstance(v, dict):
                    continue
                updated_mapping[k] = deep_update(updated_mapping[k], v)
            else:
                updated_mapping[k] = v
    return updated_mapping


# Shape-groups larger than this are treated as a dynamically-keyed collection (e.g. one entry per
# antivirus engine or DNS record) rather than a handful of fixed named fields, and are collapsed
# down to a single representative sample.
DYNAMIC_MAP_THRESHOLD = 10


def _shape_key(value: Any) -> Any:
    if isinstance(value, dict):
        return ("dict", tuple(sorted((k, _shape_key(v)) for k, v in value.items())))
    if isinstance(value, list):
        return ("list",)
    return (type(value).__name__,)


def collapse_dynamic_maps(value: Any) -> Any:
    if isinstance(value, dict):
        collapsed = {k: collapse_dynamic_maps(v) for k, v in value.items()}
        groups: dict[Any, list[tuple[Any, Any]]] = defaultdict(list)
        for k, v in collapsed.items():
            groups[_shape_key(v)].append((k, v))

        result: dict[Any, Any] = {}
        for group in groups.values():
            if len(group) > DYNAMIC_MAP_THRESHOLD:
                first_key, first_value = group[0]
                result[first_key] = first_value
            else:
                result.update(group)
        return result
    if isinstance(value, list):
        return [collapse_dynamic_maps(v) for v in value]
    return value


VENDOR_RESPONSE_SUFFIX = "_response"


def group_vendor_fields(merged_fields: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    vendor: dict[str, Any] = {}
    for key, value in merged_fields.items():
        if key.endswith(VENDOR_RESPONSE_SUFFIX):
            vendor[key] = value
        else:
            result[key] = value
    if vendor:
        result["vendor"] = vendor
    return result


def _try_parse_json_string(value: str) -> dict[str, Any] | list[Any] | None:
    stripped = value.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        try:
            parsed = ast.literal_eval(stripped)
        except (ValueError, SyntaxError):
            return None
    return parsed if isinstance(parsed, (dict, list)) else None


def handle_key(key: str, value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        parsed = _try_parse_json_string(value)
        if parsed is not None:
            value = parsed
    all_fields: dict[str, Any] = defaultdict(dict)
    if isinstance(value, dict):
        for subkey, subvalue in value.items():
            all_fields[key] = deep_update(all_fields[key], handle_key(subkey, subvalue))
    elif isinstance(value, list):
        all_fields[key] = [handle_key(key, value[0])[key]] if len(value) > 0 else []
    else:
        all_fields[key] = type(value).__name__
    return all_fields


def process_file(file_path: str) -> dict[str, Any]:
    all_fields: dict[str, Any] = {}
    with _open_file(file_path) as f:
        for row in csv.DictReader(f):
            for key, value in row.items():
                parsed_value = value
                with contextlib.suppress(Exception):
                    parsed_value = ast.literal_eval(value)
                if parsed_value is None:
                    parsed_value = {}
                all_fields = deep_update(all_fields, handle_key(key, parsed_value))
    return all_fields


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--folder", help="Data folder", required=True)
    parser.add_argument(
        "-w",
        "--workers",
        help="Number of parallel worker processes (defaults to the number of CPU cores).",
        type=int,
        default=(os.cpu_count() or 11) - 4,
    )
    parser.add_argument(
        "-o", "--output", help="Output file", type=str, default="group_analysis_out_dir/group_available_fields.json"
    )
    return parser.parse_args()


def compile_fields(args: argparse.Namespace) -> None:
    all_files = _find_report_files(args.folder)
    if not all_files:
        print(f"No files found in folder {args.folder}.")
        sys.exit(1)
    file_num = len(all_files)
    print(f"Merging fields on {file_num} files:")

    merged_fields: dict[str, Any] = {}
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for idx, file_fields in enumerate(executor.map(process_file, all_files)):
            print(f"\r[{idx + 1}/{file_num}] Files", end=" ... ")
            merged_fields = deep_update(merged_fields, file_fields)
    print("\nMerged fields")

    merged_fields = collapse_dynamic_maps(merged_fields)
    merged_fields = group_vendor_fields(merged_fields)

    with _open_file(args.output, "w") as f:
        json.dump(merged_fields, f, indent=2)


if __name__ == "__main__":
    args = parse_args()
    args.output = args.folder + args.output if args.folder.endswith("/") else args.folder + "/" + args.output
    compile_fields(args)
