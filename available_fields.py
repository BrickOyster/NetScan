import asyncio
import argparse
import csv
import sys
import ast
import json
from collections import defaultdict
from typing import Any, Dict, TypeVar
from glob import glob

KeyType = TypeVar('KeyType')
csv.field_size_limit(sys.maxsize)


def deep_update(mapping: Dict[KeyType, Any], *updating_mappings: Dict[KeyType, Any]) -> Dict[KeyType, Any]:
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


async def producer(file_queue: asyncio.Queue, row_queue: asyncio.Queue):
    while True:
        file = await file_queue.get()
        if file is None:
            return
        with open(file, "r") as f:
            rows = csv.DictReader(f)
            for row in rows:
                await row_queue.put(row)
        file_queue.task_done()


async def handle_key(key, value):
    print(f"\r{key:<40}: {type(value).__name__:<9}", end="        ")
    all_fields = defaultdict(lambda: defaultdict(dict))
    if isinstance(value, dict):
        for subkey, subvalue in value.items():
            try:
                value = ast.literal_eval(value)
            except Exception:
                pass
            all_fields[key] = deep_update(all_fields[key], await handle_key(subkey, subvalue))
    elif isinstance(value, list):
        all_fields[key] = [value[0]] if len(value) > 0 else []
    else:
        all_fields[key] = type(value).__name__
    return all_fields


async def consumer(row_queue: asyncio.Queue):
    all_fields = defaultdict(dict)
    while True:
        row = await row_queue.get()
        if row is None:
            return all_fields
        for key, value in row.items():
            try:
                value = ast.literal_eval(value)
            except Exception:
                pass
            if value is None:
                value = {}
            all_fields = deep_update(all_fields, await handle_key(key, value))
        row_queue.task_done()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--folder", help="Data folder", required=True)
    parser.add_argument("-w", "--workers", help="Number of worker tasks", type=int, default=300)
    parser.add_argument("-o", "--output", help="Output file", type=str, default="group_available_fields.json")
    return parser.parse_args()


async def compile_fields():
    args = parse_args()
    args.producers = args.workers // 5
    args.consumers = args.workers - args.producers

    file_queue = asyncio.Queue(args.producers * 2)
    row_queue = asyncio.Queue(args.consumers * 2)
    producer_tasks = [
        asyncio.create_task(producer(file_queue, row_queue))
        for _ in range(args.producers)
    ]
    consumer_tasks = [
        asyncio.create_task(consumer(row_queue), name=f"{i}")
        for i in range(args.consumers)
    ]

    all_files = glob(f"**/{args.folder}/**/report_*.csv", recursive=True)
    for idx, file in enumerate(all_files):
        await file_queue.put(file)
    for _ in range(args.producers):
        await file_queue.put(None)
    await asyncio.gather(*producer_tasks)

    for _ in range(args.consumers):
        await row_queue.put(None)
    all_ret = await asyncio.gather(*consumer_tasks)

    merged_fields = {}
    for consumer_ret in all_ret:
        merged_fields = deep_update(merged_fields, consumer_ret)
    print("\nMerged fields")

    try:
        firstitem = next(iter(merged_fields["report"].values()))
        firstkey = next(iter(merged_fields["report"].keys()))
        merged_fields["report"] = {}
        merged_fields["report"][firstkey] = firstitem
    except Exception:
        print("No report results found in report")
    try:
        firstitem = next(iter(merged_fields["vt_response"]["attributes"]["results"].values()))
        firstkey = next(iter(merged_fields["vt_response"]["attributes"]["results"].keys()))
        merged_fields["vt_response"]["attributes"]["results"] = {}
        merged_fields["vt_response"]["attributes"]["results"][firstkey] = firstitem
    except Exception:
        print("No vt_response results found in report")
    try:
        firstitem = next(iter(merged_fields["cs_response"]["result"]["dns"]["records"].values()))
        firstkey = next(iter(merged_fields["cs_response"]["result"]["dns"]["records"].keys()))
        merged_fields["cs_response"]["result"]["dns"]["records"] = {}
        merged_fields["cs_response"]["result"]["dns"]["records"][firstkey] = firstitem
    except Exception:
        print("No dns records found in cs_response")
    try:
        firstitem = next(iter(merged_fields["cs_response"]["result"]["resource"]["dns"]["forward_dns"].values()))
        firstkey = next(iter(merged_fields["cs_response"]["result"]["resource"]["dns"]["forward_dns"].keys()))
        merged_fields["cs_response"]["result"]["resource"]["dns"]["forward_dns"] = {}
        merged_fields["cs_response"]["result"]["resource"]["dns"]["forward_dns"][firstkey] = firstitem
    except Exception:
        print("No forward_dns records found in cs_response")

    with open(args.output, "w") as f:
        json.dump(merged_fields, f, indent=2)


if __name__ == "__main__":
    asyncio.run(compile_fields())
