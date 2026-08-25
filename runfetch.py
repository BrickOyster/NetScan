#!/usr/bin/env python3
import argparse
import asyncio
import csv
import io
import os
import pathlib
import sys
import time
from pprint import pp
from typing import Any

import aiohttp
import anyio
from dotenv import load_dotenv

from vendors import (
    VIRUSTOTAL_RESET_TIME,
    WAITING_TIME,
    Report,
    TotalVotes,
    ai_get_url_report,
    check_vt_quota,
    # cs_get_url_report,
    datetime,
    fetch_cinsscore,
    fetch_openphish,
    # fetch_silentpush,
    info_print,
    process_ai_report,
    process_cb_report,
    # process_cs_report,
    process_op_report,
    # process_sp_report,
    process_tf_report,
    process_vt_report,
    tf_search_ioc,
    vt_get_ip_analysis,
    vt_submit_ip_scan,
)

# Loading API keys from environment variables
load_dotenv()

# Load txt servises
cinsscore_list = fetch_cinsscore()


async def cb_search_list(_session: aiohttp.ClientSession, search_term: str, _apikey: str) -> int:
    return cinsscore_list.count(search_term.split(":", maxsplit=1)[0])


openphish_list, op_missed = fetch_openphish()


async def op_search_list(_session: aiohttp.ClientSession, search_term: str, _apikey: str) -> int:
    return openphish_list.count(search_term.split(":", maxsplit=1)[0])


info_print(f"Loaded remote lists with {op_missed} missed items.")

# ------------------- Service Configuration -------------------
# For extra services:
# 1. Define environment variable in .env file for key||secret::rate_limit
# 2. Create corresponding functions in vendors.py
# 3. Add service info in the dicts below
# Available not used: CENSYS, SILENTPUSH
services = {
    "VIRUSTOTAL": "vt",
    "ABUSEIPDB": "ai",
    "THREATFOX": "tf",
    "CINSSCORE": "cb",
    "OPENPHIS": "op",
}  # Service name : abbreviation
fetch_from_service = {
    # VIRUSTOTAL is handled separately by the producer/consumer split below.
    "ABUSEIPDB": ai_get_url_report,
    "THREATFOX": tf_search_ioc,
    "CINSSCORE": cb_search_list,
    "OPENPHIS": op_search_list,
}  # Service name : function to fetch report
process_service_report = {
    "ABUSEIPDB": process_ai_report,
    "THREATFOX": process_tf_report,
    "CINSSCORE": process_cb_report,
    "OPENPHIS": process_op_report,
}  # Service name : function to process report
# -------------------------------------------------------------

# Producer -> consumer handoff: everything gathered before the VT analysis is ready.
VTQueueItem = tuple[str, str, str | None, TotalVotes, Report, dict[str, Any]]

KEYS = {service: os.getenv(service) for service in services}

key_in_use = {service: key.split("::")[0] for service, key in KEYS.items() if key is not None and key != "None"}
pp(key_in_use)


async def quota_worker(args: argparse.Namespace) -> None:
    """Background task to monitor VT quota and cancel all tasks if quota is exceeded."""
    async with aiohttp.ClientSession() as session:
        left_day = 100
        while left_day != 0:
            await asyncio.sleep(10 * WAITING_TIME)
            if time.localtime().tm_hour == VIRUSTOTAL_RESET_TIME:
                break
            vt_quota = await check_vt_quota(session, key_in_use["VIRUSTOTAL"])
            allowed_day = vt_quota["api_requests_daily"]["user"]["allowed"]
            left_day = allowed_day - vt_quota["api_requests_daily"]["user"]["used"]
            allowed_hour = vt_quota["api_requests_hourly"]["user"]["allowed"]
            left_hour = allowed_hour - vt_quota["api_requests_hourly"]["user"]["used"]
            if args.debug:
                info_print(f"VT quota = H: {left_hour}/{allowed_hour} | D:{left_day}/{allowed_day}")

    info_print("VT quota exceeded, cancelling all tasks...")
    for task in asyncio.all_tasks():
        if task.get_name() == "quota-worker":
            continue
        info_print(f"Canceling task: {task.get_name()}")
        task.cancel("quota exceeded error")


async def producer(
    name: int,
    in_queue: asyncio.Queue[str | None],
    out_queue: asyncio.Queue[VTQueueItem | None],
    args: argparse.Namespace,
) -> None:
    """Kicks off a VT rescan (no wait), fetches the other services, and hands off to the VT consumers."""
    async with aiohttp.ClientSession() as session:
        while True:
            ip_port = await in_queue.get()
            if ip_port is None:  # Sentinel to stop producer
                in_queue.task_done()
                break
            ip, port = ip_port.split(":")

            if args.debug:
                info_print(f"Producer #{name} processing '{ip_port}'")

            total_votes: TotalVotes = {}
            report: Report = {}
            responses: dict[str, Any] = {"vt_response": {}}

            analysis_id = None
            if key_in_use["VIRUSTOTAL"]:
                analysis_id = await vt_submit_ip_scan(session, ip_port, key_in_use["VIRUSTOTAL"])

            for service_name, fetch in fetch_from_service.items():
                service_abbr = services[service_name]
                if not key_in_use[service_name]:
                    responses[f"{service_abbr}_response"] = {}
                    continue
                responses[f"{service_abbr}_response"] = await fetch(
                    session,
                    ip_port,
                    *key_in_use[service_name].split("||"),
                )
                total_votes, report = await process_service_report[service_name](
                    responses[f"{service_abbr}_response"],
                    total_votes,
                    report,
                )

            await out_queue.put((ip, port, analysis_id, total_votes, report, responses))
            in_queue.task_done()
            await asyncio.sleep(WAITING_TIME)


async def consumer(
    name: int,
    queue: asyncio.Queue[VTQueueItem | None],
    out_f: Any,
    fieldnames: list[str],
    lock: asyncio.Lock,
    args: argparse.Namespace,
) -> None:
    """Consumes producer output: polls VirusTotal for the finished analysis and writes the row."""
    async with aiohttp.ClientSession() as session:
        while True:
            item = await queue.get()
            if item is None:  # Sentinel to stop consumer
                queue.task_done()
                break
            ip, port, analysis_id, total_votes, report, responses = item

            if args.debug:
                info_print(f"Consumer #{name} processing '{ip}:{port}'")

            if analysis_id and key_in_use["VIRUSTOTAL"]:
                vt_response = await vt_get_ip_analysis(session, analysis_id, key_in_use["VIRUSTOTAL"])
                responses["vt_response"] = vt_response or {}
                total_votes, report = await process_vt_report(responses["vt_response"], total_votes, report)

            # Write results row by row
            async with lock:  # make sure only one consumer writes at a time
                to_write = {
                    "IP": ip,
                    "Port": port,
                    "total_votes": total_votes,
                    "report": report,
                }
                to_write.update(responses)
                row = io.StringIO()
                csv.DictWriter(row, fieldnames=fieldnames).writerow(to_write)
                await out_f.write(row.getvalue())

            queue.task_done()


async def main(args: argparse.Namespace) -> None:
    info_print(f"Found {args.file_num} files.")

    if args.start_from:
        info_print(f"Resuming from entry {args.start_from}.")

    start_time = time.time()
    quota_workers = None
    for idx, file in enumerate(args.files):
        info_print(f"Processing file {idx + 1}/{args.file_num}:{file}")
        ip_queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=args.queue_size)  # buffer size
        vt_queue: asyncio.Queue[VTQueueItem | None] = asyncio.Queue(maxsize=150 * args.queue_size)
        lock = asyncio.Lock()

        date = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        out_file = f"{file.removesuffix('.csv')}/report_{date}.csv"
        info_print(f"Output file: {out_file}")
        await anyio.Path(file.removesuffix(".csv")).mkdir(exist_ok=True)

        async with await anyio.open_file(out_file, "w", newline="", encoding="utf-8") as out_f:
            fieldnames = [
                "IP",
                "Port",
                "total_votes",
                "report",
            ]
            fieldnames.extend([f"{service_abbr}_response" for service_abbr in services.values()])
            header = io.StringIO()
            csv.DictWriter(header, fieldnames=fieldnames).writeheader()
            await out_f.write(header.getvalue())

            # Start producers and consumers
            if not quota_workers:
                info_print("Starting quota worker...")
                quota_workers = asyncio.create_task(quota_worker(args), name="quota-worker")
            producers = [
                asyncio.create_task(producer(i, ip_queue, vt_queue, args), name=f"producer-{i}")
                for i in range(args.workers)
            ]
            consumers = [
                asyncio.create_task(consumer(i, vt_queue, out_f, fieldnames, lock, args), name=f"consumer-{i}")
                for i in range(args.vt_workers)
            ]

            # Read input CSV line by line and feed the producers
            async with await anyio.open_file(file, newline="", encoding="utf-8") as in_f:
                reader = csv.DictReader((await in_f.read()).splitlines())
                for row in reader:
                    if args.start_from:
                        args.start_from -= 1
                        continue
                    ip = row["IP"]
                    port = row["Port"]
                    label = row["label"]
                    if args.debug:
                        info_print(f"Enqueuing {ip}:{port}...")
                    if label.lower() != "benign":
                        await ip_queue.put(f"{ip}:{port}")

                # Send sentinel to stop producers
                for _ in producers:
                    await ip_queue.put(None)

                await ip_queue.join()
                await asyncio.gather(*producers)

                # Send sentinel to stop consumers
                for _ in consumers:
                    await vt_queue.put(None)

                await vt_queue.join()
                await asyncio.gather(*consumers)

        remaining = (time.time() - start_time) * (args.file_num - idx - 1) / (idx + 1)
        info_print(f"Report for file {idx + 1}/{args.file_num} has been generated.")
        info_print(f"Estimated time remaining: {remaining / 60:.1f}m.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch URL reports.")

    parser.add_argument("-f", "--folder", required=True, help="Folder containing CSV files to process")
    parser.add_argument("-w", "--workers", type=int, default=2, help="Concurrent producers (default: 2)")
    parser.add_argument("-vw", "--vt_workers", type=int, default=4, help="Concurrent VT result consumers (default: 4)")
    parser.add_argument("-q", "--queue_size", type=int, default=4, help="Size of the queue buffers (default: 4)")
    parser.add_argument("-sf", "--start_from", type=int, default=0, help="Skip first N entries in first file.")
    parser.add_argument("-dbg", "--debug", action="store_true", help="Enable debug level prints")

    args = parser.parse_args()

    files = [str(f) for f in pathlib.Path(args.folder).iterdir() if f.suffix == ".csv"]
    if not files:
        info_print(f"No CSV files found in folder {args.folder}.")
        sys.exit(1)
    args.files = files
    args.file_num = len(args.files)

    return args


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(main(args))
    except asyncio.CancelledError as e:
        info_print(f"Process cancelled due to {e.args}. Exiting...")
        sys.exit(1)
