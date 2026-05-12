import argparse
import asyncio
import csv
import os
import pathlib
import sys
import time
from pprint import pp

import aiohttp
from dotenv import load_dotenv

from vendors import (
    WAITING_TIME,
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
    vt_scan_ip,
)

# Loading API keys from environment variables
load_dotenv()

# Load txt servises
cinsscore_list = fetch_cinsscore()


async def cb_search_list(session, search_term, apikey):  # noqa: ARG001, RUF029
    return cinsscore_list.count(search_term.split(":")[0])


openphish_list, op_missed = fetch_openphish()


async def op_search_list(session, search_term, apikey):  # noqa: ARG001, RUF029
    return openphish_list.count(search_term.split(":")[0])


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
    "VIRUSTOTAL": vt_scan_ip,
    "ABUSEIPDB": ai_get_url_report,
    "THREATFOX": tf_search_ioc,
    "CINSSCORE": cb_search_list,
    "OPENPHIS": op_search_list,
}  # Service name : function to fetch report
process_service_report = {
    "VIRUSTOTAL": process_vt_report,
    "ABUSEIPDB": process_ai_report,
    "THREATFOX": process_tf_report,
    "CINSSCORE": process_cb_report,
    "OPENPHIS": process_op_report,
}  # Service name : function to process report
# -------------------------------------------------------------

KEYS = {service: os.getenv(service) for service in services}

key_in_use = {service: key.split("::")[0] for service, key in KEYS.items() if key is not None and key != "None"}
pp(key_in_use)


async def quota_worker(args):
    """Background task to monitor VT quota and cancel all tasks if quota is exceeded."""
    async with aiohttp.ClientSession() as session:
        left_day = 100
        while left_day != 0:
            await asyncio.sleep(10 * WAITING_TIME)
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


async def worker(name, queue, writer, lock, args):
    """Consumes IPs from queue, processes them, and writes results to CSV."""
    async with aiohttp.ClientSession() as session:
        while True:
            ip_port = await queue.get()
            if ip_port is None:  # Sentinel to stop worker
                queue.task_done()
                break
            ip, port = ip_port.split(":")

            async with lock:  # make sure only one worker writes at a time
                if args.debug:
                    info_print(f"Worker #{name} processing '{ip_port}'")

            # Process the IP
            total_votes = {}
            report = {}
            responses = {}

            for service_name, service_abbr in services.items():
                if not key_in_use[service_name]:
                    responses[f"{service_abbr}_response"] = {}
                    continue
                responses[f"{service_abbr}_response"] = await fetch_from_service[service_name](
                    session,
                    f"{ip_port}",
                    *key_in_use[service_name].split("||"),
                )
                total_votes, report = await process_service_report[service_name](
                    responses[f"{service_abbr}_response"],
                    total_votes,
                    report,
                )

            # Write results row by row
            async with lock:  # make sure only one worker writes at a time
                to_write = {
                    "IP": ip,
                    "Port": port,
                    "total_votes": total_votes,
                    "report": report,
                }
                to_write.update(responses)
                writer.writerow(to_write)

            queue.task_done()
            await asyncio.sleep(WAITING_TIME)


async def main(args):
    info_print(f"Found {args.file_num} files.")

    if args.start_from:
        info_print(f"Resuming from entry {args.start_from}.")

    start_time = time.time()
    quota_workers = None
    for idx, file in enumerate(args.files):
        info_print(f"Processing file {idx + 1}/{args.file_num}:{file}")
        queue = asyncio.Queue(maxsize=args.queue_size)  # buffer size
        lock = asyncio.Lock()

        date = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        out_file = f"{file.removesuffix('.csv')}/report_{date}.csv"
        info_print(f"Output file: {out_file}")
        pathlib.Path(file.removesuffix(".csv")).mkdir(exist_ok=True)  # noqa: ASYNC240

        with pathlib.Path(out_file).open("w", newline="", encoding="utf-8") as out_f:  # noqa: ASYNC230
            fieldnames = [
                "IP",
                "Port",
                "total_votes",
                "report",
            ]
            fieldnames.extend([f"{service_abbr}_response" for service_abbr in services.values()])
            writer = csv.DictWriter(out_f, fieldnames=fieldnames)
            writer.writeheader()

            # Start workers
            if not quota_workers:
                info_print("Starting quota worker...")
                quota_workers = asyncio.create_task(quota_worker(args), name="quota-worker")
            workers = [
                asyncio.create_task(worker(i, queue, writer, lock, args), name=f"worker-{i}")
                for i in range(args.workers)
            ]

            # Producer: read input CSV line by line
            with pathlib.Path(file).open(newline="", encoding="utf-8") as in_f:  # noqa: ASYNC230
                reader = csv.DictReader(in_f)
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
                        await queue.put(f"{ip}:{port}")

                # Send sentinel to stop workers
                for _ in workers:
                    await queue.put(None)

                await queue.join()
                await asyncio.gather(*workers)

        remaining = (time.time() - start_time) * (args.file_num - idx - 1) / (idx + 1)
        info_print(f"Report for file {idx + 1}/{args.file_num} has been generated.")
        info_print(f"Estimated time remaining: {remaining / 60:.1f}m.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch URL reports.")

    parser.add_argument("-f", "--folder", required=True, help="Folder containing CSV files to process")
    parser.add_argument("-w", "--workers", type=int, default=2, help="Concurrent workers (default: 2)")
    parser.add_argument("-q", "--queue_size", type=int, default=4, help="Size of the queue buffer (default: 4)")
    parser.add_argument("-sf", "--start_from", type=int, default=0, help="Skip first N entries in first file.")
    parser.add_argument("-dbg", "--debug", action="store_true", help="Enable debug level prints")

    args = parser.parse_args()

    files = [str(f) for f in pathlib.Path(args.folder).iterdir() if f.suffix == ".csv"]
    if not files:
        info_print(f"No CSV files found in folder {args.folder}.")
        sys.exit(1)
    args.files = files
    args.file_num = len(args.files)

    try:
        asyncio.run(main(args))
    except asyncio.CancelledError as e:
        info_print(f"Process cancelled due to {e.args}. Exiting...")
        sys.exit(1)
