import os
import argparse
import csv
import asyncio
import aiohttp
import time

from dotenv import load_dotenv
from datetime import datetime
from vendors import (
    fetch_cinsscore,
    fetch_openphish,
    vt_scan_ip,
    ai_get_url_report,
    cs_get_url_report,
    tf_search_ioc,
    process_vt_report,
    process_ai_report,
    process_cs_report,
    process_tf_report,
    process_cb_report,
    process_op_report,
    check_vt_quota,
    WAITING_TIME,
)

# Loading API keys from environment variables
load_dotenv()

# Load txt servises
cinsscore_list = fetch_cinsscore()


async def cb_search_list(session, search_term, apikey):
    return cinsscore_list.count(search_term.split(":")[0])


openphish_list, op_missed = fetch_openphish()


async def op_search_list(session, search_term, apikey):
    return openphish_list.count(search_term.split(":")[0])


print(f"Loaded remote lists with {op_missed} missed items.")

# ------------------- Service Configuration -------------------
# For extra services:
# 1. Define environment variable in .env file for key||secret::rate_limit
# 2. Create corresponding functions in vendors.py
# 3. Add service info in the dicts below
services = {
    "VIRUSTOTAL": "vt",
    "ABUSEIPDB": "ai",
    "CENSYS": "cs",
    "THREATFOX": "tf",
    "CINSSCORE": "cb",
    "OPENPHIS": "op",
}  # Service name : abbreviation
fetch_from_service = {
    "VIRUSTOTAL": vt_scan_ip,
    "ABUSEIPDB": ai_get_url_report,
    "CENSYS": cs_get_url_report,
    "THREATFOX": tf_search_ioc,
    "CINSSCORE": cb_search_list,
    "OPENPHIS": op_search_list,
}  # Service name : function to fetch report
process_service_report = {
    "VIRUSTOTAL": process_vt_report,
    "ABUSEIPDB": process_ai_report,
    "CENSYS": process_cs_report,
    "THREATFOX": process_tf_report,
    "CINSSCORE": process_cb_report,
    "OPENPHIS": process_op_report,
}  # Service name : function to process report
# -------------------------------------------------------------

KEYS = {
    service: (
        os.getenv(service).split(",")
        if os.getenv(service) not in [None, "None"]
        else []
    )
    for service in services
}

# Convert lists to queues
for service in KEYS:
    if KEYS[service]:
        queue = asyncio.Queue()
        for key in KEYS[service]:
            queue.put_nowait(key)
        KEYS[service] = queue
    else:
        KEYS[service] = asyncio.Queue()

key_limit = {
    service: 0
    for service in KEYS
    if KEYS[service] is not None and KEYS[service] != "None"
}
key_in_use = {
    service: None
    for service in KEYS
    if KEYS[service] is not None and KEYS[service] != "None"
}


def get_next_key(service):
    global key_limit, key_in_use
    if not KEYS[service].empty():
        key, limit = KEYS[service].get_nowait().split("::")
        key_in_use[service] = key
        key_limit[service] = int(limit)
        print(
            f"Next key for {service}: {key_in_use[service]}, Key limit: {key_limit[service]}"
        )
    else:
        key_in_use[service] = None
        key_limit[service] = None
        print(f"{service} has no more API keys available.")


def check_keys():
    [get_next_key(service) for service in KEYS if key_limit[service] == 0]


async def quota_worker(args):
    left_day = 100
    while left_day != 0:
        await asyncio.sleep(10 * WAITING_TIME)
        vt_quota = await check_vt_quota(key_in_use["VIRUSTOTAL"])
        allowed_day = vt_quota["api_requests_daily"]["user"]["allowed"]
        left_day = allowed_day - vt_quota["api_requests_daily"]["user"]["used"]
        allowed_hour = vt_quota["api_requests_hourly"]["user"]["allowed"]
        left_hour = allowed_hour - vt_quota["api_requests_hourly"]["user"]["used"]
        if args.debug:
            print(
                f"{datetime.now().time()} | VT quota = H: {left_hour}/{allowed_hour} | D:{left_day}/{allowed_day}",
                flush=True,
            )

    print("VT quota exceeded, cancelling all tasks...")
    for task in asyncio.all_tasks():
        if task.get_name() == "quota-worker":
            continue
        print(f"Canceling task: {task.get_name()}")
        task.cancel("quota exceeded error")


async def worker(name, queue, writer, lock, args):
    """Consumes IPs from queue, processes them, and writes results to CSV"""
    async with aiohttp.ClientSession() as session:
        while True:
            ip_port = await queue.get()
            if ip_port is None:  # Sentinel to stop worker
                queue.task_done()
                break
            ip, port = ip_port.split(":")

            async with lock:  # make sure only one worker writes at a time
                for service in KEYS:
                    key_limit[service] -= 1 if key_limit[service] else 0
                check_keys()
                if args.debug:
                    print(
                        f"{datetime.now().time()} | Worker #{name} processing '{ip_port}'",
                        flush=True,
                    )

            # Process the IP
            total_votes = {}
            report = {}
            responses = {}

            for service in services:
                if not key_in_use[service]:
                    responses[f"{services[service]}_response"] = {}
                    continue
                responses[f"{services[service]}_response"] = await fetch_from_service[
                    service
                ](session, f"{ip_port}", *key_in_use[service].split("||"))
                total_votes, report = await process_service_report[service](
                    responses[f"{services[service]}_response"], total_votes, report
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
    print(
        f"Found {args.file_num} files to process. With {args.workers} workers and {args.queue_size} queue size."
    )
    check_keys()

    if args.start_from:
        print(f"Resuming from entry {args.start_from}.")

    start_time = time.time()
    total_matched = 0
    quota_workers = None
    for idx, file in enumerate(args.files):
        print(f"\nProcessing file {idx + 1}/{args.file_num}:\n{file}")
        queue = asyncio.Queue(maxsize=args.queue_size)  # buffer size
        lock = asyncio.Lock()

        date = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        OUTPUT_FILE = f"{file.removesuffix('.csv')}/report_{date}.csv"
        print(f"Output file: {OUTPUT_FILE}")
        if not os.path.exists(file.removesuffix(".csv")):
            os.mkdir(file.removesuffix(".csv"))

        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as out_f:
            fieldnames = [
                "IP",
                "Port",
                "total_votes",
                "report",
            ]
            for service in services:
                fieldnames.append(f"{services[service]}_response")
            writer = csv.DictWriter(out_f, fieldnames=fieldnames)
            writer.writeheader()

            # Start workers
            if not quota_workers:
                print("Starting quota worker...")
                quota_workers = asyncio.create_task(
                    quota_worker(args), name="quota-worker"
                )
            workers = [
                asyncio.create_task(
                    worker(i, queue, writer, lock, args), name=f"worker-{i}"
                )
                for i in range(args.workers)
            ]

            # Producer: read input CSV line by line
            with open(file, newline="") as in_f:
                matched_count = 0
                reader = csv.DictReader(in_f)
                for row_idx, row in enumerate(reader):
                    if args.start_from:
                        args.start_from -= 1
                        continue
                    ip = row["IP"]
                    port = row["Port"]
                    label = row["label"]
                    if args.debug:
                        print(f"{datetime.now().time()} | Enqueuing {ip}:{port}...")
                    if label.lower() != "benign":
                        matched_count += 1
                        await queue.put(f"{ip}:{port}")
                total_matched += matched_count

                # Send sentinel to stop workers
                for _ in workers:
                    await queue.put(None)

                await queue.join()
                await asyncio.gather(*workers)

        elapsed = time.time() - start_time
        avg_time = elapsed / (idx + 1)
        remaining = avg_time * (args.file_num - idx - 1)
        print(
            f"\nReport for file {idx + 1}/{args.file_num} has been generated. Estimated time remaining: {remaining/60:.1f}m."
        )
    print(f"\nReports with {total_matched} hits generated in {elapsed/60:.1f}m.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch URL reports.")
    parser.add_argument(
        "-f", "--folder", required=True, help="Folder containing CSV files to process"
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=2,
        help="Number of concurrent workers (default: 2) to increase a paid VT API key is required",
    )
    parser.add_argument(
        "-q",
        "--queue_size",
        type=int,
        default=4,
        help="Size of the queue buffer (default: 4)",
    )
    parser.add_argument(
        "-sf",
        "--start_from",
        type=int,
        default=0,
        help="Skip first N entries in first file. For resuming interrupted runs.",
    )
    parser.add_argument(
        "-dbg",
        "--debug",
        action="store_true",
        help="Enable debug level prints",
    )
    args = parser.parse_args()

    files = [
        os.path.join(args.folder, f)
        for f in os.listdir(args.folder)
        if f.endswith(".csv")
    ]
    if not files:
        print(f"No CSV files found in folder {args.folder}.")
        exit(1)
    args.files = files
    args.file_num = len(args.files)

    try:
        asyncio.run(main(args))
    except asyncio.CancelledError as e:
        print(f"Process cancelled due to {e.args}. Exiting...")
        exit(1)
