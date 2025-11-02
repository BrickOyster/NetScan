import os, argparse, csv, json, asyncio, aiohttp

from dotenv import load_dotenv
from datetime import datetime
import time
from vendors import *

# Loading API keys from environment variables
load_dotenv()

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
}  # Service name : abbreviation
fetch_from_service = {
    "VIRUSTOTAL": vt_scan_url,
    "ABUSEIPDB": ai_get_url_report,
    "CENSYS": cs_get_url_report,
    "THREATFOX": tf_search_ioc,
}  # Service name : function to fetch report
process_service_report = {
    "VIRUSTOTAL": process_vt_report,
    "ABUSEIPDB": process_ai_report,
    "CENSYS": process_cs_report,
    "THREATFOX": process_tf_report,
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


async def worker(name, queue, session, writer, lock, args):
    """Consumes IPs from queue, processes them, and writes results to CSV"""
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
        await asyncio.sleep(31)


async def main(args):
    file_num = len(args.files)
    print(
        f"Found {file_num} files to process. With {args.workers} workers and {args.queue_size} queue size."
    )
    check_keys()

    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        for idx, file in enumerate(args.files):
            queue = asyncio.Queue(maxsize=args.queue_size)  # buffer size
            lock = asyncio.Lock()

            date = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
            OUTPUT_FILE = f"{file.removesuffix('.csv')}/report_{date}.csv"
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

                # Start 15 workers
                workers = [
                    asyncio.create_task(worker(i, queue, session, writer, lock, args))
                    for i in range(args.workers)
                ]

                # Producer: read input CSV line by line
                with open(file, newline="") as in_f:
                    matched_count = 0
                    reader = csv.DictReader(in_f)
                    for row_idx, row in enumerate(reader):
                        ip = row["IP"]
                        port = row["Port"]
                        label = row["label"]
                        print(
                            f"\rPassed {row_idx+1} items so far ({matched_count} malicious)...        ",
                            end="    ",
                        )
                        if label.lower() != "benign":
                            await queue.put(f"{ip}:{port}")
                            matched_count += 1

                    # Send sentinel to stop workers
                    for _ in workers:
                        await queue.put(None)

                    await queue.join()
                    await asyncio.gather(*workers)

            elapsed = time.time() - start_time
            avg_time = elapsed / (idx + 1)
            remaining = avg_time * (file_num - idx - 1)
            print(
                f"\nReport for file {idx + 1}/{file_num} has been generated. Estimated time remaining: {remaining/60:.1f}m."
            )
        print(f"\nAll reports generated in {elapsed/60:.1f}m.")


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
        help="Number of concurrent workers (default: 4) to increase a paid API key is required",
    )
    parser.add_argument(
        "-q",
        "--queue_size",
        type=int,
        default=20,
        help="Size of the queue buffer (default: 20)",
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

    asyncio.run(main(args))
