import os, argparse, csv, json, asyncio, aiohttp

from dotenv import load_dotenv
from datetime import datetime
import time
from vendors import (
    vt_scan_url,
    vt_get_url_analysis,
    ai_get_url_report,
)

# Loading API keys from environment variables
load_dotenv()
KEYS = {
    "VIRUSTOTAL": os.getenv("VIRUSTOTAL").split(","),
    "ABUSEIPDB": os.getenv("ABUSEIPDB").split(","),
    "CENSYS": os.getenv("CENSYS").split(","),
}
key_num = {
    service: 0
    for service in KEYS
    if KEYS[service] is not None and KEYS[service] != "None"
}
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
    global key_num, key_limit, key_in_use
    if len(KEYS[service]) == key_num[service]:
        key_in_use[service] = None
        key_limit[service] = None

    if service in KEYS:
        key_tuple = KEYS[service][key_num[service]]
        key_num[service] += 1
        if "::" in key_tuple:
            seckey, limit = key_tuple.split("::")
            limit = int(limit)
        else:
            seckey, limit = key_tuple, None
        if "||" in seckey:
            key, secret = seckey.split("||")
        else:
            key, secret = seckey, None
        key_limit[service] = limit
        key_in_use[service] = key


def check_keys():
    if key_limit["VIRUSTOTAL"] == 0:
        get_next_key("VIRUSTOTAL")
    if key_limit["ABUSEIPDB"] == 0:
        get_next_key("ABUSEIPDB")
    if key_limit["CENSYS"] == 0:
        get_next_key("CENSYS")


async def worker(name, queue, session, writer, lock):
    """Consumes IPs from queue, processes them, and writes results to CSV"""
    while True:
        ip = await queue.get()
        if ip is None:  # Sentinel to stop worker
            # print(f"Worker {name} exiting.")
            queue.task_done()
            break

        # Prossess the IP
        total_votes, report = {}, {}
        vt_response = {}
        if key_in_use["VIRUSTOTAL"]:
            analysis_id = await vt_scan_url(session, f"{ip}", key_in_use["VIRUSTOTAL"])
            vt_response = await vt_get_url_analysis(
                session, analysis_id, key_in_use["VIRUSTOTAL"]
            )

            # Process results
            report.update(vt_response["attributes"]["results"])
            for key, value in vt_response["attributes"]["stats"].items():
                total_votes[key] = total_votes.get(key, 0) + value

        ai_response = {}
        if key_in_use["ABUSEIPDB"]:
            ai_response = await ai_get_url_report(
                session, f"{ip}", key_in_use["ABUSEIPDB"]
            )

            # Process results
            if ai_response["abuseConfidenceScore"] > 20:
                report["AbuseIPDB"] = {"category": "malicious"}
                total_votes["malicious"] = total_votes.get("malicious", 0) + 1
            else:
                report["AbuseIPDB"] = {"category": "harmless"}
                total_votes["harmless"] = total_votes.get("harmless", 0) + 1

        cs_response = {}
        if key_in_use["CENSYS"]:
            pass

        # Write results row by row
        async with lock:  # make sure only one worker writes at a time
            if key_limit["VIRUSTOTAL"]:
                key_limit["VIRUSTOTAL"] -= 1
            if key_limit["ABUSEIPDB"]:
                key_limit["ABUSEIPDB"] -= 1

            check_keys()
            writer.writerow(
                {
                    "IP": ip,
                    "total_votes": total_votes,
                    "report": report,
                    "vt_response": vt_response,
                    "ai_response": ai_response,
                    "cs_response": cs_response,
                }
            )

        # print(f"Worker {name} finished {ip}")
        queue.task_done()


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
                    "total_votes",
                    "report",
                    "vt_response",
                    "ai_response",
                    "cs_response",
                ]
                writer = csv.DictWriter(out_f, fieldnames=fieldnames)
                writer.writeheader()

                # Start 15 workers
                workers = [
                    asyncio.create_task(worker(i, queue, session, writer, lock))
                    for i in range(args.workers)
                ]

                # Producer: read input CSV line by line
                with open(file, newline="") as in_f:
                    reader = csv.DictReader(in_f)
                    for row_idx, row in enumerate(reader):
                        ip = row["IP"]
                        label = row["label"]
                        print(
                            f"\rPassed {row_idx} items so far... ({ip})",
                            end="    ",
                        )
                        if label.lower() != "benign":
                            await queue.put(ip)

                # Send sentinel to stop workers
                for _ in workers:
                    await queue.put(None)

                await queue.join()
                await asyncio.gather(*workers)

            elapsed = time.time() - start_time
            avg_time = elapsed / (idx + 1)
            remaining = avg_time * (file_num - idx - 1)
            print(
                f"\nReport for file {idx + 1}/{file_num} has been generated. Estimated time remaining: {remaining:.1f}s"
            )
        print(f"\nAll reports generated in {elapsed:.1f}s.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch URL reports.")
    parser.add_argument(
        "-f", "--folder", required=True, help="Folder containing CSV files to process"
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=20,
        help="Number of concurrent workers (default: 20)",
    )
    parser.add_argument(
        "-q",
        "--queue_size",
        type=int,
        default=30,
        help="Size of the queue buffer (default: 30)",
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
