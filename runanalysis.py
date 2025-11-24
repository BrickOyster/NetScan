import os, glob, argparse, csv, asyncio, aiohttp
import matplotlib.pyplot as plt
from datetime import datetime, date, timedelta
csv.field_size_limit(100000000)
services = {
    "VIRUSTOTAL": "vt",
    "ABUSEIPDB": "ai",
    "CENSYS": "cs",
    "THREATFOX": "tf",
}  # Service name : abbreviation

async def worker(name, queue, lock, args):
    results = {
        
    }
    not_complete = 0
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        file_idx, file_path = item
        date = file_path.split("/")[-1].split("_")[1]
        with open(file_path, newline="") as in_f:
            reader = csv.DictReader(in_f)
            for row_idx, row in enumerate(reader):
                identifier = f"{row['IP']}:{row['Port']}"
                total_votes = eval(row.get("total_votes", {}))
                if sum(total_votes.values()) < 50:
                    not_complete += 1
                if identifier not in results:
                    results[identifier] = []
                results[identifier].append((date,total_votes.get("malicious", 0)))
        queue.task_done()
    return (results, not_complete)

async def main(args):
    queue = asyncio.Queue(maxsize=args.queue_size)  # buffer size
    lock = asyncio.Lock()
    start_time = datetime.now()
    print(f"Running analysis for {args.file_num} files from the ...")
 
    # Start workers
    workers = [
        asyncio.create_task(worker(i, queue, lock, args))
        for i in range(args.workers)
    ]
    
    for idx, file in enumerate(args.files):
        await queue.put((idx, file))
    
    # Stop workers
    for _ in workers:
        await queue.put(None)
    
    await queue.join()
    all_ret = await asyncio.gather(*workers)
    total_results = {}
    statistics = {
        "Total IP": 0,
        "All zero votes": 0,
        "Non zero first day": 0,
        "Detected by more after non zero first day": 0,
        "Zero first day": 0,
        "Detected after zero first day": 0,
        "Zero first two days": 0,
        "Zero first two days detected on third": 0,
        "Zero first two days detected on third that increased after ": 0,
        "Not complete": 0,
    }
    off_day_one = 0
    off_day_two = 0
    plt.figure(figsize=(10, 6))
    start_date = date(2025, 10, 17)
    end_date = date.today()

    date_list = [(start_date + timedelta(days=i)).isoformat() for i in range((end_date - start_date).days + 1)]
    # plt.plot(date_list, [0]*len(date_list), linestyle='--', color='gray')
    for re in all_ret:
        r, c = re
        statistics["Not complete"] += c
        for k, v in r.items():
            statistics["Total IP"] += 1
            if sum([x[1] for x in v]) == 0:
                statistics["All zero votes"] += 1
            else:
                # Sort by date
                v.sort(key=lambda x: x[0])

                if v[0][0] in ["2025-10-17", "2025-10-18", "2025-10-19"]:
                    if v[0][1] != 0:
                        statistics["Non zero first day"] += 1
                        for day_data in v[1:]:
                            if day_data[1] > v[0][1]:
                                statistics["Detected by more after non zero first day"] += 1
                                break
                    else:
                        statistics["Zero first day"] += 1
                        if v[1][0] in ["2025-10-20", "2025-10-21", "2025-10-22"] and v[1][1] != 0:
                            statistics["Detected after zero first day"] += 1
                        else:
                            off_day_two += 1
                    if v[0][1] + v[1][1] == 0:
                        statistics["Zero first two days"] += 1
                        if v[2][0] in ["2025-10-23", "2025-10-24", "2025-10-25"] and v[2][1] != 0:
                            statistics["Zero first two days detected on third"] += 1
                            for day_data in v[3:]:
                                if v[3][1] > v[2][1]:
                                    statistics["Zero first two days detected on third that increased after"] += 1
                else:
                    off_day_one += 1

                dates = [x[0] for x in v]
                votes = [x[1] for x in v]
                plt.plot(dates, votes, marker='o', label=k)

            total_results[k] = v
    for stat, val in statistics.items():
        print(f"{stat}: {val}")
    print(f"Off day one count: {off_day_one}")
    print(f"Off day two count: {off_day_two}")
    print(f"All files processed in {(datetime.now() - start_time).seconds}s.")
    plt.xlabel('Date')
    plt.ylabel('Malicious Votes')
    plt.title('Malicious Votes Over Time per IP:Port')
    plt.xticks(rotation=45)
    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run analysis on ip data.")
    parser.add_argument(
        "-f", "--folder", required=True, 
        help="Input file containing IP data"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=10, 
        help="Number of worker tasks to run concurrently."
    )
    parser.add_argument(
        "-q", "--queue_size", type=int, default=50, 
        help="Size of the task queue."
    )
    args = parser.parse_args()
    args.start_date = args.folder.split("_")[-2:-1]

    files = glob.glob(os.path.join(args.folder, "**/report*.csv"), recursive=True)
    if not files:
        print(f"No files found in folder {args.folder}.")
        exit(1)
    args.files = files
    args.file_num = len(files)

    asyncio.run(main(args))