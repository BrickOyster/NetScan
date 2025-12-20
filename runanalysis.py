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
    results = {}
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
            group = file_path.split("/")[1].split("_")[1]
            for row_idx, row in enumerate(reader):
                identifier = f"{row['IP']}:{row['Port']}:{group}"
                total_votes = eval(row.get("total_votes", {}))
                if sum(total_votes.values()) < 50:
                    not_complete += 1
                if identifier not in results:
                    results[identifier] = []
                results[identifier].append((date, total_votes.get("malicious", 0)))
        queue.task_done()
    return (results, not_complete)


async def main(args):
    queue = asyncio.Queue(maxsize=args.queue_size)  # buffer size
    lock = asyncio.Lock()
    start_time = datetime.now()
    print(f"Running analysis for {args.file_num} files from the ...")
    if not os.path.exists(args.output):
        os.mkdir(args.output)

    # Start workers
    workers = [
        asyncio.create_task(worker(i, queue, lock, args)) for i in range(args.workers)
    ]

    with open(f"{args.output}out_logs.txt", "w") as f:
        f.write(f"Total files: {args.file_num}\n")
        for idx, file in enumerate(args.files):
            await queue.put((idx, file))
            f.write(f"{file}\n")

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
        "Zero first two days detected after": 0,
        "Not complete": 0,
    }
    off_day_one = 0
    off_day_two = 0

    end_date = date.today()

    groups_encountaired = {}
    with open(
        f"{args.output}non_zero.csv", "w", newline="", encoding="utf-8"
    ) as non_zero, open(
        f"{args.output}all_zero.csv", "w", newline="", encoding="utf-8"
    ) as all_zero:
        fieldnames = ["IP", "Port"]
        all_zero_writer = csv.DictWriter(all_zero, fieldnames=fieldnames)
        all_zero_writer.writeheader()
        non_zero_writer = csv.DictWriter(non_zero, fieldnames=fieldnames)
        non_zero_writer.writeheader()
        for re in all_ret:
            r, c = re
            statistics["Not complete"] += c
            for k, v in r.items():
                ip, port, group = k.split(":")
                start_date = datetime.fromisoformat(args.start_dates[group]).date()
                if group not in groups_encountaired:
                    groups_encountaired[group] = len(groups_encountaired) + 1
                    plt.figure(groups_encountaired[group], figsize=(19, 10))
                    date_list = [
                        (start_date + timedelta(days=i)).isoformat()
                        for i in range((end_date - start_date).days + 1)
                    ]
                    plt.plot(
                        date_list, [0] * len(date_list), linestyle="--", color="gray"
                    )
                    plt.xlabel("Date")
                    plt.ylabel("Malicious Votes")
                    plt.title(f"Malicious Votes Over Time per IP:Port:{group}")
                    plt.xticks(rotation=45)
                plt.figure(groups_encountaired[group])

                statistics["Total IP"] += 1
                if sum([x[1] for x in v]) == 0:
                    all_zero_writer.writerow({"IP": ip, "Port": port})
                    statistics["All zero votes"] += 1
                else:
                    non_zero_writer.writerow({"IP": ip, "Port": port})
                    # Sort by date
                    v.sort(key=lambda x: x[0])

                    if v[0][0] == start_date.isoformat():
                        pass
                        if v[0][1] != 0:
                            statistics["Non zero first day"] += 1
                            for day_data in v[1:]:
                                if day_data[1] > v[0][1]:
                                    statistics[
                                        "Detected by more after non zero first day"
                                    ] += 1
                                    break
                        else:
                            statistics["Zero first day"] += 1
                            if v[1][0] == (start_date + timedelta(days=3)).isoformat():
                                if v[1][1] != 0:
                                    statistics["Detected after zero first day"] += 1
                                else:
                                    statistics["Zero first two days"] += 1
                                    if (
                                        v[2][0]
                                        == (start_date + timedelta(days=6)).isoformat()
                                        and sum([x[1] for x in v[2:]]) != 0
                                    ):
                                        statistics[
                                            "Zero first two days detected after"
                                        ] += 1
                            else:
                                off_day_two += 1
                    else:
                        off_day_one += 1

                    dates = [x[0] for x in v]
                    votes = [x[1] for x in v]
                    plt.plot(dates, votes, marker="o", label=k)

                total_results[k] = v
    with open(f"{args.output}out_logs.txt", "a") as f:
        f.write(f"\n\nOff day one count: {off_day_one}")
        f.write(f"\nOff day two count: {off_day_two}")

        for stat, val in statistics.items():
            f.write(f"\n{stat}: {val}")

    for i, p in groups_encountaired.items():
        plt.figure(p)
        plt.savefig(f"{args.output}figure_{p}.png")
    print(f"All files processed in {(datetime.now() - start_time).seconds}s.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run analysis on ip data.")
    parser.add_argument(
        "-f", "--folder", required=True, help="Input file containing IP data"
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Number of worker tasks to run concurrently.",
    )
    parser.add_argument(
        "-q", "--queue_size", type=int, default=50, help="Size of the task queue."
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="group_analysis_out_dir/",
        help="Size of the task queue.",
    )
    args = parser.parse_args()
    args.output = (
        args.folder + args.output
        if args.folder.endswith("/")
        else args.folder + "/" + args.output
    )
    print(f"Output folder set to {args.output}")
    args.start_date = args.folder.split("_")[-2:-1]

    files = glob.glob(os.path.join(args.folder, "**/report*.csv"), recursive=True)
    if not files:
        print(f"No files found in folder {args.folder}.")
        exit(1)

    group_start = {}
    for file in files:
        group_name = file.split("/")[1].split("_")[1]
        report_file = file.split("/")[-1]
        group_date = report_file.split("_")[1]

        if group_name not in group_start or group_date < group_start[group_name]:
            group_start[group_name] = group_date
    args.start_dates = group_start

    args.files = files
    args.file_num = len(files)

    asyncio.run(main(args))
