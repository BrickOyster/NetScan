import os, glob, argparse, csv, asyncio, aiohttp
from datetime import datetime, date, timedelta
import matplotlib.pyplot as plt

csv.field_size_limit(100000000)
services = {
    "VIRUSTOTAL": "vt",
    "ABUSEIPDB": "ai",
    "CENSYS": "cs",
    "THREATFOX": "tf",
    "CINSSCORE": "cb",
    "OPENPHIS": "op",
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
        report_date = file_path.split("/")[-1].split("_")[1]
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
                results[identifier].append(
                    (
                        report_date,
                        total_votes.get("malicious", 0)
                        + total_votes.get("suspicious", 0),
                        total_votes.get("undetected", 0)
                        + total_votes.get("harmless", 0),
                    )
                )
        queue.task_done()
    return (results, not_complete)


async def main(args):
    queue = asyncio.Queue(maxsize=args.queue_size)  # buffer size
    lock = asyncio.Lock()
    start_time = datetime.now()
    end_date = date.today()
    print(f"Running analysis for {args.file_num} files from {args.folder} ...")
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

    groups_encountaired = {}
    start_date = datetime.fromisoformat(
        sorted(args.start_dates.items(), key=lambda item: item[1])[0][1]
    ).date()
    end_date = datetime.fromisoformat(
        sorted(args.end_dates.items(), key=lambda item: item[1])[-1][1]
    ).date()
    date_diff = [
        f"+{i}" for i in range(0, (end_date - start_date).days + 1, args.day_diff)
    ]
    print(f"Start date: {start_date}, End date: {end_date}")
    total_results = {}
    for_precentage = [(0, 0)] * len(date_diff)  # (malicious, harmless)
    for group in ["aggregate", "diff", "precentage", "diff_precentage"]:
        groups_encountaired[group] = len(groups_encountaired) + 1
        plt.figure(groups_encountaired[group], figsize=(19, 10))
        total_results[group] = [0] * len(date_diff)
        plt.plot(date_diff, [0] * len(date_diff), linestyle="--", color="gray")
        plt.xlabel("Date Diff")
        plt.ylabel("Malicious Votes")
        plt.title(f"{group} Malicious Votes Over Time")
        plt.xticks(rotation=45)

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
    with (
        open(
            f"{args.output}non_zero.csv", "w", newline="", encoding="utf-8"
        ) as non_zero,
        open(
            f"{args.output}all_zero.csv", "w", newline="", encoding="utf-8"
        ) as all_zero,
    ):
        fieldnames = ["IP", "Port"]
        all_zero_writer = csv.DictWriter(all_zero, fieldnames=fieldnames)
        all_zero_writer.writeheader()
        non_zero_writer = csv.DictWriter(non_zero, fieldnames=fieldnames)
        non_zero_writer.writeheader()
        for re in all_ret:
            r, c = re
            statistics["Not complete"] += c
            for ip_port_group, group_res in r.items():
                ip, port, group = ip_port_group.split(":")
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
                if sum([v[1] for v in group_res]) == 0:
                    all_zero_writer.writerow({"IP": ip, "Port": port})
                    statistics["All zero votes"] += 1
                else:
                    non_zero_writer.writerow({"IP": ip, "Port": port})
                    # Sort by date
                    group_res.sort(key=lambda v: v[0])

                    if (
                        group_res[0][0] == start_date.isoformat()
                        and group_res[0][1] != 0
                    ):
                        statistics["Non zero first day"] += 1
                        if any(v[1] > group_res[0][1] for v in group_res[1:]):
                            statistics["Detected by more after non zero first day"] += 1
                    elif (
                        group_res[0][0] == start_date.isoformat()
                        and group_res[0][1] == 0
                    ):
                        statistics["Zero first day"] += 1
                        if any(v[1] > 0 for v in group_res[1:]):
                            statistics["Detected after zero first day"] += 1
                        if (
                            len(group_res) > 1
                            and group_res[1][0]
                            == (start_date + timedelta(days=args.day_diff)).isoformat()
                            and group_res[1][1] == 0
                        ):
                            statistics["Zero first two days"] += 1
                            if any(v[1] > 0 for v in group_res[2:]):
                                statistics["Zero first two days detected after"] += 1
                        elif (
                            len(group_res) > 1
                            and group_res[1][0]
                            == (start_date + timedelta(days=args.day_diff)).isoformat()
                        ):
                            off_day_two += 1
                    else:
                        off_day_one += 1

                    dates = [x[0] for x in group_res]
                    malicious_votes = [x[1] for x in group_res]
                    plt.plot(dates, malicious_votes, marker="o", label=ip_port_group)

                dates = [x[0] for x in group_res]
                malicious_votes = [x[1] for x in group_res]
                for d_idx, d in enumerate(dates):
                    day_diff = (datetime.fromisoformat(d).date() - start_date).days
                    int_day_diff = day_diff // args.day_diff
                    if day_diff % args.day_diff != 0:
                        print(day_diff, args.day_diff)
                    total_results["aggregate"][int_day_diff] += malicious_votes[d_idx]
                    if int_day_diff == 0:
                        total_results["diff"][int_day_diff] += 0
                    else:
                        total_results["diff"][int_day_diff] += (
                            malicious_votes[d_idx] - malicious_votes[d_idx - 1]
                        )
                    if malicious_votes[d_idx] > 0:
                        for_precentage[int_day_diff] = (
                            for_precentage[int_day_diff][0] + 1,
                            for_precentage[int_day_diff][1],
                        )
                    else:
                        for_precentage[int_day_diff] = (
                            for_precentage[int_day_diff][0],
                            for_precentage[int_day_diff][1] + 1,
                        )
        total_results["precentage"] = [
            (m * 100.0 / (m + h) if m + h > 0 else 0) for m, h in for_precentage
        ]
        total_results["diff_precentage"] = []
        for i in range(len(date_diff)):
            if i == 0:
                total_results["diff_precentage"].append(0)
            else:
                prev_mal = total_results["aggregate"][i - 1]
                prev_harmless = (
                    for_precentage[i - 1][1]
                    if i - 1 < len(for_precentage)
                    else for_precentage[-1][1]
                )
                curr_mal = total_results["aggregate"][i]
                curr_harmless = (
                    for_precentage[i][1] if i < len(for_precentage) else for_precentage[-1][1]
                )
                diff_mal = curr_mal - prev_mal
                diff_harmless = curr_harmless - prev_harmless
                total_results["diff_precentage"].append(
                    (diff_mal / (diff_mal + diff_harmless) if diff_mal + diff_harmless > 0 else 0)
                )

    plt.figure(groups_encountaired["aggregate"])
    plt.plot(date_diff, total_results["aggregate"], marker="o")
    plt.figure(groups_encountaired["precentage"])
    plt.plot(date_diff, total_results["precentage"], marker="o")
    plt.figure(groups_encountaired["diff_precentage"])
    plt.plot(date_diff, total_results["diff_precentage"], marker="o")
    plt.figure(groups_encountaired["diff"])
    plt.plot(date_diff, total_results["diff"], marker="o")

    with open(f"{args.output}out_logs.txt", "a") as f:
        f.write(f"\n\nOff day one count: {off_day_one}")
        f.write(f"\nOff day two count: {off_day_two}")

        for stat, val in statistics.items():
            f.write(f"\n{stat}: {val}")

    for i, p in groups_encountaired.items():
        plt.figure(p)
        plt.savefig(f"{args.output}figure_{i}.png")
    print(f"All files processed in {(datetime.now() - start_time).seconds}s.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run analysis on ip data.")
    parser.add_argument(
        "-f", "--folder", required=True, help="Input file containing IP data"
    )
    parser.add_argument(
        "-d",
        "--day_diff",
        type=int,
        default=3,
        help="Number of days between first and second scan of group.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=15,
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
    group_end = {}
    for file in files:
        group_name = file.split("/")[1].split("_")[1]
        report_file = file.split("/")[-1]
        group_date = report_file.split("_")[1]

        if group_name not in group_start or group_date < group_start[group_name]:
            group_start[group_name] = group_date
        if group_name not in group_end or group_date > group_end[group_name]:
            group_end[group_name] = group_date
    args.start_dates = group_start
    args.end_dates = group_end

    args.files = files
    args.file_num = len(files)

    asyncio.run(main(args))
