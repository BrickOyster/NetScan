import argparse
import asyncio
import csv
import io
import pathlib
import sys
from ast import literal_eval
from collections import defaultdict
from datetime import datetime, timedelta
from operator import itemgetter
from pprint import pprint

import anyio
import matplotlib.pyplot as plt

csv.field_size_limit(100000000)
services = {
    "VIRUSTOTAL": "vt",
    "ABUSEIPDB": "ai",
    "CENSYS": "cs",
    "THREATFOX": "tf",
    "CINSSCORE": "cb",
    "OPENPHIS": "op",
    "SILENTPUSH": "sp",
}  # Service name : abbreviation
INVALID_VOTES_SUM = 50
EXPIRED_AFTER = 2  # Consider an indicator expired after 2 non-detections


def _open_csv(file_path) -> io.TextIOWrapper:
    return pathlib.Path(file_path).open(encoding="utf-8")


async def worker(_, queue):
    results_total = defaultdict(list)
    results_report = defaultdict(list)
    not_complete = 0
    while True:
        file_path = await queue.get()
        if file_path is None:
            queue.task_done()
            break
        report_date = file_path.split("/")[-1].split("_")[1]
        group = file_path.split("/")[1].split("_")[1]
        with _open_csv(file_path) as in_f:
            reader = csv.DictReader(in_f)
            for row in reader:
                identifier = f"{row['IP']}:{row['Port']}:{group}"
                total_votes = literal_eval(row.get("total_votes", {}))
                report = literal_eval(row.get("report", {}))
                if sum(total_votes.values()) < INVALID_VOTES_SUM:
                    not_complete += 1
                results_total[identifier].append(
                    (
                        report_date,
                        total_votes.get("malicious", 0) + total_votes.get("suspicious", 0),
                        total_votes.get("undetected", 0) + total_votes.get("harmless", 0),
                    ),
                )
                results_report[identifier].append((report_date, report))
        queue.task_done()
    return (results_total, results_report, not_complete)


async def gather_results(args):
    queue = asyncio.Queue(maxsize=args.queue_size)  # buffer size

    # Start workers
    workers = [asyncio.create_task(worker(i, queue)) for i in range(args.workers)]

    for file in args.files:
        await queue.put(file)

    # Stop workers
    for _ in workers:
        await queue.put(None)

    await queue.join()

    all_ret = await asyncio.gather(*workers)
    total_results = {}
    [total_results.update(res[0]) for res in all_ret]
    report_results = {}
    [report_results.update(res[1]) for res in all_ret]
    not_complete = sum(res[2] for res in all_ret)
    print("Gathered results")  # noqa: T201
    return total_results, report_results, not_complete


async def compile_total_results(results, all_zero_writer, non_zero_writer, args):
    total_figures = defaultdict(lambda: len(total_figures) + 1)
    total_statistics = {
        "# Total Stats": "----------------",
        "Total IP": 0,
        "All zero votes": 0,
        "Non zero first day": 0,
        "Detected by more after non zero first day": 0,
        "Zero first day": 0,
        "Detected after zero first day": 0,
        "Zero first two days": 0,
        "Zero first two days detected after": 0,
        "Off day one": 0,
        "Off day two": 0,
    }
    total_results = {}

    for_precentage = [(0, 0)] * len(args.date_diff)  # (malicious, harmless)
    for_diff = [(0, 0)] * len(args.date_diff)  # (plus, minus)
    for group in ["aggregate", "diff", "precentage", "diff_precentage"]:
        plt.figure(total_figures[group], figsize=(19, 10))
        total_results[group] = [0] * len(args.date_diff)
        plt.plot(args.date_diff, [0] * len(args.date_diff), linestyle="--", color="gray")
        plt.xlabel("Date Diff")
        plt.ylabel("Malicious Votes")
        plt.title(f"{group} Malicious Votes Over Time")
        plt.xticks(rotation=45)

    for ip_port_group, group_res in results.items():
        ip, port, group = ip_port_group.split(":")
        start_date = datetime.fromisoformat(args.start_dates[group]).date()
        if group not in total_figures:
            plt.figure(total_figures[group], figsize=(19, 10))
            date_list = [
                (start_date + timedelta(days=i)).isoformat() for i in range((args.end_date - args.start_date).days + 1)
            ]
            plt.plot(date_list, [0] * len(date_list), linestyle="--", color="gray")
            plt.xlabel("Date")
            plt.ylabel("Malicious Votes")
            plt.title(f"Malicious Votes Over Time per IP:Port:{group}")
            plt.xticks(rotation=45)
        plt.figure(total_figures[group])

        total_statistics["Total IP"] += 1
        if sum(v[1] for v in group_res) == 0:
            all_zero_writer.writerow({"IP": ip, "Port": port})
            total_statistics["All zero votes"] += 1
        else:
            non_zero_writer.writerow({"IP": ip, "Port": port})
            # Sort by date
            group_res.sort(key=itemgetter(0))

            if group_res[0][0] == start_date.isoformat() and group_res[0][1] != 0:
                total_statistics["Non zero first day"] += 1
                if any(v[1] > group_res[0][1] for v in group_res[1:]):
                    total_statistics["Detected by more after non zero first day"] += 1
            elif group_res[0][0] == start_date.isoformat() and group_res[0][1] == 0:
                total_statistics["Zero first day"] += 1
                if any(v[1] > 0 for v in group_res[1:]):
                    total_statistics["Detected after zero first day"] += 1
                if (
                    len(group_res) > 1
                    and group_res[1][0] == (start_date + timedelta(days=args.day_diff)).isoformat()
                    and group_res[1][1] == 0
                ):
                    total_statistics["Zero first two days"] += 1
                    if any(v[1] > 0 for v in group_res[2:]):
                        total_statistics["Zero first two days detected after"] += 1
                elif len(group_res) > 1 and group_res[1][0] == (start_date + timedelta(days=args.day_diff)).isoformat():
                    total_statistics["Off day two"] += 1
            else:
                total_statistics["Off day one"] += 1

            dates = [x[0] for x in group_res]
            malicious_votes = [x[1] for x in group_res]
            plt.plot(dates, malicious_votes, marker="o", label=ip_port_group)

        dates = [x[0] for x in group_res]
        malicious_votes = [x[1] for x in group_res]
        for d_idx, d in enumerate(dates):
            day_diff = (datetime.fromisoformat(d).date() - start_date).days
            int_day_diff = day_diff // args.day_diff
            if day_diff % args.day_diff != 0:
                print(day_diff, args.day_diff, ip_port_group)  # noqa: T201
            total_results["aggregate"][int_day_diff] += malicious_votes[d_idx]
            if int_day_diff == 0:
                total_results["diff"][int_day_diff] += 0
            else:
                value_diff = malicious_votes[d_idx] - malicious_votes[d_idx - 1]
                total_results["diff"][int_day_diff] += value_diff
                if value_diff > 0:
                    for_diff[int_day_diff] = (
                        for_diff[int_day_diff][0] + value_diff,
                        for_diff[int_day_diff][1],
                    )
                elif value_diff < 0:
                    for_diff[int_day_diff] = (
                        for_diff[int_day_diff][0],
                        for_diff[int_day_diff][1] - value_diff,
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
        total_results["precentage"] = [(m * 100.0 / (m + h) if m + h > 0 else 0) for m, h in for_precentage]
        total_results["diff_precentage"] = [0] + [
            (for_diff[i][0] - for_diff[i][1]) * 100.0 / (total_results["aggregate"][i - 1])
            if total_results["aggregate"][i - 1] != 0
            else 0
            for i in range(1, len(for_diff))
        ]

    plt.figure(total_figures["aggregate"])
    plt.plot(args.date_diff, total_results["aggregate"], marker="o")
    plt.figure(total_figures["precentage"])
    plt.plot(args.date_diff, total_results["precentage"], marker="o")
    plt.figure(total_figures["diff"])
    plt.plot(args.date_diff, total_results["diff"], marker="o")
    total_results["diff_plus"] = [x[0] for x in for_diff]
    plt.plot(args.date_diff, total_results["diff_plus"], marker="o", label="Plus")
    total_results["diff_minus"] = [-x[1] for x in for_diff]
    plt.plot(args.date_diff, total_results["diff_minus"], marker="o", label="Minus")
    plt.legend()
    plt.figure(total_figures["diff_precentage"])
    plt.plot(args.date_diff, total_results["diff_precentage"], marker="o")
    total_results["diff_precentage_plus"] = [0] + [
        (for_diff[i][0] * 100.0 / total_results["aggregate"][i - 1]) if total_results["aggregate"][i - 1] != 0 else 0
        for i in range(1, len(for_diff))
    ]
    plt.plot(args.date_diff, total_results["diff_precentage_plus"], marker="o", label="Plus")
    total_results["diff_precentage_minus"] = [0] + [
        -(for_diff[i][1] * 100.0 / total_results["aggregate"][i - 1]) if total_results["aggregate"][i - 1] != 0 else 0
        for i in range(1, len(for_diff))
    ]
    plt.plot(args.date_diff, total_results["diff_precentage_minus"], marker="o", label="Minus")
    plt.legend()

    return total_statistics, total_figures, total_results


async def compile_report_results(results, args):
    report_figures = defaultdict(lambda: len(report_figures) + 20)
    report_stats = {"Report Stats": "----------------"}
    report_results = {}

    vendor_date_counts = defaultdict(lambda: [0] * len(args.date_diff))
    vendor_date_malicious = defaultdict(lambda: [0] * len(args.date_diff))
    id_indicator_limetime = defaultdict(lambda: defaultdict(int))

    for identifier, samples in results.items():
        _, _, group = identifier.split(":")
        id_not_detected = defaultdict(int)
        id_expired = set()
        sorted_samples = sorted(samples, key=itemgetter(0))

        for report_date, report_data in sorted_samples:
            day_diff = (
                datetime.fromisoformat(report_date).date() - datetime.fromisoformat(args.start_dates[group]).date()
            ).days
            for engine_name, engine_result in report_data.items():
                vendor_date_counts[engine_name][day_diff // args.day_diff] += 1
                if engine_name in id_expired:
                    continue

                matched_category = ["malicious", "suspicious"]
                if str(engine_result.get("category", "")).strip().lower() in set(matched_category):
                    vendor_date_malicious[engine_name][day_diff // args.day_diff] += 1
                    id_indicator_limetime[engine_name][identifier] += args.day_diff
                    id_not_detected[engine_name] = 0
                else:
                    if engine_name not in id_not_detected:
                        continue
                    id_indicator_limetime[engine_name][identifier] += args.day_diff
                    id_not_detected[engine_name] += 1
                    if id_not_detected[engine_name] >= EXPIRED_AFTER:
                        id_indicator_limetime[engine_name][identifier] -= args.day_diff
                        id_expired.add(engine_name)

    for engine_name in vendor_date_counts:
        counts = vendor_date_counts[engine_name]
        malicious_counts = vendor_date_malicious[engine_name]
        average_lifetime = (
            sum(id_indicator_limetime[engine_name].values()) / len(id_indicator_limetime[engine_name])
            if id_indicator_limetime[engine_name]
            else 0
        )
        percentages = [(malicious_counts[i] * 100.0 / counts[i]) if counts[i] > 0 else 0 for i in range(len(counts))]
        report_results[engine_name] = {
            "counts": counts,
            "malicious_counts": malicious_counts,
            "average_lifetime": average_lifetime,
            "percentages": percentages,
        }

    for idx, (engine_name, data) in enumerate(
        sorted(report_results.items(), key=lambda item: max(item[1]["percentages"]), reverse=True)[: args.top_engines],
    ):
        plt.figure(report_figures[f"{engine_name}_percentages_{idx + 1}"], figsize=(19, 10))
        plt.plot(args.date_diff, data["percentages"], marker="o")
        plt.xlabel("Date Diff")
        plt.ylabel("Malicious Percentage")
        plt.title(f"{engine_name} Malicious Percentage Over Time")
        plt.xticks(rotation=45)

        plt.figure(report_figures[f"{engine_name}_counts_{idx + 1}"], figsize=(19, 10))
        plt.plot(args.date_diff, data["malicious_counts"], marker="o")
        plt.xlabel("Date Diff")
        plt.ylabel("Malicious Reports")
        plt.title(f"{engine_name} Malicious Reports Over Time")
        plt.xticks(rotation=45)

        report_stats["Average Lifetime " + engine_name] = data["average_lifetime"]
        report_stats["Max Percentage " + engine_name] = max(data["percentages"])

    return report_stats, report_figures, report_results


async def main(args):
    timezone = datetime.now().astimezone().tzinfo
    start_time = datetime.now(tz=timezone)
    print(f"Running analysis for {args.file_num} files from {args.folder} ...")  # noqa: T201
    print(f"Start date: {args.start_date}, End date: {args.end_date}")  # noqa: T201

    output_path = anyio.Path(args.output)
    await output_path.mkdir(exist_ok=True)
    async for file in output_path.iterdir():
        await file.unlink()

    non_zero_af = await anyio.open_file(f"{args.output}non_zero.csv", "w", newline="", encoding="utf-8")
    all_zero_af = await anyio.open_file(f"{args.output}all_zero.csv", "w", newline="", encoding="utf-8")
    stat_af = await anyio.open_file(f"{args.output}out_logs.txt", "a", encoding="utf-8")
    try:
        stat_af.wrapped.write("Analysis started with args:\n")
        pprint(vars(args), stream=stat_af.wrapped)
        stat_af.wrapped.flush()
        fieldnames = ["IP", "Port"]
        all_zero_writer = csv.DictWriter(all_zero_af.wrapped, fieldnames=fieldnames)
        all_zero_writer.writeheader()
        non_zero_writer = csv.DictWriter(non_zero_af.wrapped, fieldnames=fieldnames)
        non_zero_writer.writeheader()

        statistics = {
            "Not complete": 0,
        }
        figures = {}

        total_ret, report_ret, not_complete = await gather_results(args)
        statistics["Not complete"] = not_complete

        total_results_task = asyncio.create_task(
            compile_total_results(total_ret, all_zero_writer, non_zero_writer, args),
        )
        report_results_task = asyncio.create_task(compile_report_results(report_ret, args))

        total_stats, total_figures, _ = await asyncio.wait_for(total_results_task, timeout=None)
        statistics.update(total_stats)
        figures.update(total_figures)

        report_stats, report_figures, _ = await asyncio.wait_for(report_results_task, timeout=None)
        statistics.update(report_stats)
        figures.update(report_figures)

        stat_af.wrapped.writelines(f"\n{stat}: {val}" for stat, val in statistics.items())
        for i, p in figures.items():
            plt.figure(p)
            plt.savefig(f"{args.output}figure_{i}.png")
    finally:
        await non_zero_af.aclose()
        await all_zero_af.aclose()
        await stat_af.aclose()

    print(f"All files processed in {(datetime.now(tz=timezone) - start_time).seconds}s.")  # noqa: T201


def parse_args():
    parser = argparse.ArgumentParser(description="Run analysis on ip data.")
    parser.add_argument("-f", "--folder", required=True, help="Input file containing IP data")
    parser.add_argument("-t", "--top_engines", type=int, default=3, help="Number of top engines to plot.")
    parser.add_argument("-d", "--day_diff", type=int, default=3, help="Days between group scans.")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Number of concurrent worker tasks.")
    parser.add_argument("-q", "--queue_size", type=int, default=50, help="Size of the task queue.")
    parser.add_argument("-o", "--output", type=str, default="group_analysis_out_dir/", help="Output directory.")
    args = parser.parse_args()
    args.output = args.folder + args.output if args.folder.endswith("/") else args.folder + "/" + args.output
    args.start_date = args.folder.split("_")[-2:-1]

    files = [str(file) for file in pathlib.Path(args.folder).glob("**/report*.csv")]
    if not files:
        print(f"No files found in folder {args.folder}.")  # noqa: T201
        sys.exit(1)

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

    group_date_diffs = defaultdict(int)
    for group, s in group_start.items():
        e = group_end[group]
        days_diff = (datetime.fromisoformat(e).date() - datetime.fromisoformat(s).date()).days
        group_date_diffs[group] = days_diff
    args.start_dates = group_start
    args.end_dates = group_end

    args.files = files
    args.file_num = len(files)

    args.start_date = datetime.fromisoformat(min(args.start_dates.values())).date()
    args.end_date = args.start_date + timedelta(days=max(group_date_diffs.values()))
    args.date_diff = [f"+{i}" for i in range(0, (args.end_date - args.start_date).days + 1, args.day_diff)]

    return args


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main(args))
