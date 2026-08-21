#!/usr/bin/env python3
import argparse
import asyncio
import csv
import glob
import io
import json
import os
import pathlib
import sys
from ast import literal_eval
from collections import defaultdict
from datetime import datetime, timedelta
from operator import itemgetter
from pprint import pprint
from typing import IO, Any

import anyio
import matplotlib.pyplot as plt

from available_fields import compile_fields

TotalResults = dict[str, list[tuple[str, int, int]]]
ReportResults = dict[str, list[tuple[str, dict[str, Any]]]]

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


def _open_csv(file_path: str) -> io.TextIOWrapper:
    return pathlib.Path(file_path).open(encoding="utf-8")


def _write_ip_port_series_csv(f: IO[str], results: TotalResults) -> None:
    writer = csv.writer(f)
    writer.writerow(["IP", "Port", "Group", "Date", "MaliciousVotes", "HarmlessVotes"])
    for ip_port_group, samples in results.items():
        ip, port, group = ip_port_group.split(":")
        for date, malicious, harmless in samples:
            writer.writerow([ip, port, group, date, malicious, harmless])


def _write_total_series_csv(f: IO[str], total_results: dict[str, Any], date_diff: list[str]) -> None:
    columns = [
        "aggregate",
        "diff",
        "diff_plus",
        "diff_minus",
        "precentage",
        "diff_precentage",
        "diff_precentage_plus",
        "diff_precentage_minus",
    ]
    writer = csv.writer(f)
    writer.writerow(["DateDiff", *columns])
    for idx, date_diff_value in enumerate(date_diff):
        writer.writerow([date_diff_value, *(total_results[column][idx] for column in columns)])


def _write_engine_series_csv(f: IO[str], report_results: dict[str, Any], date_diff: list[str]) -> None:
    writer = csv.writer(f)
    writer.writerow(["Engine", "DateDiff", "Count", "MaliciousCount", "Percentage"])
    for engine_name, data in report_results.items():
        for idx, date_diff_value in enumerate(date_diff):
            writer.writerow(
                [
                    engine_name,
                    date_diff_value,
                    data["counts"][idx],
                    data["malicious_counts"][idx],
                    data["percentages"][idx],
                ],
            )


def _write_engine_summary_csv(f: IO[str], report_results: dict[str, Any]) -> None:
    writer = csv.writer(f)
    writer.writerow(["Engine", "AverageLifetime", "MaxPercentage"])
    for engine_name, data in report_results.items():
        writer.writerow([engine_name, data["average_lifetime"], max(data["percentages"])])


async def worker(_: int, queue: asyncio.Queue[str | None]) -> tuple[TotalResults, ReportResults, int]:
    results_total: TotalResults = defaultdict(list)
    results_report: ReportResults = defaultdict(list)
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
                try:
                    identifier = f"{row['IP']}:{row['Port']}:{group}"
                    total_votes = literal_eval(row.get("total_votes", {}))
                    report = literal_eval(row.get("report", {}))
                except (KeyError, ValueError, SyntaxError) as e:
                    print(f"Skipping malformed row in {file_path}: {e}")
                    continue
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


async def gather_results(args: argparse.Namespace) -> tuple[TotalResults, ReportResults, int]:
    queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=args.queue_size)  # buffer size

    # Start workers
    workers = [asyncio.create_task(worker(i, queue)) for i in range(args.workers)]

    for file in args.files:
        await queue.put(file)

    # Stop workers
    for _ in workers:
        await queue.put(None)

    await queue.join()

    all_ret = await asyncio.gather(*workers)
    total_results: TotalResults = {}
    [total_results.update(res[0]) for res in all_ret]
    report_results: ReportResults = {}
    [report_results.update(res[1]) for res in all_ret]
    not_complete = sum(res[2] for res in all_ret)
    print("Gathered results")
    return total_results, report_results, not_complete


async def compile_total_results(
    results: TotalResults,
    all_zero_writer: csv.DictWriter[str],
    non_zero_writer: csv.DictWriter[str],
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    # Prefixed with "1" so these figure numbers can never collide with report_figures' "2"-prefixed
    # ones once matplotlib treats them as figure identifiers (plt.figure(num) creates a *new*, blank
    # figure whenever num doesn't match an already-open one, so an accidental collision here doesn't
    # error -- it silently overwrites/blanks a figure).
    total_figures: dict[str, str] = defaultdict(lambda: f"1{len(total_figures) + 1}")
    total_statistics: dict[str, Any] = {
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
    total_results: dict[str, Any] = {}

    for_precentage = [(0, 0)] * len(args.date_diff)  # (malicious, harmless)
    for_diff = [(0, 0)] * len(args.date_diff)  # (plus, minus)
    group_labels = {
        "aggregate": ("Total Malicious Votes Over Time", "Total Malicious Votes"),
        "diff": ("Change in Malicious Votes Over Time", "Change in Malicious Votes"),
        "precentage": ("Percentage of IPs with Malicious Votes Over Time", "IPs with Malicious Votes (%)"),
        "diff_precentage": (
            "Percentage Point Change in Malicious Votes Over Time",
            "Percentage Point Change (%)",
        ),
    }

    for group in ["aggregate", "diff", "precentage", "diff_precentage"]:
        plt.figure(total_figures[group], figsize=(19, 10))
        total_results[group] = [0] * len(args.date_diff)
        plt.plot(args.date_diff, [0] * len(args.date_diff), linestyle="--", color="gray")
        title, ylabel = group_labels[group]
        plt.xlabel("Date Diff")
        plt.ylabel(ylabel)
        plt.title(title)
        plt.xticks(rotation=45)

    for ip_port_group, group_res in results.items():
        ip, port, group = ip_port_group.split(":")
        start_date = datetime.fromisoformat(args.start_dates[group]).date()
        if args.do_group_graphs:
            if group not in total_figures:
                plt.figure(total_figures[group], figsize=(19, 10))
                date_list = [
                    (start_date + timedelta(days=i)).isoformat()
                    for i in range((args.end_date - args.start_date).days + 1)
                ]
                plt.plot(date_list, [0] * len(date_list), linestyle="--", color="gray")
                plt.xlabel("Date")
                plt.ylabel("Malicious Votes")
                plt.title(f"Malicious Votes Over Time per IP:Port:{group}")
                plt.xticks(rotation=45)
            plt.figure(total_figures[group])

        total_statistics["Total IP"] += 1
        all_zero = sum(v[1] for v in group_res) == 0
        if all_zero:
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
                    and group_res[1][0]
                    == (start_date + timedelta(days=group_value(args, group, "day_diff"))).isoformat()
                    and group_res[1][1] == 0
                ):
                    total_statistics["Zero first two days"] += 1
                    if any(v[1] > 0 for v in group_res[2:]):
                        total_statistics["Zero first two days detected after"] += 1
                elif (
                    len(group_res) > 1
                    and group_res[1][0]
                    == (start_date + timedelta(days=group_value(args, group, "day_diff"))).isoformat()
                ):
                    total_statistics["Off day two"] += 1
            else:
                total_statistics["Off day one"] += 1

        dates = [x[0] for x in group_res]
        malicious_votes = [x[1] for x in group_res]
        if not all_zero and args.do_group_graphs:
            plt.plot(dates, malicious_votes, marker="o", label=ip_port_group)

        for d_idx, d in enumerate(dates):
            day_diff = (datetime.fromisoformat(d).date() - start_date).days
            int_day_diff = day_diff // group_value(args, group, "day_diff")
            if day_diff % group_value(args, group, "day_diff") != 0:
                print(day_diff, group_value(args, group, "day_diff"), ip_port_group)
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
        (
            (for_diff[i][0] - for_diff[i][1]) * 100.0 / (total_results["aggregate"][i - 1])
            if total_results["aggregate"][i - 1] != 0
            else 0
        )
        for i in range(1, len(for_diff))
    ]

    plt.figure(total_figures["aggregate"])
    plt.plot(args.date_diff, total_results["aggregate"], marker="o")
    plt.figure(total_figures["precentage"])
    plt.plot(args.date_diff, total_results["precentage"], marker="o")
    plt.figure(total_figures["diff"])
    plt.plot(args.date_diff, total_results["diff"], marker="o", label="Net")
    total_results["diff_plus"] = [x[0] for x in for_diff]
    plt.plot(args.date_diff, total_results["diff_plus"], marker="o", label="Plus")
    total_results["diff_minus"] = [-x[1] for x in for_diff]
    plt.plot(args.date_diff, total_results["diff_minus"], marker="o", label="Minus")
    plt.legend()
    plt.figure(total_figures["diff_precentage"])
    plt.plot(args.date_diff, total_results["diff_precentage"], marker="o", label="Net")
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


async def compile_report_results(
    results: ReportResults, args: argparse.Namespace
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    report_figures: dict[str, str] = defaultdict(lambda: f"2{len(report_figures)}")
    report_stats: dict[str, Any] = {"Report Stats": "----------------"}
    report_results: dict[str, Any] = {}

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
                vendor_date_counts[engine_name][day_diff // group_value(args, group, "day_diff")] += 1
                if engine_name in id_expired:
                    continue

                matched_category = ["malicious", "suspicious"]
                if str(engine_result.get("category", "")).strip().lower() in set(matched_category):
                    vendor_date_malicious[engine_name][day_diff // group_value(args, group, "day_diff")] += 1
                    id_indicator_limetime[engine_name][identifier] += group_value(args, group, "day_diff")
                    id_not_detected[engine_name] = 0
                else:
                    if engine_name not in id_not_detected:
                        continue
                    id_indicator_limetime[engine_name][identifier] += group_value(args, group, "day_diff")
                    id_not_detected[engine_name] += 1
                    if id_not_detected[engine_name] >= EXPIRED_AFTER:
                        id_indicator_limetime[engine_name][identifier] -= group_value(args, group, "day_diff")
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

    engine_detected_sets = {eng: set(ids.keys()) for eng, ids in id_indicator_limetime.items()}
    all_detected = set().union(*engine_detected_sets.values()) if engine_detected_sets else set()

    detection_counts = defaultdict(int)
    for ip in all_detected:
        n = sum(1 for s in engine_detected_sets.values() if ip in s)
        detection_counts[n] += 1
    for k in sorted(detection_counts):
        report_stats[f"IPs detected by exactly {k} provider(s)"] = detection_counts[k]

    engines = sorted(engine_detected_sets.keys())
    jaccard_indices = {}
    for i, eng_a in enumerate(engines):
        for eng_b in engines[i + 1 :]:
            set_a, set_b = engine_detected_sets[eng_a], engine_detected_sets[eng_b]
            union = set_a | set_b
            jaccard = len(set_a & set_b) / len(union) if union else 0.0
            jaccard_indices[eng_a, eng_b] = jaccard

    for (eng_a, eng_b), jaccard in sorted(jaccard_indices.items(), key=itemgetter(1), reverse=True):
        report_stats[f"RQ3 Jaccard({eng_a}, {eng_b})"] = round(jaccard, 4)

    return report_stats, report_figures, report_results


async def main(args: argparse.Namespace) -> None:
    timezone = datetime.now().astimezone().tzinfo
    start_time = datetime.now(tz=timezone)
    print(f"Running analysis for {args.file_num} files from {args.folder} ...")
    print(f"Start date: {args.start_date}, End date: {args.end_date}")

    output_path = anyio.Path(args.output)
    await output_path.mkdir(exist_ok=True)
    async for file in output_path.iterdir():
        await file.unlink()

    non_zero_af = await anyio.open_file(f"{args.output}non_zero.csv", "w", newline="", encoding="utf-8")
    all_zero_af = await anyio.open_file(f"{args.output}all_zero.csv", "w", newline="", encoding="utf-8")
    stat_af = await anyio.open_file(f"{args.output}out_logs.txt", "a", encoding="utf-8")
    ip_port_series_af = await anyio.open_file(f"{args.output}ip_port_series.csv", "w", newline="", encoding="utf-8")
    total_series_af = await anyio.open_file(f"{args.output}total_series.csv", "w", newline="", encoding="utf-8")
    engine_series_af = await anyio.open_file(f"{args.output}engine_series.csv", "w", newline="", encoding="utf-8")
    engine_summary_af = await anyio.open_file(f"{args.output}engine_summary.csv", "w", newline="", encoding="utf-8")
    try:
        stat_af.wrapped.write("Analysis started with args:\n")
        pprint(vars(args), stream=stat_af.wrapped)
        stat_af.wrapped.flush()
        fieldnames = ["IP", "Port"]
        all_zero_writer = csv.DictWriter(all_zero_af.wrapped, fieldnames=fieldnames)
        all_zero_writer.writeheader()
        non_zero_writer = csv.DictWriter(non_zero_af.wrapped, fieldnames=fieldnames)
        non_zero_writer.writeheader()

        statistics: dict[str, Any] = {
            "Not complete": 0,
        }
        figures: dict[str, str] = {}

        total_ret, report_ret, not_complete = await gather_results(args)
        statistics["Not complete"] = not_complete
        _write_ip_port_series_csv(ip_port_series_af.wrapped, total_ret)

        total_results_task = asyncio.create_task(
            compile_total_results(total_ret, all_zero_writer, non_zero_writer, args),
        )
        report_results_task = asyncio.create_task(compile_report_results(report_ret, args))

        total_stats, total_figures, total_results = await asyncio.wait_for(total_results_task, timeout=None)
        statistics.update(total_stats)
        figures.update(total_figures)
        _write_total_series_csv(total_series_af.wrapped, total_results, args.date_diff)

        report_stats, report_figures, report_results = await asyncio.wait_for(report_results_task, timeout=None)
        statistics.update(report_stats)
        figures.update(report_figures)
        _write_engine_series_csv(engine_series_af.wrapped, report_results, args.date_diff)
        _write_engine_summary_csv(engine_summary_af.wrapped, report_results)

        stat_af.wrapped.writelines(f"\n{stat}: {val}" for stat, val in statistics.items())
        for i, p in figures.items():
            plt.figure(p)
            plt.savefig(f"{args.output}figure_{i}.png")
    finally:
        await non_zero_af.aclose()
        await all_zero_af.aclose()
        await stat_af.aclose()
        await ip_port_series_af.aclose()
        await total_series_af.aclose()
        await engine_series_af.aclose()
        await engine_summary_af.aclose()

    print(f"All files processed in {(datetime.now(tz=timezone) - start_time).seconds}s.")


def _load_config_overrides(folder: str) -> dict[str, Any]:
    config_path = pathlib.Path(folder) / "config.json"
    if not config_path.exists():
        return {}
    try:
        with config_path.open(encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Ignoring invalid config file {config_path}: {e}")
        return {}


def _apply_config_overrides(args: argparse.Namespace, overrides: dict[str, Any]) -> None:
    for key, value in overrides.items():
        if hasattr(args, key):
            print(f"Overriding {key}={getattr(args, key)!r} with {value!r} from config.json")
            setattr(args, key, value)


def _valid_group_overrides(
    args: argparse.Namespace, group_name: str, group_folder_path: pathlib.Path
) -> dict[str, Any]:
    overrides = _load_config_overrides(str(group_folder_path))
    valid_overrides = {}
    for key, value in overrides.items():
        if hasattr(args, key):
            print(
                f"Group {group_name}: overriding {key}={getattr(args, key)!r} with {value!r} "
                f"from {group_folder_path}/config.json",
            )
            valid_overrides[key] = value
        else:
            print(f"Group {group_name}: ignoring unknown config.json key {key!r}")
    return valid_overrides


def group_value(args: argparse.Namespace, group: str, key: str) -> Any:
    return args.group_overrides.get(group, {}).get(key, getattr(args, key))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run analysis on ip data.")
    parser.add_argument("-f", "--folder", required=True, help="Input file containing IP data")
    parser.add_argument("-t", "--top_engines", type=int, default=3, help="Number of top engines to plot.")
    parser.add_argument("-d", "--day_diff", type=int, default=3, help="Days between group scans.")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Number of concurrent worker tasks.")
    parser.add_argument("-q", "--queue_size", type=int, default=50, help="Size of the task queue.")
    parser.add_argument("-o", "--output", type=str, default="group_analysis_out_dir/", help="Output directory.")
    parser.add_argument(
        "--do_group_graphs",
        action="store_true",
        help="Also generate a per-group per-IP figure for each group (can be many for large combined runs).",
    )
    args = parser.parse_args()
    _apply_config_overrides(args, _load_config_overrides(args.folder))
    args.output = args.folder + args.output if args.folder.endswith("/") else args.folder + "/" + args.output

    # glob.glob (unlike pathlib.Path.glob, pre-3.13) follows symlinked directories during "**"
    # recursion, which matters for combined-wave folders that symlink in other waves' groups.
    pattern = str(pathlib.Path(args.folder) / "**" / "report_????-??-??_*.csv")
    files = glob.glob(pattern, recursive=True)
    if not files:
        print(f"No files found in folder {args.folder}.")
        sys.exit(1)

    group_start = {}
    group_end = {}
    group_folders = {}
    for file in files:
        group_folder = file.split("/")[1]
        group_name = group_folder.split("_")[1]
        report_file = file.split("/")[-1]
        group_date = report_file.split("_")[1]

        group_folders[group_name] = group_folder
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

    args.group_overrides = {
        group_name: _valid_group_overrides(args, group_name, pathlib.Path(args.folder) / group_folder)
        for group_name, group_folder in group_folders.items()
    }

    args.files = files
    args.file_num = len(files)

    args.start_date = datetime.fromisoformat(min(args.start_dates.values())).date()
    args.end_date = args.start_date + timedelta(days=max(group_date_diffs.values()))
    axis_day_diff = min(group_value(args, group, "day_diff") for group in group_folders)
    args.date_diff = [f"+{i}" for i in range(0, (args.end_date - args.start_date).days + 1, axis_day_diff)]

    return args


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main(args))

    args.workers = (os.cpu_count() or 11) - 4
    args.output += "group_available_fields.json"
    compile_fields(args)
