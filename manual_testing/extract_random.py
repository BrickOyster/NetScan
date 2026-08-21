#!/usr/bin/env python3
import argparse
import csv
import random
from pathlib import Path

parser = argparse.ArgumentParser(description="Chose random 100 lines.")
parser.add_argument("-i", "--infile", required=True, help="Input file")
parser.add_argument("-o", "--outfile", default="results.csv", help="Input file")
parser.add_argument("-n", "--entrynumber", default=150, help="Number of entries to extract")
args = parser.parse_args()

with (
    Path(args.infile).open(encoding="utf-8") as csvinfile,
    Path(args.outfile).open("w", encoding="utf-8") as csvoutfile,
):
    data = csv.DictReader(csvinfile)
    header = data.fieldnames or []
    sampled_data = random.sample(list(data), args.entrynumber)

    writer = csv.DictWriter(csvoutfile, header)
    writer.writeheader()
    writer.writerows(sampled_data)
