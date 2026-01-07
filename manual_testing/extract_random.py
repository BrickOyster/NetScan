import csv, random, argparse

parser = argparse.ArgumentParser(description="Chose random 100 lines.")
parser.add_argument(
    "-i", "--infile", required=True, help="Input file"
)
parser.add_argument(
    "-o", "--outfile", default="results.csv", help="Input file"
)
parser.add_argument(
    "-n", "--entrynumber", default=150, help="Number of entries to extract"
)
args = parser.parse_args()

with open(args.infile) as csvinfile, open(args.outfile, "w") as csvoutfile:
    data = csv.DictReader(csvinfile)
    header = data.fieldnames
    sampled_data = random.sample(list(data), args.entrynumber)
    
    writer = csv.DictWriter(csvoutfile,header)
    writer.writeheader()
    writer.writerows(sampled_data)
