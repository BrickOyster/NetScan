import os, argparse, csv

from dotenv import load_dotenv
from vendors import vt_scan_url, vt_get_url_analysis, vt_get_url_report

def main(args):
    # Loading API keys from environment variables
    load_dotenv()
    KEYS = {
        "VIRUSTOTAL": os.getenv("VIRUSTOTAL"),
        "ABUSEIPDB": os.getenv("ABUSEIPDB"),
        "CENSYS": os.getenv("CENSYS"),
        "GRAYNOISE": os.getenv("GRAYNOISE"),
    }
    key_num = { service: 0 for service in KEYS if KEYS[service] is not None and KEYS[service] != "None" }
    key_limit = { service: 0 for service in KEYS if KEYS[service] is not None and KEYS[service] != "None" }
    key_in_use = { service: None for service in KEYS if KEYS[service] is not None and KEYS[service] != "None" }
    def get_next_key(service):
        nonlocal key_num, key_limit, key_in_use
        if service in KEYS:
            key_tuple = KEYS[service].split(",")[key_num[service]]
            key_num[service] += 1
            key, limit = key_tuple.split("::")
            key_limit[service] = int(limit)
            key_in_use[service] = key
    
    for file in args.files:
        with open(file, newline='') as csvfile, open(f'{csvfile.name.split(".")[0]}_report.csv', 'w', newline='') as report_file:
            reader = csv.reader(csvfile, delimiter=',')
            writer = csv.writer(report_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(['Date','Domain','IP','Port','label','prob','report','total_votes'])
            
            next(reader)
            for row in reader:
                Date, Domain, IP, Port = row[:4]
                label, prob = row[-2:]

                report = {}
                total_votes = {}

                if key_limit["VIRUSTOTAL"] == 0:
                    get_next_key("VIRUSTOTAL")
                    
                if key_in_use["VIRUSTOTAL"]:
                    analysis_id = vt_scan_url(f'{IP}:{Port}', key_in_use["VIRUSTOTAL"])
                    key_limit["VIRUSTOTAL"] -= 1
                    stats, results, request_num = vt_get_url_analysis(analysis_id, key_in_use["VIRUSTOTAL"])
                    key_limit["VIRUSTOTAL"] -= request_num
                    report.update(results)
                    for key, value in stats.items():
                        total_votes[key] = total_votes[key] + value if key in total_votes else value

                writer.writerow([Date, Domain, IP, Port, label, prob, report, total_votes])
                print(f' {request_num+1} \n')



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch URL reports.")
    parser.add_argument('files', nargs='+', help='CSV files to process')
    args = parser.parse_args()
    if not args.files:
        print("No files provided. Please specify CSV files to process.")
    else:
        if not all(os.path.isfile(file) for file in args.files):
            print("One or more files do not exist. Please check the file paths.")
    
    main(args)