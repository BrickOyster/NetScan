import os, argparse, csv

from dotenv import load_dotenv
from vendors import vt_scan_url, vt_get_url_analysis, ai_get_url_report
from time import sleep
from datetime import datetime

def main(args):
    # Loading API keys from environment variables
    load_dotenv()
    KEYS = {
        "VIRUSTOTAL": os.getenv("VIRUSTOTAL").split(","),
        "ABUSEIPDB": os.getenv("ABUSEIPDB").split(","),
        "CENSYS": os.getenv("CENSYS").split(","),
        "GRAYNOISE": os.getenv("GRAYNOISE").split(","),
    }
    key_num = { service: 0 for service in KEYS if KEYS[service] is not None and KEYS[service] != "None" }
    key_limit = { service: 0 for service in KEYS if KEYS[service] is not None and KEYS[service] != "None" }
    key_in_use = { service: None for service in KEYS if KEYS[service] is not None and KEYS[service] != "None" }
    def get_next_key(service):
        nonlocal key_num, key_limit, key_in_use
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
    
    for file in args.files:
        date = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        with open(file, newline='') as csvfile, open(f'{csvfile.name.split(".")[0]}_report_{date}.csv', 'w', newline='') as report_file:
            reader = csv.reader(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            next(reader)
            writer = csv.writer(report_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(['Date','Domain','IP','Port','label','prob','total_votes','report', 'vt_response', 'ai_response', 'cs_response', 'gn_response'])
            wr = 0
            for row in reader:
                Date, Domain, IP, Port = row[:4]
                label, prob = row[-2:]

                report = {}
                total_votes = {}

                if key_limit["VIRUSTOTAL"] <= 0:
                    get_next_key("VIRUSTOTAL")
                vt_response = {}
                if key_in_use["VIRUSTOTAL"]:
                    analysis_id = vt_scan_url(f'{IP}:{Port}', key_in_use["VIRUSTOTAL"])
                    vt_response, request_num = vt_get_url_analysis(analysis_id, key_in_use["VIRUSTOTAL"]) 
                    
                    wr += ( request_num - 1 )
                    key_limit["VIRUSTOTAL"] -= ( request_num + 1 )
                    # Process results
                    report.update(vt_response['attributes']['results'])
                    for key, value in vt_response['attributes']['stats'].items():
                        total_votes[key] = total_votes.get(key, 0) + value

                if key_limit["ABUSEIPDB"] == 0:
                    get_next_key("ABUSEIPDB")
                ai_response = {}
                if key_in_use["ABUSEIPDB"]:
                    ai_response = ai_get_url_report(f'{IP}:{Port}', key_in_use["ABUSEIPDB"])

                    key_limit["ABUSEIPDB"] -= 1
                    # Process results
                    if ai_response["abuseConfidenceScore"] > 50:
                        report["AbuseIPDB"] = {'category': 'malicious'}
                        total_votes["malicious"] = total_votes.get("malicious", 0) + 1
                    else:
                        report["AbuseIPDB"] = {'category': 'harmless'}
                        total_votes["harmless"] = total_votes.get("harmless", 0) + 1

                if key_limit["CENSYS"] == 0:
                    get_next_key("CENSYS")
                cs_response = {}

                if key_limit["GRAYNOISE"] == 0:
                    get_next_key("GRAYNOISE")
                gn_response = {}

                writer.writerow([Date, Domain, IP, Port, label, prob, total_votes, report, vt_response, ai_response, cs_response, gn_response])
                print(f'\r{IP}:{Port} - Wasted reqs: {wr}.', end='       ')
        print(f'\rReport for {file} has been generated with {wr} wasted requests.', end='   \n')

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