import asyncio
import socket
from datetime import datetime

import requests

WAITING_TIME = 32
MALICIOUS_CONFIDENSE_THRESHOLD = 0.25
SUSPICIOUS_CONFIDENSE_THRESHOLD = 0.15
VIRUSTOTAL_RESET_TIME = 3


def wait_for_connection():
    while True:
        try:
            # Attempt to connect to a well-known host (Google's public DNS)
            socket.create_connection(("8.8.8.8", 53), timeout=5)
        except TimeoutError:
            pass
        else:
            return True


def info_print(text):
    timezone = datetime.now().astimezone().tzinfo
    print(f"{datetime.now(tz=timezone).time()} | {text}", flush=True)  # noqa: T201


async def check_vt_quota(session, apikey):
    headers = {"x-apikey": apikey, "accept": "application/json"}

    quota_url = "https://www.virustotal.com/api/v3/users/" + apikey + "/overall_quotas"
    quota_resp = {}
    try:
        async with session.get(quota_url, headers=headers) as resp:
            quota_resp = await resp.json()
            daily = quota_resp["data"]["api_requests_daily"]
            hourly = quota_resp["data"]["api_requests_hourly"]
            return {"api_requests_daily": daily, "api_requests_hourly": hourly}
    except Exception as e:
        info_print(f"Error while retrieving quota {e} \n {quota_resp}")
        if quota_resp.get("error", {}).get("code", "") == "QuotaExceededError":
            return {
                "api_requests_daily": {"user": {"allowed": 500, "used": 500}},
                "api_requests_hourly": {"user": {"allowed": 500, "used": 500}},
            }

        return {
            "api_requests_daily": {"user": {"allowed": 500, "used": 501}},
            "api_requests_hourly": {"user": {"allowed": 500, "used": 501}},
        }


async def vt_scan_ip(session, search_term, apikey):
    ip, _ = search_term.split(":")
    testing = ""
    try:
        headers = {
            "accept": "application/json",
            "x-apikey": apikey,
            "content-type": "application/x-www-form-urlencoded",
        }
        async with session.post(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/analyse",
            headers=headers,
        ) as resp:
            testing = await resp.text()
            data = await resp.json()
            return await vt_get_ip_analysis(session, data["data"]["id"], apikey)
    except Exception as e:
        if testing.find("Too Many Requests") != -1:
            info_print("VirusTotal too many requests")
            await asyncio.sleep(2 * WAITING_TIME)
            return await vt_scan_ip(session, search_term, apikey)
        if testing.find("QuotaExceededError") != -1:
            info_print(f"VirusTotal quota exceeded ({search_term})")
            await asyncio.sleep(4 * WAITING_TIME)
            return {}
        if f"{e}".startswith("Cannot connect to host"):
            info_print("Lost connection")
            wait_for_connection()
            info_print("Connection restored")
            await asyncio.sleep(WAITING_TIME)
            return await vt_scan_ip(session, search_term, apikey)
        info_print(f"\nAn error occurred for vt_url {search_term}: \n{e} \n{testing}")
        return {}


async def vt_get_ip_analysis(session, analysis_id, apikey):
    request_num = 0
    report_after = 5
    response = {"attributes": {"status": "not_completed"}}
    try:
        headers = {"accept": "application/json", "x-apikey": apikey}
        while response["attributes"]["status"] != "completed":
            res_status = response["attributes"]["status"]
            if res_status == "unspecified":
                return response  # Panic return
            if res_status == "queued":
                info_print(f"VT queued. Waiting for {4 * WAITING_TIME} seconds before retrying...")
                await asyncio.sleep(4 * WAITING_TIME)
            elif res_status == "in-progress":
                info_print(f"VT in-progress. Waiting for {WAITING_TIME} seconds before retrying...")
                await asyncio.sleep(WAITING_TIME)
            else:
                info_print(f"VT {res_status}. Waiting for {WAITING_TIME} seconds before retrying...")
                await asyncio.sleep(WAITING_TIME)
            async with session.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            ) as resp:
                data = await resp.json()
                response = data.get("data", data)
            request_num += 1
        if request_num > report_after:
            info_print(f"VT tries {request_num} requests.")
    except Exception as e:
        info_print(f"\nAn error occurred for vt_id {analysis_id}: {e}\n{response}")
    else:
        return response


async def process_vt_report(vt_response, total_votes, report):
    try:
        report.update(vt_response["attributes"]["results"])
        for key, value in vt_response["attributes"]["stats"].items():
            total_votes[key] = total_votes.get(key, 0) + value
    except Exception as e:
        info_print(f"\nAn error occurred while processing VirusTotal report: {e}\n{vt_response}")
    return total_votes, report


async def ai_get_url_report(session, search_term, apikey):
    url, _ = search_term.split(":")
    testing = ""
    try:
        querystring = {"ipAddress": url, "maxAgeInDays": "30"}
        headers = {"Accept": "application/json", "Key": apikey}
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=querystring,
        ) as resp:
            testing = await resp.text()
            return (await resp.json())["data"]
    except Exception as e:
        info_print(f"\nAn error occurred for ai_url {search_term}: \n{e} \n{testing}")
        return {}


async def process_ai_report(ai_response, total_votes, report):
    try:
        if ai_response["abuseConfidenceScore"] > MALICIOUS_CONFIDENSE_THRESHOLD * 100:
            report["AbuseIPDB"] = {"category": "malicious"}
            total_votes["malicious"] = total_votes.get("malicious", 0) + 1
        elif ai_response["abuseConfidenceScore"] > SUSPICIOUS_CONFIDENSE_THRESHOLD * 100:
            report["AbuseIPDB"] = {"category": "suspicious"}
            total_votes["suspicious"] = total_votes.get("suspicious", 0) + 1
        else:
            report["AbuseIPDB"] = {"category": "harmless"}
            total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    except Exception as e:
        info_print(f"\nAn error occurred while processing AbuseIPDB report: {e}\n{ai_response}")
    return total_votes, report


async def cs_get_url_report(session, search_term, _apikey, secret):
    url, _ = search_term.split(":")
    testing = ""
    try:
        headers = {
            # "X-Organization-ID": apikey,
            "Accept": "application/json",
            "authorization": f"Bearer {secret}",
        }
        async with session.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{url}",
            headers=headers,
        ) as resp:
            testing = await resp.text()
            return await resp.json()
    except Exception as e:
        if "insufficient balance" in f"{e}":
            info_print(f"Censys quota exceeded ({search_term})")
        else:
            info_print(f"\nAn error occurred for cs_url {search_term}: \n{e} \n{testing}")
        return {}


async def process_cs_report(cs_response, total_votes, report):
    try:
        if "labels" in cs_response["result"]["resource"]:
            for label in cs_response["result"]["resource"]["labels"]:
                if "c2" in label["value"] or "c2" in label:
                    info_print("Censys found c2 label. Houray!")
                    report["Censys"] = {"category": "malicious"}
                    total_votes["malicious"] = total_votes.get("malicious", 0) + 1
                    total_votes["harmless"] = total_votes.get("harmless", 0) - 1
                    return total_votes, report
        if "services" in cs_response["result"]:
            for service in cs_response["result"]["services"]:
                for label in service["labels"]:
                    if "c2" in label["value"] or "c2" in label:
                        info_print("Censys found c2 label. Houray!")
                        report["Censys"] = {"category": "malicious"}
                        total_votes["malicious"] = total_votes.get("malicious", 0) + 1
                        total_votes["harmless"] = total_votes.get("harmless", 0) - 1
                        return total_votes, report
        report["Censys"] = {"category": "harmless"}
        total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    except Exception as e:
        info_print(f"\nAn error occurred while processing Censys report: {e}\n{cs_response}")
    return total_votes, report


async def tf_search_ioc(session, search_term, apikey):
    testing = ""
    try:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Auth-Key": apikey,
        }
        payload = {
            "query": "search_ioc",
            "search_term": search_term,
            "exact_match": "true",
        }
        async with session.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers=headers,
            json=payload,
        ) as resp:
            testing = await resp.text()
            return await resp.json()
    except Exception as e:
        info_print(f"\nAn error occurred for tf_search {search_term}: \n{e} \n{testing}")
        return {}


async def process_tf_report(tf_response, total_votes, report):
    try:
        if tf_response["query_status"] == "no_result":
            report["ThreatFox"] = {"category": "harmless"}
            total_votes["harmless"] = total_votes.get("harmless", 0) + 1
        else:
            report["ThreatFox"] = {"category": "malicious"}
            total_votes["malicious"] = total_votes.get("malicious", 0) + 1
    except Exception as e:
        info_print(f"\nAn error occurred while processing ThreatFox report: {e}\n{tf_response}")
    return total_votes, report


def fetch_cinsscore():
    url = "https://cinsscore.com/list/ci-badguys.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception if the request failed

        # Use regex to extract all valid IPv4 addresses
        return response.text.splitlines()
    except requests.RequestException as e:
        info_print(f"Error fetching IPs: {e}")
        return []


async def process_cb_report(cb_responce, total_votes, report):
    if cb_responce:
        report["Cinsscore"] = {"category": "malicious"}
        total_votes["malicious"] = total_votes.get("malicious", 0) + 1
    else:
        report["Cinsscore"] = {"category": "harmless"}
        total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    return total_votes, report


def fetch_openphish():
    url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    missed = 0
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception if the request failed

        # Split the response text into lines (each line is a URL)
        urls = response.text.splitlines()

        ips = []
        for hostname in urls:
            domain = hostname.split("//")[-1].split("/")[0]
            try:
                ip = socket.gethostbyname_ex(domain)[2]
                ips.extend(ip)
            except Exception:
                missed += 1
    except requests.RequestException as e:
        info_print(f"Error fetching URLs: {e}")
        return []
    else:
        return ips, missed


async def process_op_report(op_response, total_votes, report):
    if op_response:
        report["OpenPhish_pub"] = {"category": "malicious"}
        total_votes["malicious"] = total_votes.get("malicious", 0) + 1
    else:
        report["OpenPhish_pub"] = {"category": "harmless"}
        total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    return total_votes, report


async def fetch_silentpush(session, search_term, apikey):
    url, _ = search_term.split(":")
    testing = ""
    try:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {apikey}",
        }
        async with session.get(
            f"https://api.silentpush.com/api/v1/merge-api/explore/ipv4/riskscore/{url}",
            headers=headers,
        ) as resp:
            testing = await resp.text()
            return await resp.json()
    except Exception as e:
        info_print(f"\nAn error occurred for silentpush {search_term}: \n{e} \n{testing}")
        return {}


async def process_sp_report(sp_response, total_votes, report):
    try:
        if sp_response.get("risk_score", 0) > MALICIOUS_CONFIDENSE_THRESHOLD * 100:
            report["SilentPush"] = {"category": "malicious"}
            total_votes["malicious"] = total_votes.get("malicious", 0) + 1
        elif sp_response.get("risk_score", 0) > SUSPICIOUS_CONFIDENSE_THRESHOLD * 100:
            report["SilentPush"] = {"category": "suspicious"}
            total_votes["suspicious"] = total_votes.get("suspicious", 0) + 1
        else:
            report["SilentPush"] = {"category": "harmless"}
            total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    except Exception as e:
        info_print(f"\nAn error occurred while processing SilentPush report: {e}\n{sp_response}")
    return total_votes, report
