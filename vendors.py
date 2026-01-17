import aiohttp, asyncio, socket, requests, re

WAITING_TIME = 40


async def check_connection():
    try:
        # Attempt to connect to a well-known host (Google's public DNS)
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except Exception as e:
        return False


async def check_vt_quota(apikey):
    headers = {"x-apikey": apikey, "accept": "application/json"}

    quota_url = "https://www.virustotal.com/api/v3/users/" + apikey + "/overall_quotas"
    quota_resp = {}
    try:
        quota_resp = requests.get(quota_url, headers=headers).json()
        daily = quota_resp["data"]["api_requests_daily"]
        hourly = quota_resp["data"]["api_requests_hourly"]
        return {"api_requests_daily": daily, "api_requests_hourly": hourly}
    except Exception as e:
        print(f"Error while retrieving quota {e} \n {quota_resp}")
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
    """
    Submits an IP for scanning on VirusTotal.
    request: https://docs.virustotal.com/reference/rescan-ip
    """
    ip, port = search_term.split(":")
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
            print("VirusTotal too many requests")
            await asyncio.sleep(2 * WAITING_TIME)
            return await vt_scan_ip(session, search_term, apikey)
        if f"{e}".startswith("Cannot connect to host"):
            print("Lost connection")
            while not await check_connection():
                await asyncio.sleep(WAITING_TIME)
            print("Connection restored")
            await asyncio.sleep(WAITING_TIME)
            return await vt_scan_ip(session, search_term, apikey)
        print(f"\nAn error occurred for vt_url {search_term}: \n{e} \n{testing}")
        return {}


async def vt_get_ip_analysis(session, id, apikey):
    """
    Fetches the URL analysis from VirusTotal.
    request: https://docs.virustotal.com/reference/url
    """
    request_num = 0
    response = {"attributes": {"status": "not_completed"}}
    try:
        headers = {"accept": "application/json", "x-apikey": apikey}
        while response["attributes"]["status"] != "completed":
            if response["attributes"]["status"] == "unspecified":
                return response  # Panic return
            await asyncio.sleep(WAITING_TIME)
            async with session.get(
                f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers
            ) as resp:
                data = await resp.json()
                response = data["data"]
            request_num += 1
        return response
    except Exception as e:
        print(f"\nAn error occurred for vt_id {id}: {e}")


async def process_vt_report(vt_response, total_votes, report):
    try:
        report.update(vt_response["attributes"]["results"])
        for key, value in vt_response["attributes"]["stats"].items():
            total_votes[key] = total_votes.get(key, 0) + value
    except Exception as e:
        print(
            f"\nAn error occurred while processing VirusTotal report: {e}\n{vt_response}"
        )
    finally:
        return total_votes, report


async def ai_get_url_report(session, search_term, apikey):
    """
    Fetches the URL report from AbuseIPDB.
    request: https://docs.abuseipdb.com/?python#check-endpoint
    """
    url, port = search_term.split(":")
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
            decodedResponse = await resp.json()
            return decodedResponse["data"]
    except Exception as e:
        print(f"\nAn error occurred for ai_url {search_term}: \n{e} \n{testing}")
        return {}


async def process_ai_report(ai_response, total_votes, report):
    try:
        if ai_response["abuseConfidenceScore"] > 25:
            report["AbuseIPDB"] = {"category": "malicious"}
            total_votes["malicious"] = total_votes.get("malicious", 0) + 1
        elif ai_response["abuseConfidenceScore"] > 10:
            report["AbuseIPDB"] = {"category": "suspicious"}
            total_votes["suspicious"] = total_votes.get("suspicious", 0) + 1
        else:
            report["AbuseIPDB"] = {"category": "harmless"}
            total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    except Exception as e:
        print(
            f"\nAn error occurred while processing AbuseIPDB report: {e}\n{ai_response}"
        )
    finally:
        return total_votes, report


async def cs_get_url_report(session, search_term, apikey, secret):
    """
    Fetches the URL report from Censys.
    request: https://
    """
    url, port = search_term.split(":")
    testing = ""
    try:
        headers = {"Accept": "application/json"}
        auth = aiohttp.BasicAuth(apikey, secret)
        async with session.get(
            f"https://search.censys.io/api/v2/hosts/{url}",
            headers=headers,
            auth=auth,
        ) as resp:
            testing = await resp.text()
            return await resp.json()
    except Exception as e:
        print(f"\nAn error occurred for cs_url {search_term}: \n{e} \n{testing}")
        return {}


async def process_cs_report(cs_response, total_votes, report):
    try:
        if (
            "labels" in cs_response["result"]
            and "c2" in cs_response["result"]["labels"]
        ):
            report["Censys"] = {"category": "malicious"}
            total_votes["malicious"] = total_votes.get("malicious", 0) + 1
        else:
            report["Censys"] = {"category": "harmless"}
            total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    except Exception as e:
        print(f"\nAn error occurred while processing Censys report: {e}\n{cs_response}")
    finally:
        return total_votes, report


async def tf_search_ioc(session, search_term, apikey):
    """
    Searches ThreatFox (abuse.ch) for an IOC.
    request: https://threatfox-api.abuse.ch/api/v1/
    """
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
        print(f"\nAn error occurred for tf_search {search_term}: \n{e} \n{testing}")
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
        print(
            f"\nAn error occurred while processing ThreatFox report: {e}\n{tf_response}"
        )
    finally:
        return total_votes, report


def fetch_cinsscore():
    """
    Fetches the list of 'bad guy' IPs from cinsscore.com and returns them as a list of strings.
    """
    url = "https://cinsscore.com/list/ci-badguys.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception if the request failed

        # Use regex to extract all valid IPv4 addresses
        ips = response.text.splitlines()
        return ips
    except requests.RequestException as e:
        print(f"Error fetching IPs: {e}")
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
    """
    Fetches the list of phishing URLs from OpenPhish and returns them as a list of strings.
    """
    url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    test = ""
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
            except Exception as e:
                missed += 1
        return ips, missed
    except requests.RequestException as e:
        print(f"Error fetching URLs: {e}")
        return []


async def process_op_report(op_response, total_votes, report):
    if op_response:
        report["OpenPhish_pub"] = {"category": "malicious"}
        total_votes["malicious"] = total_votes.get("malicious", 0) + 1
    else:
        report["OpenPhish_pub"] = {"category": "harmless"}
        total_votes["harmless"] = total_votes.get("harmless", 0) + 1
    return total_votes, report
