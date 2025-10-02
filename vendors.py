import aiohttp, asyncio, json, socket, ipaddress
import vt
from time import sleep


async def vt_scan_url(session, url, apikey):
    """
    Submits a URL for scanning on VirusTotal.
    request: https://docs.virustotal.com/reference/url
    """
    try:
        payload = {"url": url}
        headers = {
            "accept": "application/json",
            "x-apikey": apikey,
            "content-type": "application/x-www-form-urlencoded",
        }
        async with session.post(
            "https://www.virustotal.com/api/v3/urls", headers=headers, data=payload
        ) as resp:
            data = await resp.json()
            return data["data"]["id"]
    except Exception as e:
        print(f"An error occurred for vt_url {url}: {e}")


async def vt_get_url_analysis(session, id, apikey):
    """
    Fetches the URL analysis from VirusTotal.
    request: https://docs.virustotal.com/reference/url
    """
    request_num = 0
    response = {"attributes": {"status": "not_completed"}}
    try:
        headers = {"accept": "application/json", "x-apikey": apikey}
        await asyncio.sleep(20)
        while response["attributes"]["status"] != "completed":
            await asyncio.sleep(5 * request_num)
            async with session.get(
                f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers
            ) as resp:
                data = await resp.json()
                response = data["data"]
            request_num += 1
        return response
    except Exception as e:
        print(f"An error occurred for vt_id {id}: {e}")


async def ai_get_url_report(session, url, apikey):
    """
    Fetches the URL report from AbuseIPDB.
    request: https://docs.abuseipdb.com/?python#check-endpoint
    """
    try:
        querystring = {"ipAddress": url, "maxAgeInDays": "30"}
        headers = {"Accept": "application/json", "Key": apikey}
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=querystring,
        ) as resp:
            decodedResponse = await resp.json()
            return decodedResponse["data"]
    except Exception as e:
        print(f"An error occurred for ai_url {url}: {e}")


async def cs_get_url_report(session, url, apikey, secret):
    """
    Fetches the URL report from Censys.
    request: https://
    """
    try:
        headers = {"Accept": "application/json"}
        auth = aiohttp.BasicAuth(apikey, secret)
        async with session.get(
            f"https://search.censys.io/api/v2/hosts/{url}",
            headers=headers,
            auth=auth,
        ) as resp:
            return await resp.json()
    except Exception as e:
        print(f"An error occurred for cs_url {url}: {e}")
