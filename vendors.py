import requests, json, socket, ipaddress
import vt
from time import sleep

def vt_scan_url(url, apikey):
    """
    Submits a URL for scanning on VirusTotal.
    request: https://docs.virustotal.com/reference/url
    py package: https://github.com/VirusTotal/vt-py
    """
    try:
        payload = { "url": url }
        headers = {
            "accept": "application/json",
            "x-apikey": apikey,
            "content-type": "application/x-www-form-urlencoded"
        }

        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload).json()["data"]
        
        return response['id']
    except vt.APIError as e:
        print(f"API error for {url}: {e}")
    except Exception as e:
        print(f"An error occurred for {url}: {e}")

def vt_get_url_analysis(id, apikey):
    """
    Fetches the URL analysis from VirusTotal.
    request: https://docs.virustotal.com/reference/url
    py package: https://github.com/VirusTotal/vt-py
    """
    request_num = 0
    response={'attributes':{'status': 'not_completed'}}
    try:
        headers = {"accept": "application/json", "x-apikey": apikey}

        sleep(10)
        while response['attributes']['status'] != 'completed':
            sleep(5*request_num)
            response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers).json()["data"]
            request_num += 1
            
        return response, request_num
    except vt.APIError as e:
        print(f"API error for {id}: {e}")
    except Exception as e:
        print(f"An error occurred for {id}: {e}")

def vt_get_url_report(url, apikey):
    """
    Fetches the URL report from VirusTotal.
    request: https://docs.virustotal.com/reference/url
    py package: https://github.com/VirusTotal/vt-py
    """
    try:
        headers = {"accept": "application/json", "x-apikey": apikey}
        url_id = vt.url_id(url)

        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers).json()["data"]

        return response['attributes']['last_analysis_stats'], response['attributes']['last_analysis_results']
    except vt.APIError as e:
        print(f"API error for {url}: {e}")
    except Exception as e:
        print(f"An error occurred for {url}: {e}")

def ai_get_url_report(url, apikey):
    """
    Fetches the URL report from AbuseIPDB.
    request: https://docs.abuseipdb.com/?python#check-endpoint
    """
    try:
        try:
            url_ip = url.split(':')[0]
            ipaddress.ip_address(url_ip)
        except ValueError:
            url_ip = socket.gethostbyname(url) if not url.startswith('http') else socket.gethostbyname(url.split('//')[1])
        
        querystring = {
            'ipAddress': url_ip,
            'maxAgeInDays': '30'
        }
        headers = {
            'Accept': 'application/json',
            'Key': apikey
        }

        response = requests.request(method='GET', url='https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)

        # Formatted output
        decodedResponse = json.loads(response.text)
        return decodedResponse["data"]
    except Exception as e:
        print(f"An error occurred for {url}: {e}")
