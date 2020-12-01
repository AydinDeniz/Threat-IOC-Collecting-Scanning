import requests
import json
import time
from polyswarm_api.api import PolyswarmAPI

total_score = 0

VTAPI = ""
MalshareAPI = ""
ALIENAPI = ""
MalshareAPI = ""
POLYAPI = ""


def VirusTotalURL(url):
    skor = 0
    zararlı = False
    urlvt = 'https://www.virustotal.com/vtapi/v2/url/scan'
    urlvtreport = 'https://www.virustotal.com/vtapi/v2/url/report'
    try:
        resource = url
        params = {'apikey': VTAPI , 'url': resource, 'allinfo': True}
        response = requests.post(urlvt, params=params)
        vttext = json.loads(response.text)
        rc = (vttext['response_code'])
        skor = URLHausURL(url) + AlienVaultURL(url) + MalshareURL(url) + PolySwarmURL(url)
        try:
            resource=vttext['url']
            params = {'apikey': VTAPI , 'resource': resource}
            response = requests.get(urlvtreport, params=params)
            vttext = json.loads(response.text)
            rc = (vttext['response_code'])
            if (rc == 0):
                final = 'Error gathering the Report.'
                print(final)
                exit(1)
            pos = str(vttext['positives'])
            total = str(vttext['total'])
            final = (pos + "/" + total)
            if(final[0] != "0"):
                zararlı = True
                print("VirusTotal: Malicious VirusTotal Score:" + final)
            else:
                print("VirusTotal: Not Malicious VirusTotal Score:" + final)


        except ValueError:
            print("Error while connecting to Virus Total!\n")
    except ValueError:
        print("Error while connecting to Virus Total!\n")
    if(zararlı):
        return skor + 1
    else:
        return skor + 0
def URLHausURL(url):
    haustext = ''
    hausresponse = ''
    finalurl5 = ''

    try:
        requestsession5 = requests.Session()
        requestsession5.headers.update({'accept': 'application/json'})
        params = {"url": url}
        hausresponse = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data=params)
        haustext = json.loads(hausresponse.text)
        if(haustext.get("query_status") != "no_results"):
            print("URLHaus: Malicious")
            return 1
        elif(haustext.get("query_status") == "no_results"):
            print("UrlHaus: Not Malicious")
            return 0
    except (BrokenPipeError, IOError, TypeError):
        exit(1)
    except ValueError as e:
        print(e)
        print(("Error while connecting to URLhaus!\n"))
    return 0
def AlienVaultURL(url):
    hatext = ''
    haresponse = ''
    history = '10'
    user_agent = {'X-OTX-API-KEY': ALIENAPI}
    search_params = {'limit': history}
    myargs = url
    try:
        resource = "http://otx.alienvault.com/api/v1"
        requestsession = requests.Session()
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'indicators', 'url', myargs, 'general'])
        haresponse = requestsession.post(url=finalurl, headers=user_agent, params=search_params)
        hatext = json.loads(haresponse.text)
        if((len(hatext.get("pulse_info").get("related").get("alienvault").get("malware_families"))) == 0):
            print("AlienVault: Zararsız")
            return 0
        elif((len(hatext.get("pulse_info").get("related").get("alienvault").get("malware_families"))) != 0):
            print("AlienVault: Zararlı")
            return 1
    except ValueError as e:
        print(e)
        print(("Error while connecting to Alien Vault!\n"))
    return 0
def MalshareURL(url):
    api_key = MalshareAPI
    url = "https://malshare.com/api.php?api_key=%s&action=search&query=%s" % (api_key, url)
    r = requests.get(url)
    if(r.json()):
        print("Malshare: Malicious")
        return 1
    else:
        print("Malshare: Not Malicious")
        return 0
def PolySwarmURL(url):
    polyswarm = PolyswarmAPI(key=POLYAPI)
    try:
        poly = (r'"' + url + r'"')
        metaresults = polyswarm.search_by_metadata("strings.urls:" + url)
        for y in metaresults:
            if (y.sha256):
                if (str(y.scan.get('detections', {}).get('malicious'))) != 'None':
                    print("Polyswarm: Malicious")
                    return 1
                else:
                    print("Polyswarm: Not Malicious")
                    return 0
    except Exception:
        print("Polyswarm API Quota reached.")
        return 0

#VirusTotalURL("http://182.116.116.217:59036/Mozi.m")
#URLHausURL("http://182.116.116.217:59036/Mozi.m")
#AlienVaultURL("http://182.116.116.217:59036/Mozi.m")
#MalshareURL("http://182.116.116.217:59036/Mozi.m")
#PolySwarmURL("http://182.116.116.217:59036/Mozi.m")

def URLCheck(URL):
    print("\nScanned URL: " + URL)
    print("\nUrlhaus...")
    print("AlienVault...")
    print("Malshare...")
    print("PolySwarm...")
    print("VirusTotal...\n")
    print("")
    total_score = VirusTotalURL(URL)# + URLHausURL(URL) + AlienVaultURL(URL) + MalshareURL(URL) + PolySwarmURL(URL)
    # bu kısımı yorum satırına çevirdim çünkü VirusTotalURL fonksiyonun içinde aynısı bulunuyor
    # virus totalin taraması 10 saniye sürüyor bu sırada diğer 4 taramayı aradan çıkartıyor
    # kısacası zaman tasarufu için kodu böyle yazdım
    print("\nTotal Score: " + str(total_score) + "/5")

URLCheck("http://123.235.82.206:36751/Mozi.a") #sample