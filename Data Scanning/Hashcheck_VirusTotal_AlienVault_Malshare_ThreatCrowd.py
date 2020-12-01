import requests
import json
import time

total_score = 0

VTAPI = ""
MalshareAPI = ""
ALIENAPI = ""


def VirusTotalHash(hash):
    params = {'apikey': VTAPI , 'resource': hash}
    r = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    try:
        response = r.json()
        if r.status_code != 200:
            print("HTTP error")
            print(r.status_code)
            return 0
    except:
        print("Hata!\nAPI Request hakkı kalmadı")
        return 0
    if response.get("positives") != 0:
        print("VirusTotal: Malicious VirusTotal Score:" + str(response.get("positives")))
        return 1
    else:
        print("VirusTotal: Not Malicious")
        return 0

def MalshareHash(hash):
    url = "https://malshare.com/api.php?api_key=%s&action=search&query=%s" % (MalshareAPI, hash)
    try:
        r = requests.get(url)
    except:
        return 0
    if len(r.json()) != 0:
        print("Malshare: Malicious")
        return 1
    else:
        print("Malshare: Not Malicious")
        return 0

def AlienVaultHash(hash):
    url = 'http://otx.alienvault.com/api/v1'
    hatext = ''
    haresponse = ''
    history = '10'
    user_agent = {'X-OTX-API-KEY': ALIENAPI}
    search_params = {'limit': history}
    myargs = hash
    try:
        resource = url
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource,'indicators', 'file', myargs])
        haresponse = requestsession.post(url=finalurl, headers=user_agent, params=search_params)
        hatext = json.loads(haresponse.text)
        if((len(hatext.get("pulse_info").get("related").get("alienvault").get("malware_families"))) == 0):
            print("AlienVault: Not Malicious")
            return 0
        elif((len(hatext.get("pulse_info").get("related").get("alienvault").get("malware_families"))) != 0):
            print("AlienVault: Malicious")
            return 1
    except ValueError as e:
        print("AlienVault connection error")
        return 0
    return 0

def URLHausHash(hash):
    haustext = ''
    haus = 'https://urlhaus-api.abuse.ch/v1/payload/'
    hausresponse = ''
    finalurl9 = ''
    params = ''
    try:
        requestsession9 = requests.Session()
        requestsession9.headers.update({'accept': 'application/json'})
        if ((len(hash)==32)):
            params = {"md5_hash": hash}
        hausresponse = requests.post(haus, data=params)
        haustext = json.loads(hausresponse.text)
        if ((len(hash)==64)):
            params = {"sha256_hash": hash}
        hausresponse = requests.post(haus, data=params)
        haustext = json.loads(hausresponse.text)

        if haustext.get('query_status') != 'no_results':
            print("URLHaus: Malicious")
            return 1
        else:
            print("URLHaus: Not Malicious")
            return 0
    except:
        print("URLHaus connection error")
        return 0

def ThreatCrowdHash(hash):
    hatext = ''
    haresponse = ''
    myargs = hash
    try:
        resource = 'https://www.threatcrowd.org/searchApi/v2/'
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'file', 'report'])
        haresponse = requestsession.get(url=finalurl, params={"resource":myargs})
        hatext = json.loads(haresponse.text)
        if(hatext['response_code'] == '0'):
            print("ThreatCrowd: Not Malicious")
            return 0

        if len(hatext.get("scans")) > 0:
            print("ThreatCrowd: Malicious")
            return 1

        if(not '200' in str(haresponse)):
            print("ThreatdCrowd cant connect")
            return 0
    except:
        print("ThreatCrowd cant connect")
        return 0


def HashCheck(hash):
    total_score = 0
    print("\nTaratılan Hash: " + hash)
    print("\nVirusTotal...")
    print("Malshare...")
    print("AlienVault...")
    print("URLHaus...")
    print("ThreatCrowd...")
    print("")
    total_score += VirusTotalHash(hash)
    total_score += MalshareHash(hash)
    total_score += AlienVaultHash(hash)
    total_score += URLHausHash(hash)
    total_score += ThreatCrowdHash(hash)
    print("\nTotal Score: " + str(total_score) + "/5")

HashCheck("f688a3a22b55aa0d26c62ce74aaafe8300ccfa9ae6a2d4c7b47e4679ed338c9c") #sample hash

