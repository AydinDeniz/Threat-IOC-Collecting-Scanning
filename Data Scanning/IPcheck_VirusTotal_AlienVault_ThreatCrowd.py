import requests
import json
import time

total_score = 0

VTAPI = ""
ALIENAPI = ""

def VirusTotalIP(IP):
    vtcounter = 0
    vt = False
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': VTAPI, 'ip': IP}
    r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/" + IP ,headers={'x-apikey': VTAPI})
    try:
        response = r.json()
        if r.status_code != 200:
            print("HTTP error")
            print(r.status_code)
        for k in response.get("data").get("attributes").get("last_analysis_results"):
            if (response.get("data").get("attributes").get("last_analysis_results").get(k).get("result") != "clean" and response.get("data").get("attributes").get("last_analysis_results").get(k).get("result") != "unrated"):
                vtcounter += 1
                vt = True

        if vt == True:
            print("VirusTotal: Malicious VirusTotal Score:" + str(vtcounter))
            return 1
        else:
            print("VirusTotal: Not Malicious VirusTotal Score:" + str(vtcounter))
            return 0

    except:
        print("VirusTotal connection error!\n")
        return 0


def AlienVaultURL(url):
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
        if ((len(hatext.get("pulse_info").get("related").get("alienvault").get("malware_families"))) == 0):
            print("AlienVault: Not Malicious")
            return 0
        elif ((len(hatext.get("pulse_info").get("related").get("alienvault").get("malware_families"))) != 0):
            print("AlienVault: Malicious")
            return 1
    except ValueError as e:
        print(e)
        print(("Error while connecting to Alien Vault!\n"))
    return 0

def ThreatCrowd(IP):
    threatcrowdurl = 'https://www.threatcrowd.org/searchApi/v2/'
    hatext = ''
    haresponse = ''
    myargs = IP
    try:
        resource = 'https://www.threatcrowd.org/searchApi/v2/'
        requestsession = requests.Session( )
        requestsession.headers.update({'Content-Type': 'application/json'})
        finalurl = '/'.join([resource, 'ip', 'report'])
        haresponse = requestsession.get(url=finalurl, params={"ip":myargs})
        hatext = json.loads(haresponse.text)

        if(hatext['response_code'] == '0'):
            print("ThreatCrowd: Not Malicious")
            return 0

        if(not '200' in str(haresponse)):
            print("ThreatCrowd connection error")
            return 0
        if(hatext.get("votes") < 0):
            print("ThreatCrowd: Malicious")
            return 1

        print(type(hatext))

    except ValueError as e:
        print(e)
        print((mycolors.foreground.lightred + "Error while connecting to ThreatCrowd!\n"))
        return 0

def IPCheck(IP):
    total_score = 0
    print("\nScanned IP Addresses: " + IP)
    print("\nVirusTotal...")
    print("AlienVault...")
    print("ThreatCrowd...")
    print("")
    total_score += VirusTotalIP(IP)
    total_score += AlienVaultURL(IP)
    total_score += ThreatCrowd(IP)
    print("\nTotal Score: " + str(total_score) + "/3")

IPCheck("188.40.75.132")#sample ip address to check
