import requests
import datetime
import json

url = 'https://www.virustotal.com/api/v3/intelligence/search'
api_key = ""

def fixDate(year, month ,day):
    stringDate = str(year) + "-"

    if(month<10):
        stringDate += "0" + str(month) + "-"
    else:
        stringDate += str(month) + "-"

    if(day<10):
        stringDate += "0" + str(day)
    else:
        stringDate += str(day)

    return stringDate
def listToFile(type,list):
    print(type + " Listesi txt dosyasına yazılıyor...")
    f = open(type+".txt", 'w')
    for l in list:
        f.write(l + '\n')
        if(type == "domain"):
            f.write(str(domainListData.get(l)) + '\n')
        elif(type == "ip"):
            f.write(str(ipListData.get(l)) + '\n')
    f.close()
    print(type + " Listesi txt dosyasına yazıldı...")
def cleanRest(dict):
    list = []
    for key in dict:
        if(dict.get(key).get("result") != "clean" and dict.get(key).get("result") != "unrated"):
           list.append(key)
    return list

#-----------------domain search parametreleri------------------------

domainMinPositive = 2       #minumum positive score
domainDayCount = 1          #kaç gün öncesinden veri çekmeye başlasın?
domainLimit = 300           #veriler 10 ar 10 ar çekilecek
domainCursor = ""           #burası boş kalmalı
domainList = []
domainListData = {}

#--------------------------------------------------------------------
#-----------------hash search parametreleri----------------------

hashMinPositive = 20      #minumum positive score
hashDayCount = 1          #kaç gün öncesinden veri çekmeye başlasın?
hashLimit = 300           #veriler 300 er 300 er çekilecek
hashCursor = ""           #burası boş kalmalı
hashList = []
hashTotalSeach = 9000       #max çekilecek hash

#--------------------------------------------------------------------
#-----------------ip adres search parametreleri----------------------

ipMinPositive = 5         #minumum positive score
ipLimit = 300             #300'den fazla request kabul edilmiyor
ipList = []
ipListData = {}
ipTotalSearch = 9000       #ipLimit'in katı olmalı bu parametre

#--------------------------------------------------------------------


def domainSearch(domainMinPositive,domainDayCount,domainLimit,domainCursor,domainList):
    isContinueing = True
    today = datetime.datetime.now()
    daysBefore = datetime.timedelta(days=domainDayCount)
    dateToGoBack = today - daysBefore
    fullDate = fixDate(dateToGoBack.year, dateToGoBack.month, dateToGoBack.day)
    query = "entity:domain positives:" + str(domainMinPositive) + "+ creation_date:" + fullDate + "+"
    count = 0
    print("\nSon {} gündeki, score'u {} ve fazlası olan domainlerin listesi...\n".format(domainDayCount,domainMinPositive))
    while isContinueing:
        params = {'query': query,
                  'limit': domainLimit,
                  'descriptors_only': False,
                  'cursor': domainCursor}
        response = requests.get(url, params=params, headers={'x-apikey': api_key})
        r = response.json()

        for i in range(domainLimit):
            try:
                domainData = {}
                count += 1
                print(count)
                print(r.get("data")[i].get("id"))
                domainList.append(r.get("data")[i].get("id"))
                domainData["Categories"] = r.get("data")[i].get("attributes").get("categories")
                domainData["Creation Date"] = r.get("data")[i].get("attributes").get("creation_date")
                domainData["Stats"] = r.get("data")[i].get("attributes").get("last_analysis_stats")
                domainData["Detectors"] = cleanRest(r.get("data")[i].get("attributes").get("last_analysis_results"))
                if not r.get("data")[i].get("attributes").get("last_https_certificate"):
                    domainData["Cert Signature"] = "-"
                    domainData["Subject Alternative Name"] = "-"
                else:
                    domainData["Cert Signature"] = r.get("data")[i].get("attributes").get("last_https_certificate").get("cert_signature")
                    domainData["Subject Alternative Name"] = r.get("data")[i].get("attributes").get("last_https_certificate").get("extensions").get("subject_alternative_name")
                    print(domainData["Subject Alternative Name"])
                    print(type(domainData["Subject Alternative Name"]))
                domainData["Tags"] = r.get("data")[i].get("attributes").get("tags") #bos liste gelebilir
                if not r.get("data")[i].get("attributes").get("tags"):
                    domainData["Tags"] = "-"
                domainData["Total Votes"] = r.get("data")[i].get("attributes").get("total_votes")
                domainData["Reputation"] = r.get("data")[i].get("attributes").get("reputation")
                #domainData["WhoIs"] = r.get("data")[i].get("attributes").get("whois")
                domainListData[r.get("data")[i].get("id")] = domainData
                print(domainData)
                del domainData
            except IndexError:
                print("\nDomain Listesi tamamlandı...\n")
                isContinueing = False
                break

        if not isContinueing:
            break

        domainCursor = r['meta']['cursor']

def hashSearch(hashMinPositive,hashDayCount,hashLimit,hashCursor,hashList):
    isContinueing = True
    today = datetime.datetime.now()
    daysBefore = datetime.timedelta(days=hashDayCount)
    dateToGoBack = today - daysBefore
    fullDate = fixDate(dateToGoBack.year, dateToGoBack.month, dateToGoBack.day)
    query = "positives:" + str(hashMinPositive) + "+ fs:" + fullDate + "+"
    count = 0
    print("\nSon {} gündeki, score'u {} ve fazlası olan hashlerin listesi...\n".format(hashDayCount,hashMinPositive))
    while isContinueing:
        params = {'query': query,
                  'limit': hashLimit,
                  'order': "first_submission_date-",
                  'descriptors_only': False,
                  'cursor': hashCursor}
        response = requests.get(url, params=params, headers={'x-apikey': api_key})
        r = response.json()

        for i in range(hashLimit):
            try:
                count += 1
                print(count)
                print(r.get("data")[i].get("id"))
                hashList.append(r.get("data")[i].get("id"))
                if count == hashTotalSeach:
                    isContinueing = False
            except IndexError:
                print("\nHash Listesi tamamlandı...\n")
                isContinueing = False
                break

        if not isContinueing:
            break

        hashCursor = r['meta']['cursor']

def ipSearch(ipLimit,ipMinPositive):
    searchCounter = ipTotalSearch / ipLimit
    ipCursor = ''
    query = "entity:ip p:"+str(ipMinPositive)+"+"
    print("\nZararlı Score'u {}'un üstündeki güncel son {} IP adresinin listesi hazırlanıyor...\n".format(ipMinPositive,ipTotalSearch))
    count = 0
    for i in range(int(searchCounter)):
        params = {'query': query,
                  'limit': ipLimit,
                  'descriptors_only': False,
                  'cursor': ipCursor}
        response = requests.get(url, params=params, headers={'x-apikey': api_key})
        r = response.json()
        for i in range(ipLimit):
            try:
                ipData = {}
                count += 1
                print(count)
                print(r.get("data")[i].get("id"))
                ipList.append(r.get("data")[i].get("id"))
                # print(r.get("data")[i].get("attributes").get("as_owner"))
                # print(r.get("data")[i].get("attributes").get("country"))
                # print(r.get("data")[i].get("attributes").get("last_analysis_stats"))
                # print(cleanRest(r.get("data")[i].get("attributes").get("last_analysis_results")))
                if (r.get("data")[i].get("attributes").get("as_owner")):
                    ipData["Owner"] = r.get("data")[i].get("attributes").get("as_owner")
                else:
                    ipData["Owner"] = "-"
                if (r.get("data")[i].get("attributes").get("country")):
                    ipData["Country"] = r.get("data")[i].get("attributes").get("country")
                else:
                    ipData["Country"] = "-"
                ipData["Stats"] = r.get("data")[i].get("attributes").get("last_analysis_stats")
                ipData["Detectors"] = cleanRest(r.get("data")[i].get("attributes").get("last_analysis_results"))
                ipData["Last_Modification_Date"] = str(datetime.datetime.fromtimestamp(int(r.get("data")[i].get("attributes").get("last_modification_date"))))
                ipData["Context_Attributes"] = r.get("data")[i].get("context_attributes")
                ipListData[r.get("data")[i].get("id")] = ipData
                print(ipData)
                del ipData
            except IndexError:
                print("\nIP Adresleri Listesi tamamlandı...\n")
                break
        ipCursor = r['meta']['cursor']

    print("\nIP Adresleri Listesi tamamlandı...\n")


domainSearch(domainMinPositive,domainDayCount,domainLimit,domainCursor,domainList)
listToFile("domain", domainList)

ipSearch(ipLimit, ipMinPositive)
listToFile("ip", ipList)



hashSearch(hashMinPositive,hashDayCount,hashLimit,hashCursor,hashList)
listToFile("hash", hashList)
