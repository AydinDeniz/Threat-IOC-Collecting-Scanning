import time
import requests

apikey = ""

requests.urllib3.disable_warnings()
client = requests.session()
client.verify = False
domainErrors = []
zararlıDomainArray = []
delay = {}

def DomainScanner(domain):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': apikey, 'url': domain}
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print('Connection timed out. Error is as follows-')
        print(timeout)

    domainSani = domain.replace('.', '[.]')

    print(domainSani)
    print(r)

    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            if jsonResponse['response_code'] != 1:
                print('Domain taranmak üzere gönderilirken bir hata oluştu.')
                print(jsonResponse['verbose_msg'])
            elif jsonResponse['response_code'] == -2:
                print('{!s} tarama için sıraya alındı.'.format(domainSani))
                delay[domain] = 'queued'
            else:
                print('{!s} başarıyla tarandı.'.format(domainSani))
        except ValueError:
            print('Hata yaşandı. Hatalı Listesine ekleniyor....'.format(domainSani))
            domainErrors.append(domain)
        time.sleep(15)  #private key için bu sayı 1 olacak
        return delay
    elif r.status_code == 204:
        print('HTTP 204 response. API request sayısını aşmış olabilirsiniz')

def DomainReportReader(domain, delay):
    if delay:
        if domain in delay:
            time.sleep(10) #private key için azaltılacak
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': apikey, 'resource': domain}
    try:
        r = client.post(url, params=params)
    except requests.ConnectTimeout as timeout:
        print("Timeout")
        print(timeout)
        exit(1)
    domainSani = domain.replace('.', '[.]')
    if r.status_code == 200:
        try:
            jsonResponse = r.json()
            if jsonResponse['response_code'] == 0:
                print('Domain taranmak üzere gönderilirken bir hata oluştu.')
                pass
            elif jsonResponse['response_code'] == -2:
                print('Rapor {!r} hazırlanamadı.'.format(domainSani))
            else:
                print("Rapor hazır ", domainSani)
            permalink = jsonResponse['permalink']
            scandate = jsonResponse['scan_date']
            positives = jsonResponse['positives']
            total = jsonResponse['total']
            data = [scandate, domainSani, positives, total, permalink]
            if data[2] > 0:
                zararlıDomainArray.append(data[1])
            return data
        except ValueError:
            print('{!s} taranırken bir hata oluştu. Hata listesine domain ekleniyor ...'.format(domainSani))
            domainErrors.append(domainSani)
        except KeyError:
            print('{!s} taranırken bir hata oluştu. Hata listesine domain ekleniyor ...'.format(domainSani))
            domainErrors.append(domainSani)

    elif r.status_code == 204:
        print('HTTP 204 response. API request sayısını aşmış olabilirsiniz')
        time.sleep(10) #private key için azaltılacak
        DomainReportReader(domain, delay)

try:
    with open('urls.txt', 'r') as infile:
        for domain in infile:
            domain = domain.strip('\n')
            try:
                delay = DomainScanner(domain)
                data = DomainReportReader(domain, delay)
                if data:
                    time.sleep(15) # yine azaltılacak
            except Exception as err:
                print('Hata yaşandı, tarama devam ediyor', err)
except IOError as ioerr:
    print("File kapandığına emin olun")
    print(ioerr)

count = len(domainErrors)

if count > 0:
    print('Domain taranırken {!s} hata oluştu'.format(count))
    print(domainErrors)

print("\n{} zararlı Domain tespit edildi\n".format(len(zararlıDomainArray)))
for i in zararlıDomainArray:
    print(i)

