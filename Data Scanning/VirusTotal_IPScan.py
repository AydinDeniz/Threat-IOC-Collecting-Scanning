import requests

api_key = ""
url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
file = open('ip_addresses.txt', 'r')
Lines = file.readlines()
zararlıIPArray = []

for line in Lines:
    ip = line.rstrip()
    params = {'apikey': api_key , 'ip': ip}
    r = requests.get(url, params=params)
    try:
        response = r.json()
        if r.status_code != 200:
            print("HTTP error")
            print(r.status_code)
            exit(1)
    except:
        print("Hata!\nAPI Request hakkı kalmadı")
        exit(1)
    if response.get("response_code"):
        zararlıIPArray.append(ip)

print("{} adet zararlı IP adresi bulundu. Zararlılar:".format(len(zararlıIPArray)))
for i in zararlıIPArray:
    print(i)