import requests

api_key = ""
url = 'https://www.virustotal.com/vtapi/v2/file/report'
file = open('hashes.txt', 'r')
Lines = file.readlines()
zararlıHashArray = []

for line in Lines:
    hash = line.rstrip()
    params = {'apikey': api_key , 'resource': hash}
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
        zararlıHashArray.append(line)

print("{} adet zararlı Hash bulundu. Zararlılar:".format(len(zararlıHashArray)))
for i in zararlıHashArray:
    print(i)