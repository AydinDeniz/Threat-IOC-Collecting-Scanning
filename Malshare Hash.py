import json
import requests

urlmalshare = 'https://malshare.com/api.php?api_key='
MALSHAREAPI = "" #put a public key here

def malsharelastlist(typex, counter):

    maltype = typex

    if (maltype == 1):
        filetype = 'PE32'
    elif (maltype == 2):
        filetype = 'Dalvik'
    elif (maltype == 3):
        filetype = 'ELF'
    elif (maltype == 4):
        filetype = 'HTML'
    elif (maltype == 5):
        filetype = 'ASCII'
    elif (maltype == 6):
        filetype = 'PHP'
    elif (maltype == 7):
        filetype = 'Java'
    elif (maltype == 8):
        filetype = 'RAR'
    elif (maltype == 9):
        filetype = 'Zip'
    elif (maltype == 10):
        filetype = 'UTF-8'
    elif (maltype == 11):
        filetype = 'MS-DOS'
    elif (maltype == 12):
        filetype = 'data'
    elif (maltype == 13):
        filetype = 'PDF'
    else:
        filetype = 'Composite'

    try:
        print("\n")
        print(("SHA256 hash".center(75)), end='')
        print(("MD5 hash".center(38)), end='')
        print(("File type".center(8)), end='')
        print("\n" + (126*'-').center(59))
        requestsession = requests.Session( )
        requestsession.headers.update({'accept': 'application/json'})
        finalurl = ''.join([urlmalshare, MALSHAREAPI, '&action=type&type=', filetype])
        malresponse = requestsession.get(url=finalurl)
        maltext = json.loads(malresponse.text)

        if ((maltext)):
            try:
                for i in range(0, len(maltext)):
                    if (maltext[i].get('sha256')):
                        print((str(counter) + ". " "sha256: " + "%s" % maltext[i]['sha256'] + "  md5: " + "%s" % maltext[i]['md5'] + " type: " + "%s" % filetype))
                        counter +=1

            except KeyError as e:
                pass

            except (BrokenPipeError, IOError):
                exit(1)

    except ValueError as e:
        print(e)
        print("Error\n")

    return counter

counter = 1

for maltype in range(1,14):
    counter = malsharelastlist(maltype, counter)