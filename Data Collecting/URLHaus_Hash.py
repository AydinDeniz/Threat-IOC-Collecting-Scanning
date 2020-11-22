import requests
import json

hausp = "" #public key of URLHaus

def hausgetpayloads(haus):
    counter = 1
    try:
        print("\n")
        print("Haus Downloadable Links to Recent Payloads".center(146), end='')
        print("".center(28), end='')
        print("\n" + (146*'-').center(59))
        requestsession8 = requests.Session( )
        requestsession8.headers.update({'accept': 'application/json'})
        hausresponse = requestsession8.get(haus)
        haustext = json.loads(hausresponse.text)
        npayloads = len(haustext['payloads'])
        if (npayloads > 0):
            try:
                for i in range(0,npayloads):
                    print("{}. Hash : ".format(counter) + haustext['payloads'][i].get('sha256_hash'))
                    print("File Type: " + "%-8s" % haustext['payloads'][i].get('file_type'))
                    print("First detection date: " + haustext['payloads'][i].get('firstseen'))
                    results = haustext['payloads'][i]['virustotal']
                    if (results) is not None:
                        print("VT results : " + (results['result']) + "\n")
                    else:
                        print("No VT result\n")

                    counter+=1
            except KeyError as e:
                pass
            except (BrokenPipeError, IOError, TypeError):
                exit(1)
    except KeyError as e:
        pass
    except (BrokenPipeError, IOError, TypeError):
        exit(1)
    except ValueError as e:
        print(e)
        print("Error while connecting to URLhaus!\n")

hausgetpayloads(hausp)