import requests
import json

hausb = "" #public key of URLHaus

def hausgeturls(haus):
    counter = 1
    try:
        print("\n")
        print(("Recent URLHaus malicious URLs".center(104)), end='')
        print(("".center(28)), end='')
        print("\n" + (126 * '-').center(59))
        requestsession7 = requests.Session()
        requestsession7.headers.update({'accept': 'application/json'})
        hausresponse = requestsession7.get(haus)
        haustext = json.loads(hausresponse.text)
        nurl = len(haustext['urls'])
        if (nurl > 0):
            try:
                for i in range(0, nurl):
                    if 'url' in haustext['urls'][i]:
                        print("{}. URL : ".format(counter) + haustext['urls'][i].get('url') + " ")
                        print("Status : " + haustext['urls'][i].get('url_status'))
                        print("First time added "+ haustext['urls'][i].get('date_added') + "\n")
                        counter += 1
                print("{} URLs has been collected".format(counter - 1))
            except KeyError as e:
                pass
            except (BrokenPipeError, IOError, TypeError):
                print("{} URLs has been collected.".format(counter - 1))
    except KeyError as e:
        pass
    except (BrokenPipeError, IOError, TypeError):
        exit(1)
    except ValueError as e:
        print(e)
        print("Error while connecting to URLhaus!\n")


hausgeturls(hausb)