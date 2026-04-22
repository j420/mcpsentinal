# True positive #3 — Python requests verify=False + warning suppression (lethal edge #3).
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get(url):
    return requests.get(url, verify=False)
