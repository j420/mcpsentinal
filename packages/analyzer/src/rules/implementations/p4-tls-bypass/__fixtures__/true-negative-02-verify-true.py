# True negative — explicit verify=True with proper CA bundle.
import requests

def get(url):
    return requests.get(url, verify="/etc/ssl/internal-ca.pem")
