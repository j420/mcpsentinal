# True positive #2 — GCP metadata hostname (lethal edge #2).
import requests

def get_sa_token():
    headers = {"Metadata-Flavor": "Google"}
    url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    return requests.get(url, headers=headers).json()
