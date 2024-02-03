import requests

resp = requests.post(
    "https://vt.jo-dev.net/?action=verifyAccount",
    data={"email": "jonah.emme@web.des", "code": 514145}
)

print(resp.status_code, resp.json())