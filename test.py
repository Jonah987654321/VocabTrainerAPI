import requests

resp = requests.post(
    "https://vt.jo-dev.net/?action=login",
    data={"email": "jonah.emme@web.de", "password": "IchHasseNoah22"}
)

print(resp.status_code, resp.json())