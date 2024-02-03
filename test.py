import requests

resp = requests.post(
    "https://vt.jo-dev.net/?action=createAccount",
    data={"email": "jonah.emme@web.des", "password": "IchHasseNoah22", "firstName": "Jonah", "lastName": "Emme", "modePreference": 0, "class": 20}
)

print(resp.status_code, resp.json())