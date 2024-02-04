import requests

email = "jonah.emme@web.de"
password = "IchHasseNoah22"

token = "c4b643903144b4160f35c33e5a8c73f521699929eccbf0cb09dfd5d9ec591f44"

if token is None:
    resp = requests.post("https://vt.jo-dev.net/?action=login", json={"email": email, "password": password})
    token = resp.json()["token"]
    print(resp.status_code, token)

resp = requests.post("https://vt.jo-dev.net/?action=updateUserVocabStats", headers={"Auth": token}, json={"statUpdates": {1: {"fails": 3, "success": 1}}})

print(resp.status_code, resp.json())