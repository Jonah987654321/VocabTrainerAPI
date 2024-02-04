import requests

email = "jonah.emme@web.de"
password = "IchHasseNoah22"

token = "29420ea3ce9d4bb2d61909ac063c271c3fcf7c5520188065bf3a92f7c8e1844e"

if token is None:
    resp = requests.post("https://vt.jo-dev.net/?action=login", json={"email": email, "password": password})
    token = resp.json()["token"]
    print(resp.status_code, token)

#resp = requests.post("https://vt.jo-dev.net/?action=updateUserVocabStats", headers={"Auth": token}, json={"statUpdates": {1: {"fails": 3, "success": 1}}})

resp = requests.post(
    "https://vt.jo-dev.net/?action=createAccount",
    json={"email": "emme.jonah@web.de", "password": "IchHasseNoah22", "firstName": "Jonah", "lastName": "Emme", "modePreference": 1, "class": 20}
)
print(resp.status_code, resp.json())