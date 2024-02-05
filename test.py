import requests

email = "emme.jonah@web.de"
password = "IchHasseNoah22"

token = "32f3bfe367c57ad8c227513712ec462e21ef5a0352bc7ed12fd2b0a62136ca76"

if token is None:
    resp = requests.post("https://vt.jo-dev.net/?action=login", json={"email": email, "password": password})
    token = resp.json()["token"]
    print(resp.status_code, token)

#resp = requests.post("https://vt.jo-dev.net/?action=initiatePasswordReset", json={"email": email})
#print(resp.status_code, resp.json())
    
resp = requests.post("https://vt.jo-dev.net/?action=validatePasswordReset", json={"email": email, "code": "121589"})
print(resp.status_code, resp.json())

resp = requests.post("https://vt.jo-dev.net/?action=doPasswordReset", json={"email": email, "code": "121589", "newPassword": password})
print(resp.status_code, resp.json())

#resp = requests.post("https://vt.jo-dev.net/?action=updateUserVocabStats", headers={"Auth": token}, json={"statUpdates": {1: {"fails": 3, "success": 1}}})

#resp = requests.post(
#    "https://vt.jo-dev.net/?action=createAccount",
#    json={"email": "emme.jonah@web.de", "password": "IchHasseNoah22", "firstName": "Jonah", "lastName": "Emme", "modePreference": 1, "class": 20}
#)
#print(resp.status_code, resp.json())