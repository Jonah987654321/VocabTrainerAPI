import requests
from dotenv import load_dotenv, set_key
import os

load_dotenv(".env.test")

email = os.getenv("EMAIL")
password = os.getenv("PASSWORD")

token = os.getenv("TOKEN")

if token == "":
    resp = requests.post("https://vt.jo-dev.net/?action=login", json={"email": email, "password": password})
    token = resp.json()["token"]
    set_key(".env.test", "TOKEN", token)
    print(f"Login success, retrieved token {token}")
else:
    print(f"Loaded token {token}")

#resp = requests.post("https://vt.jo-dev.net/?action=initiatePasswordReset", json={"email": email})
#print(resp.status_code, resp.json())
    
#resp = requests.post("https://vt.jo-dev.net/?action=validatePasswordReset", json={"email": email, "code": "285697"})
#print(resp.status_code, resp.json())

#resp = requests.put("https://vt.jo-dev.net/?action=doPasswordReset", json={"email": email, "code": "285697", "newPassword": password})
#print(resp.status_code, resp.json())

#resp = requests.post("https://vt.jo-dev.net/?action=updateUserVocabStats", headers={"Auth": token}, json={"statUpdates": {1: {"fails": 3, "success": 1}}})

#resp = requests.post(
#    "https://vt.jo-dev.net/?action=createAccount",
#    json={"email": "emme.jonah@web.de", "password": "IchHasseNoah22", "firstName": "Jonah", "lastName": "Emme", "modePreference": 1, "class": 20}
#)
#print(resp.status_code, resp.json())

resp = requests.get("https://vt.jo-dev.net/?action=getPreferences", headers={"Auth": token})
print(resp.status_code, resp.json())