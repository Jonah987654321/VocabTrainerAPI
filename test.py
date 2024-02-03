import requests

resp = requests.post(
    "https://vt.jo-dev.net/?action=deleteAccount",
    data={"password": "IchHasseNoah22"},
    headers={"Auth": "ec3193ebe15ff72f5fb7db3cb0052f4707edccce3a991bc275b25c911a45cb6b"}
)

print(resp.status_code, resp.json())