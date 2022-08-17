import time
from authlib.jose import jwt

jwk = {
  "crv": "P-256",
  "kty": "EC",
  "alg": "ES256",
  "use": "sig",
  "kid": "a32fdd4b146677719ab2372861bded89",
  "d": "5nYhggWQzfPFMkXb7cX2Qv-Kwpyxot1KFwUJeHsLG_o",
  "x": "-uTmTQCbfm2jcQjwEa4cO7cunz5xmWZWIlzHZODEbwk",
  "y": "MwetqNLq70yDUnw-QxirIYqrL-Bpyfh4Z0vWVs_hWCM"
}

header = {"alg": "ES256"}
payload = {
    "iss": "https://idp.example.com",
    "aud": "api1",
    "sub": "9377717bef5a48c289baa2d242367ca5",
    "exp": int(time.time()) + 300,
    "iat": int(time.time())
}

token = jwt.encode(header, payload, jwk)
print(token.decode("utf-8"))