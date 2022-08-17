from authlib.jose import JsonWebToken

token = input()

jwk = {
  "crv": "P-256",
  "kty": "EC",
  "alg": "ES256",
  "use": "sig",
  "kid": "a32fdd4b146677719ab2372861bded89",
  "x": "-uTmTQCbfm2jcQjwEa4cO7cunz5xmWZWIlzHZODEbwk",
  "y": "MwetqNLq70yDUnw-QxirIYqrL-Bpyfh4Z0vWVs_hWCM"
}

claims_options = {
    "iss": { "essential": True, "value": "https://idp.example.com" },
    "aud": { "essential": True, "value": "api1" }
}

jwt = JsonWebToken(jwk["alg"])
claims = jwt.decode(token, jwk, claims_options=claims_options)
claims.validate()

print(claims)