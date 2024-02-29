# Brandon Tsuchiya
# Project 1: JWKS server

from flask import Flask, request
import jwt
import rsa
import base64
import uuid
import time

app = Flask(__name__)

# holds all of the JWKs made
jwks = []

def create_jwt(isExpired):

     # generate key pair
    public_key, private_key = rsa.newkeys(2048)
    # modulus
    n = public_key.n
    # exponent
    e = public_key.e
    # generate random kid
    kid = str(uuid.uuid4())

    # jwt expires in an hour by default but if isExpire is true, it expires an hour before creation
    expiration = 3600
    if (not isExpired is None):
        if (isExpired == "true"):
            expiration = -3600

    # create and store jwk if not expired
    if expiration > 0:
        # create jwk
        jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "n": base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).decode("utf-8").rstrip('='),
            "e": base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')).decode("utf-8"),
            "kid": kid
            }
        # append jwk to list of jwks
        jwks.append(jwk)
    
    # iat time
    iat = int(time.time())

    # payload for jwt
    payload = {
        "userName": "username",
        "userId": 1234,
        "iat": iat,
        "exp": iat + expiration
    }

    # set private key to PEM format
    private_key_pem = private_key.save_pkcs1().decode('utf-8')

    # encode jwt
    newJwt = jwt.encode(payload, private_key_pem, algorithm = "RS256", headers={"kid": kid})
    return newJwt
    

# return all jwks
@app.route("/.well-known/jwks.json", methods = ["GET"])
def getJWKS():
    return {"keys": jwks}

# authentication endpoint
@app.route('/auth', methods = ['POST'])
def authentication():
    # get args
    isExpired = request.args.get("expired")
    jwt = create_jwt(isExpired)
    return jwt

if __name__ == "__main__":
    app.run(port=8080)