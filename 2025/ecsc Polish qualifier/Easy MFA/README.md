# Easy MFA

> Generating passwords is hard, so leave this us! We're also working on MFA.
>
> [https://easymfa.ecsc25.hack.cert.pl/](https://easymfa.ecsc25.hack.cert.pl/)
>
> **app.py**
> ```py
> import base64
> import random
> from flask import Flask, request, abort, jsonify
> from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, verify_jwt_in_request, JWTManager
> 
> 
> def get_random_string(length):
>     return random.getrandbits(length * 8).to_bytes(length, 'big')
> 
> 
> def get_mfa():
>     return base64.b64encode(get_random_string(8)).decode()
> 
> 
> app = Flask(__name__)
> app.config["JWT_SECRET_KEY"] = get_random_string(32)
> jwt = JWTManager(app)
> 
> FLAG = open("flag.txt", 'r').read()
> random_passwords = [base64.b64encode(get_random_string(8)).decode() for _ in range(384)]
> 
> 
> @app.route('/generate', methods=['GET'])
> def generate_password():
>     token = verify_jwt_in_request(optional=True)
>     if token is None:
>         index = 0
>     else:
>         _, jwt_data = token
>         index = (jwt_data['current'] + 1) % len(random_passwords)
>     access_token = create_access_token(identity="user", additional_claims={'current': index})
>     return jsonify({'token': access_token, 'password': random_passwords[index]})
> 
> 
> @app.route('/flag', methods=['POST'])
> @jwt_required()
> def flag():
>     current_user = get_jwt_identity()
>     otp = get_mfa()
>     if current_user == "admin" and request.json['OTP'] == otp:
>         return jsonify({"flag": FLAG})
>     else:
>         abort(403, f"Nope, it was {otp}")
> 
> 
> @app.get("/")
> def index():
>     return "You can't connect to this API with your browser. Check the source code."
> 
> 
> if __name__ == "__main__":
>     app.run()
> 
> ```

## Solution
Passwords are generated with deterministic Python's `random` module, and before they are generated, the same module is used to generate the JWT key. Since Python's random uses 32-bit [MT19937](https://en.wikipedia.org/wiki/Mersenne_Twister), at least 624 32-bit outputs are needed to crack it. Provided are 384 64-bit outputs, which totals to 768 32-bit outputs, which is more than enough. The solutions is as follows:

### Step 1. Calculate the JWT secret key
```py
from base64 import b64decode, b64encode
from randcrack import RandCrack # note: at the time of writing, the newest version of RandCrack on PyPI doesn't include the `offset` method; as such, it is necessary to manually create `randcrack.py` file and paste the code from GitHub there: https://raw.githubusercontent.com/tna0y/Python-random-module-cracker/2f860b0ad2439adfb82701e859b85a8f8719bf7d/randcrack/randcrack.py
import requests
import struct

HOST = 'https://easymfa.ecsc25.hack.cert.pl'

known = []
last_token = ''

for i in range(384):
    if (i + 1) % 10 == 0:
        print(f'Sending requests: {i + 1}/384')
    if last_token != '':
        resp = requests.get(f'{HOST}/generate', headers={'Authorization': f'Bearer {last_token}'}).json()
    else:
        resp = requests.get(f'{HOST}/generate').json()
    last_token = resp['token']
    pw = struct.unpack('>Q', b64decode(resp['password']))[0]
    known.append(pw % 2**32)
    known.append(pw >> 32)

rc = RandCrack()

for i in range(624):
    rc.submit(known[i])

for i in range(624, len(known)):
    assert rc.predict_getrandbits(32) == known[i]

rc.offset(-len(known) - 8)
jwt_key = rc.predict_getrandbits(32 * 8).to_bytes(32, 'big')
print(f'{jwt_key = }')
```

### Step 2. Generate a JWT token
```py
import base64
import random
from flask import Flask, request, abort, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, verify_jwt_in_request, JWTManager

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = b'\x9dL\xcc2\xb2\xd6\xad\xe0D\x8b\xf0q\x1b\xb4\xc1\x8d,\xa6\xe5\x0f\x02@\x04\xa4\xbaj\xf7\xf1f+\xd1\xdf' # the key retrieved from step 1
jwt = JWTManager(app)


@app.get('/')
def index():
    tok = create_access_token(identity="admin", additional_claims={'current': 2137})
    return tok


if __name__ == '__main__':
    app.run(port=5001)
```

### Step 3. Get the flag
```py
from base64 import b64decode, b64encode
from randcrack import RandCrack
import requests

admin_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc1MTcwMDQyNSwianRpIjoiMTE4MDdmNmEtZjA3Yi00Mzk3LTllNTctYjBhNzMzOWIyY2VhIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzUxNzAwNDI1LCJjc3JmIjoiMmQwYzA3ZTQtYWQ1My00NThjLWExZDUtMDA2M2RkMzE1NDZjIiwiZXhwIjoxNzUxNzAxMzI1LCJjdXJyZW50IjoyMTM3fQ.okswqaYqvjmfRGoJ_D4e0zuY5GuItAHGBcaX9E8WsCw' # generated in step 2
for e in known:
    assert rc.predict_getrandbits(32) == e # advance the randcrack object from step 1, double-checking that everything matches, because why not


def get_otp():
    return b64encode(rc.predict_getrandbits(8 * 8).to_bytes(8, 'big')).decode()


while True:
    resp = requests.post(f'{HOST}/flag', headers={'Authorization': f'Bearer {admin_jwt}'}, json={'OTP': get_otp()})
    if resp.status_code == 200:
        print(resp.json())
        break
    else:
        otp = resp.content.decode().split('was ')[1].split('</p>')[0]
        print(f'{otp = }')
        while get_otp() != otp:
            pass
        print('Found the otp!')
```

## Flag
`ecsc25{that_w4s_s0_rand0m}`
