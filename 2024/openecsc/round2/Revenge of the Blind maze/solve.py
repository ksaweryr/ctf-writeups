import pyshark
import requests

cap = pyshark.FileCapture('./capture.pcap', display_filter='http.response && !frame contains "FAILED"')
directions = [p.http.response_for_uri.split('=')[1] for p in cap]

with requests.session() as s:
    s.get('http://blindmazerevenge.challs.open.ecsc2024.it/')
    for d in directions:
        assert d in ['start', 'up', 'down', 'left', 'right']
        t = 'FAILED'
        while 'FAILED' in t:
            resp = s.get('http://blindmazerevenge.challs.open.ecsc2024.it/maze', params={'direction': d})
            t = resp.text

print(t)
