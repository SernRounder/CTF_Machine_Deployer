#!/bin/python
import requests
import sys
import time
port=sys.argv[1]
uri=sys.argv[2]
passcode=sys.argv[3]
url='http://localhost:{port}{uri}{passcode}'.format(port=port,uri=uri,passcode=passcode)
print(passcode)
requests.get('http://localhost:{port}/clear/{passcode}'.format(port=port,passcode=passcode))# 开局全清
while(1):
    time.sleep(300)
    requests.get(url)
