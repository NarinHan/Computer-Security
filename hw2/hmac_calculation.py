#!/bin/env python3

import hmac
import hashlib

key = 'xciujk'
message = 'lstcmd=1'
mac = hmac.new(bytearray(key.encode('utf-8')),
               msg=message.encode('utf-8', 'surrogateescape'),
               digestmod=hashlib.sha256).hexdigest()
print(mac)
